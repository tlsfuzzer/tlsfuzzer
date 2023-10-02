# Author: Hubert Kario, (c) 2023
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, Close
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import key_share_gen, SIG_ALL


version = 1


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (\"sanity\" tests are always executed)")
    print(" -C ciph        Use specified ciphersuite. Either numerical value or")
    print("                IETF name.")
    print(" -t time        Time to wait for server response, in seconds. 5.0")
    print("                by default")
    print(" --repeat num   How many times to send each probe, 10 by default")
    print(" --help         this message")

def initiate_connect(host, port):
    """Code resuse"""
    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())

    return (conversation, node)


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    ciphers = None
    repeat = 10
    timeout = 5

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:C:t:", ["help", "repeat="])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-t':
            timeout = float(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == "--repeat":
            repeat = int(arg)
        elif opt == '-C':
            if arg[:2] == '0x':
                ciphers = [int(arg, 16)]
            else:
                try:
                    ciphers = [getattr(CipherSuite, arg)]
                except AttributeError:
                    ciphers = [int(arg)]
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if not ciphers:
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256]

    ciphers += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

    conversations = {}

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.ed25519,
                SignatureScheme.ed448]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    (conversation, node) = initiate_connect(host, port)

    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(Close())

    conversations["After Alert"] = conversation

    (conversation, node) = initiate_connect(host, port)

    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(Close())

    conversations["After server ApplicationData"] = conversation

    (conversation, node) = initiate_connect(host, port)

    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectNewSessionTicket())
    node = node.add_child(Close())

    conversations["After NewSessionTicket"] = conversation

    (conversation, node) = initiate_connect(host, port)
    
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(Close())

    conversations["After client ApplicationData"] = conversation

    (conversation, node) = initiate_connect(host, port)
    
    node = node.add_child(Close())

    conversations["After client Finished"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(Close())

    conversations["After server Finished"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(Close())

    conversations["After server CertificateVerify"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(Close())

    conversations["After server Certificate"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(Close())

    conversations["After EncryptedExtensions"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(Close())

    conversations["After server ChangeCipherSpec"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(Close())

    conversations["After ServerHello"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(Close())

    conversations["After ClientHello"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    node = node.add_child(Close())

    conversations["Before ClientHello"] = conversation

    # run the conversation
    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    if not num_limit:
        num_limit = len(conversations)

    for i in range(repeat):
        # make sure that sanity test is run first and last
        # to verify that server was running and kept running throughout
        sanity_tests = [('sanity', conversations['sanity'])]
        if run_only:
            if num_limit > len(run_only):
                num_limit = len(run_only)
            regular_tests = [(k, v) for k, v in conversations.items() if k in run_only]
        else:
            regular_tests = [(k, v) for k, v in conversations.items() if
                             (k != 'sanity') and k not in run_exclude]
        sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
        ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

        for c_name, c_test in ordered_tests:
            print("\"{0}\" repeat {1}...".format(c_name, i))

            runner = Runner(c_test)

            res = True
            exception = None
            try:
                runner.run()
            except Exception as exp:
                exception = exp
                print("Error while processing")
                print(traceback.format_exc())
                res = False

            if c_name in expected_failures:
                if res:
                    xpass += 1
                    xpassed.append(c_name)
                    print("XPASS-expected failure but test passed\n")
                else:
                    if expected_failures[c_name] is not None and  \
                        expected_failures[c_name] not in str(exception):
                            bad += 1
                            failed.append(c_name)
                            print("Expected error message: {0}\n"
                                .format(expected_failures[c_name]))
                    else:
                        xfail += 1
                        print("OK-expected failure\n")
            else:
                if res:
                    good += 1
                    print("OK\n")
                else:
                    bad += 1
                    failed.append(c_name)

    print("Check if server behaves correctly when client aborts connection")
    print("Intended to test memory leaks in servers\n")

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(
        repeat * (len(sampled_tests) + 2*len(sanity_tests))))
    print("SKIP: {0}".format(len(run_exclude.intersection(conversations.keys()))))
    print("PASS: {0}".format(good))
    print("XFAIL: {0}".format(xfail))
    print("FAIL: {0}".format(bad))
    print("XPASS: {0}".format(xpass))
    print(20 * '=')
    sort = sorted(xpassed ,key=natural_sort_keys)
    if len(sort):
        print("XPASSED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))
    sort = sorted(failed, key=natural_sort_keys)
    if len(sort):
        print("FAILED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))

    if bad or xpass:
        sys.exit(1)

if __name__ == "__main__":
    main()
