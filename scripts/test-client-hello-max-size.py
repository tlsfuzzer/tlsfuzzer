# Author: Stefan Djordjevic, (c) 2017
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, SignatureScheme, GroupName
from tlslite.extensions import ALPNExtension, TLSExtension, \
        SupportedGroupsExtension, SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import RSA_SIG_ALL


version = 5


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" --help         this message")

def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    sigalgs = [SignatureScheme.rsa_pkcs1_sha256,
               SignatureScheme.rsa_pkcs1_sha384,
               SignatureScheme.rsa_pkcs1_sha512,
               SignatureScheme.rsa_pss_rsae_sha256,
               SignatureScheme.rsa_pss_rsae_sha384,
               SignatureScheme.rsa_pss_rsae_sha512,
               SignatureScheme.rsa_pss_pss_sha256,
               SignatureScheme.rsa_pss_pss_sha384,
               SignatureScheme.rsa_pss_pss_sha512]

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:x:X:d", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
        elif opt == '-d':
            dhe = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    if dhe:
        ext = {}
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sigalgs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(sigalgs)
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # client hello max size
    conversation = Connect(host, port)
    node = conversation
    proto = bytearray(b"A" * 255)
    lista = []
    lista.append(proto)
    for p in range(1, 255):
        lista.append(proto)
    # max size with
    if dhe:
        lista.append(bytearray(b'B' * 181))
    else:
        lista.append(bytearray(b'B' * 239))
    lista.append(bytearray(b'http/1.1'))
    # cipher suites array length 2^16-2, ciphers are two bytes
    # max number of ciphers can be 32767
    ciphers = []
    # adding ciphers from unassigned ranges
    # 0x00,0x5D-5F      Unassigned (93-95)
    for c in range(93, 96):
        ciphers.append(c)
    # 0x00,0x6E-83      Unassigned (110-131)
    for c in range(110, 132):
        ciphers.append(c)
    # 0x00,0xC6-FE      Unassigned (198-254)
    for c in range(198, 255):
        ciphers.append(c)
    # 0x01-55,*         Unassigned (255-22015)
    for c in range(255, 22016):
        ciphers.append(c)
    # 0x56,0x01-0xC0,0x00       Unassigned (22017-49152)
    # adding 10921 ciphers, from unassigned range above
    if dhe:
        # with DHE we send two valid ciphers, not one
        for c in range(22017, 32939 - 1):
            ciphers.append(c)
    else:
        for c in range(22017, 32939):
            ciphers.append(c)
    # adding ciphers we actually want to use
    if dhe:
        ciphers.append(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
        ciphers.append(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
    else:
        ciphers.append(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)
    ciphers.append(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    # cipher suites array filled with 32767 2bytes values
    ext = {ExtensionType.alpn: ALPNExtension().create(lista)}
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sigalgs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(sigalgs)
    # adding session_id, compression methonds
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(32),
                                               extensions=ext,
                                               compression=range(0, 255)))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["max client hello"] = conversation

    # run the conversation
    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    if run_only:
        if num_limit > len(run_only):
            num_limit = len(run_only)
        regular_tests = [(k, v) for k, v in conversations.items() if
                          k in run_only]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

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

    print("Check if server will accept Client Hello message of maximum valid")
    print("size\n")

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + 2*len(sanity_tests)))
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
