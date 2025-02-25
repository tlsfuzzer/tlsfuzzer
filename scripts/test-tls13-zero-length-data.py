# Author: Anderson Toshiyuki Sasaki, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        split_message, PopMessageFromList, SetPaddingCallback
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import key_share_gen, RSA_SIG_ALL


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
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" --help         this message")

def build_conn_graph(host, port):
    """ Reuse the same block as a function, to simplify code """
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
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
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)

    return (conversation, node, ciphers, ext)


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
        elif opt == '-n':
            num_limit = int(arg)
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

    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
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

    # Send zero-length application data between normal application data
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())    
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET /")))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"HTTP/1.")))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["zero-length app data"] = conversation

    # Send zero-length application data with padding
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())    
    node = node.add_child(SetPaddingCallback(
        SetPaddingCallback.fixed_length_cb(30)))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET /")))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"HTTP/1.")))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["zero-length app data with padding"] = conversation

    # Send zero-length application data with large paddings
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())    
    node = node.add_child(SetPaddingCallback(
        SetPaddingCallback.fill_padding_cb))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET /")))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"HTTP/1.")))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["zero-length app data with large padding"] = conversation

    # Send zero-length application data while handshaking
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.unexpected_message)
    node.next_sibling.add_child(ExpectClose())

    conversations["zero-length app data during handshake"] = conversation

    # Send zero-length application data while handshaking with padding
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(SetPaddingCallback(
        SetPaddingCallback.fixed_length_cb(30)))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.unexpected_message)
    node.next_sibling.add_child(ExpectClose())

    conversations["zero-length app data with padding during handshake"] =\
        conversation

    # Send zero-length application data while handshaking with large padding
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(SetPaddingCallback(
        SetPaddingCallback.fill_padding_cb))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))

    # The server may send NST before receiving client Finished
    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.unexpected_message)
    node.next_sibling.add_child(ExpectClose())
    conversations["zero-len app data with large padding during handshake"] =\
        conversation

    # Send a zero-length application data interleaved in handshake
    fragment_list = []
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    hello_gen = ClientHelloGenerator(ciphers, extensions=ext)
    node = node.add_child(split_message(hello_gen, fragment_list, 2))
    node = node.add_child(PopMessageFromList(fragment_list))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.unexpected_message))
    node.add_child(ExpectClose())
    conversations["zero-length app data interleaved in handshake"] =\
        conversation

    # Send zero-len app data with padding interleaved in handshaking
    fragment_list = []
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    hello_gen = ClientHelloGenerator(ciphers, extensions=ext)
    node = node.add_child(split_message(hello_gen, fragment_list, 2))
    node = node.add_child(PopMessageFromList(fragment_list))
    node = node.add_child(SetPaddingCallback(
        SetPaddingCallback.fixed_length_cb(30)))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.unexpected_message))
    node.add_child(ExpectClose())
    conversations["zero-len app data with padding interleaved in "
                  "handshake"] = conversation

    # Send zero-len app data with large padding interleaved in handshaking
    fragment_list = []
    (conversation, node, ciphers, ext) = build_conn_graph(host, port)
    hello_gen = ClientHelloGenerator(ciphers, extensions=ext)
    node = node.add_child(split_message(hello_gen, fragment_list, 2))
    node = node.add_child(PopMessageFromList(fragment_list))
    node = node.add_child(SetPaddingCallback(
        SetPaddingCallback.fill_padding_cb))
    node = node.add_child(ApplicationDataGenerator(bytearray(0)))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.unexpected_message))
    node.add_child(ExpectClose())
    conversations["zero-len app data with large padding interleaved in "
                  "handshake"] = conversation

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

    print("TLS 1.3 zero-length Application Data")
    print("Check if zero-length Application Data records handling is")
    print("correct\n.")

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
