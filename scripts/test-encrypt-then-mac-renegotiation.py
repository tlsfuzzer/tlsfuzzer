# Author: Milan Lysonek, 2017
"""Test for CVE-2017-3733 - Encrypt-then-MAC renegotiation crash"""

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
        FinishedGenerator, AlertGenerator, ResetHandshakeHashes, \
        ApplicationDataGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectApplicationData, \
        ExpectServerKeyExchange
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension, SupportedGroupsExtension
from tlsfuzzer.helpers import AutoEmptyExtension

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName
from tlsfuzzer.helpers import RSA_SIG_ALL
from tlsfuzzer.utils.lists import natural_sort_keys


version = 3


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port]")
    print(" -h hostname          name of the host to run the test against")
    print("                      localhost by default")
    print(" -p port              port number to use for connection,")
    print("                      4433 by default")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
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
    print(" --help               this message")


def main():
    hostname = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:x:X:d", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            hostname = arg
        elif opt == '-d':
            dhe = True
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

    conversation = Connect(hostname, port)
    node = conversation
    ext = {ExtensionType.encrypt_then_mac: AutoEmptyExtension()}
    if dhe:
        groups = [GroupName.secp256r1, GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension() \
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    extensions = {ExtensionType.encrypt_then_mac:None,
                  ExtensionType.renegotiation_info:None}
    node = node.add_child(ExpectServerHello(extensions=extensions))
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

    conversation = Connect(hostname, port)
    node = conversation
    # 1st handshake without encrypt-then-mac extension
    ext = {ExtensionType.renegotiation_info: None}
    if dhe:
        groups = [GroupName.secp256r1, GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension() \
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    extensions = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(extensions=extensions))
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake with encrypt-then-mac extension
    node = node.add_child(ResetHandshakeHashes())
    ext = {ExtensionType.encrypt_then_mac: AutoEmptyExtension(),
           ExtensionType.renegotiation_info: None}
    if dhe:
        groups = [GroupName.secp256r1, GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension() \
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(0),
                                               extensions=ext))
    extensions = {ExtensionType.encrypt_then_mac:None,
                  ExtensionType.renegotiation_info:None}
    node = node.add_child(ExpectServerHello(extensions=extensions))
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
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    conversations["Encrypt-then-MAC renegotiation crash"] = conversation

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
