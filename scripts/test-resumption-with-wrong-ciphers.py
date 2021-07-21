# Author: Hubert Kario, (c) 2015-2018
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName
from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ResetHandshakeHashes, Close, ResetRenegotiationInfo
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectApplicationData, \
        ExpectServerKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import SIG_ALL
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension


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
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" --swap-ciphers expect the server to pick AES-128 over AES-256")
    print(" --n/n-1        expect n/n-1 record splitting (should be used")
    print("                for TLS 1.0 and earlier only)")
    print(" --help         this message")


def main():
    """Test if server does not allow resumption with different cipher."""
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    swap_ciphers = False
    dhe = False
    splitting = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:d", ["help", "swap-ciphers",
                                                       "n/n-1"])
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
        elif opt == "--swap-ciphers":
            swap_ciphers = True
        elif opt == '-d':
            dhe = True
        elif opt == "--n/n-1":
            splitting = True
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
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
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
    if splitting:
        node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    conversation = Connect(host, port)
    node = conversation
    if dhe:
        ext = {}
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
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
    if splitting:
        node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity - aes-256 cipher"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ext = {ExtensionType.renegotiation_info: None}
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    if dhe:
        if swap_ciphers:
            exp_ciph = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        else:
            exp_ciph = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
    else:
        if swap_ciphers:
            exp_ciph = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
        else:
            exp_ciph = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
    node = node.add_child(ExpectServerHello(
        cipher=exp_ciph,
        extensions={ExtensionType.renegotiation_info:None}))
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
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(
        extensions={ExtensionType.renegotiation_info:None},
        resume=True))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    if splitting:
        node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())

    conversations["sanity - session ID resume"] = conversation

    # check if resumption with a different cipher fails
    conversation = Connect(host, port)
    node = conversation
    ext = {ExtensionType.renegotiation_info: None}
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    if dhe:
        if swap_ciphers:
            exp_ciph = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        else:
            exp_ciph = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                        CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
    else:
        if swap_ciphers:
            exp_ciph = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
        else:
            exp_ciph = CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
    node = node.add_child(ExpectServerHello(
        cipher=exp_ciph,
        extensions={ExtensionType.renegotiation_info:None}))
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
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    if dhe:
        if swap_ciphers:
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA]
        else:
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    else:
        if swap_ciphers:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA]
        else:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node.add_child(ExpectClose())

    conversations["resumption with cipher from old CH but not selected by server"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ext = {ExtensionType.renegotiation_info: None}
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(
        extensions={ExtensionType.renegotiation_info:None}))
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
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    if dhe:
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_NULL_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_NULL_SHA,
                   CipherSuite.TLS_ECDH_ANON_WITH_NULL_SHA]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_NULL_SHA]
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node.add_child(ExpectClose())

    conversations["resumption of safe session with NULL cipher"] = conversation


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

    print("Misbehaving client session resumption script")
    print("Check if server detects a misbehaving client in session"
          " resumption\n")
    print("Reproducer for CVE-2010-4180\n")

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
