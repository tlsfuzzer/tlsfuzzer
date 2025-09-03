# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Minimal test for verifying DHE_RSA key exchange support"""

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectServerKeyExchange, \
        ExpectApplicationData
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import sig_algs_to_ids, RSA_SIG_ALL, AutoEmptyExtension


version = 5


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" --alert name   the expected alert description when no overlap")
    print("                between groups - insufficient_security by default")
    print("                as per RFC 7919, while there is an erratum removing")
    print("                this restriction")
    print(" -S sigalgs     hash and signature algorithm pairs that the client")
    print("                will accept for TLS negotiation")
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
    print(" -t timeout     how long to wait before assuming the server won't")
    print("                send a message")
    print(" -M | --ems     Enable support for Extended Master Secret")
    print(" --help         this message")


def main():
    """Test if server supports the RFC 7919 key exchange"""
    host = "localhost"
    port = 4433
    num_limit = None
    fatal_alert = "insufficient_security"
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    sig_algs = None  # `sigalgs` w/o underscore is used for client certificates
    timeout = 5.0
    ems = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:S:e:x:X:t:n:M", ["help", "alert=",
                                                           "ems"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-S':
            sig_algs = sig_algs_to_ids(arg)
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
        elif opt == '--alert':
            fatal_alert = arg
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '-t':
            timeout = float(arg)
        elif opt == '-M' or opt == '--ems':
            ems = True
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    ext = {ExtensionType.renegotiation_info: None}
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    if sig_algs:
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    srv_ext = {ExtensionType.renegotiation_info:None}
    if ems:
        srv_ext[ExtensionType.extended_master_secret] = None
    node = node.add_child(ExpectServerHello(extensions=srv_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["sanity"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None}
    if sig_algs:
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    srv_ext = {ExtensionType.renegotiation_info:None}
    if ems:
        srv_ext[ExtensionType.extended_master_secret] = None
    node = node.add_child(ExpectServerHello(cipher=CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                            extensions=srv_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["Check if DHE preferred"] = conversation

    for group in GroupName.allFF:
        conversation = Connect(host, port, timeout=timeout)
        node = conversation
        ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        ext = {ExtensionType.renegotiation_info: None}
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create([group])
        if sig_algs:
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sig_algs)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(extensions=srv_ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange(valid_groups=[group]))
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        node.next_sibling = ExpectClose()
        node.add_child(ExpectClose())

        conversations["{0} negotiation".format(GroupName.toStr(group))] = \
                conversation

        conversation = Connect(host, port, timeout=timeout)
        node = conversation
        ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        ext = {ExtensionType.renegotiation_info: None}
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create([511, group])
        if sig_algs:
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sig_algs)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(extensions=srv_ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange(valid_groups=[group]))
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        node.next_sibling = ExpectClose()
        node.add_child(ExpectClose())

        conversations["unassigned tolerance, {0} negotiation".format(GroupName.toStr(group))] = \
                conversation

        conversation = Connect(host, port, timeout=timeout)
        node = conversation
        ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        ext = {ExtensionType.renegotiation_info: None}
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create([GroupName.secp256r1, group])
        if sig_algs:
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sig_algs)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(extensions=srv_ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange(valid_groups=[group]))
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        node.next_sibling = ExpectClose()
        node.add_child(ExpectClose())

        conversations["tolerate ECC curve in groups without ECC cipher, "
                      "negotiate {0} ".format(GroupName.toStr(group))] = \
                conversation

        for group2 in GroupName.allFF:
            if group == group2:
                continue
            conversation = Connect(host, port, timeout=timeout)
            node = conversation
            ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
            ext = {ExtensionType.renegotiation_info: None}
            ext[ExtensionType.supported_groups] = \
                    SupportedGroupsExtension().create([511, group, group2])
            if sig_algs:
                ext[ExtensionType.signature_algorithms] = \
                    SignatureAlgorithmsExtension().create(sig_algs)
                ext[ExtensionType.signature_algorithms_cert] = \
                    SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
            if ems:
                ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       extensions=ext))
            srv_ext = {ExtensionType.renegotiation_info:None}
            if ems:
                srv_ext[ExtensionType.extended_master_secret] = None
            node = node.add_child(ExpectServerHello(extensions=srv_ext))
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectServerKeyExchange(
                valid_groups=[group, group2]))
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(ClientKeyExchangeGenerator())
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectFinished())
            node = node.add_child(ApplicationDataGenerator(
                bytearray(b"GET / HTTP/1.0\n\n")))
            node = node.add_child(ExpectApplicationData())
            node = node.add_child(AlertGenerator(AlertLevel.warning,
                                                 AlertDescription.close_notify))
            node = node.add_child(ExpectAlert(AlertLevel.warning,
                                              AlertDescription.close_notify))
            node.next_sibling = ExpectClose()
            node.add_child(ExpectClose())

            conversations["{0} or {1} negotiation".format(GroupName.toStr(group),
                    GroupName.toStr(group2))] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None}
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create([511])
    if sig_algs:
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    srv_ext = {ExtensionType.renegotiation_info:None}
    if ems:
        srv_ext[ExtensionType.extended_master_secret] = None
    node = node.add_child(ExpectServerHello(cipher=CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                                            extensions=srv_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["fallback to non-ffdhe"] = conversation

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None}
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create([GroupName.secp256r1, 511])
    if sig_algs:
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    srv_ext = {ExtensionType.renegotiation_info:None}
    if ems:
        srv_ext[ExtensionType.extended_master_secret] = None
    node = node.add_child(ExpectServerHello(cipher=CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                                            extensions=srv_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["fallback to non-ffdhe with secp256r1 advertised"] = conversation

    # first paragraph of section 4 in RFC 7919
    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_NULL_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None}
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create([511])
    if sig_algs:
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      getattr(AlertDescription, fatal_alert)))
    node.add_child(ExpectClose())

    conversations["no overlap between groups"] = conversation


    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    num_limit = num_limit or len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    run_sanity = True
    if run_only:
        if len(run_only) == 1 and 'sanity' in run_only:
            run_sanity = False
            regular_tests = sanity_tests
        else:
            if not 'sanity' in run_only:
                run_sanity = False
            regular_tests = [(k, v) for k, v in conversations.items() if
                             k in run_only and (k != 'sanity')]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    if run_sanity:
        ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)
    else:
        ordered_tests = sampled_tests

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
    if run_sanity:
        print("TOTAL: {0}".format(len(sampled_tests) + 2 * len(sanity_tests)))
    else:
        print("TOTAL: {0}".format(len(sampled_tests)))
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
