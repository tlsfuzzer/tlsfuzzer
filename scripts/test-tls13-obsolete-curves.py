# Author: Alexander Sosedkin, (c) 2019
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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ch_cookie_handler
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket, ExpectHelloRetryRequest

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import key_share_gen, SIG_ALL, key_share_ext_gen


version = 6


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
    print(" -a alert_desc  Alert description expected for cases with invalid")
    print("                curves advertised, integer or name.")
    print("                \"illegal_parameter\" by default.")
    print(" --relaxed      Allow connections where both valid and obsolete curves")
    print("                are advertised in supported_groups and key_share.")
    print("                This is not RFC compliant.")
    print(" --cookie       expect the server to send \"cookie\" extension in")
    print("                Hello Retry Request message")
    print(" --help         this message")


def negative_test(host, port, additional_extensions, expected_alert):
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)
    ext.update(additional_extensions)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      expected_alert))
    node = node.add_child(ExpectClose())
    return conversation

def positive_test(host, port, additional_extensions):
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)
    ext.update(additional_extensions)
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
    return conversation


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    alert_desc = AlertDescription.illegal_parameter
    cookie = False
    relaxed = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:a:", ["help", "cookie", "relaxed"])
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
        elif opt == "-a":
            try:
                alert_desc = int(arg)
            except ValueError:
                alert_desc = getattr(AlertDescription, arg)
        elif opt =="--relaxed":
            relaxed = True
        elif opt == "--cookie":
            cookie = True
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
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)
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

    # verify that server supports HRR
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
    groups = [GroupName.secp256r1]
    key_shares = []
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))

    ext = OrderedDict()
    if cookie:
        ext[ExtensionType.cookie] = None
    ext[ExtensionType.key_share] = None
    ext[ExtensionType.supported_versions] = None
    node = node.add_child(ExpectHelloRetryRequest(extensions=ext))
    ext = OrderedDict()
    if cookie:
        ext[ExtensionType.cookie] = ch_cookie_handler
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
                SignatureScheme.ecdsa_secp256r1_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectServerHello())
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
    conversations["sanity - HRR support"] = conversation

    # verify that server replies with HRR when we send valid curve in supported_groups
    # and unsupported curve in supported_groups and key_share
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
    groups = [GroupName.secp256r1]
    unsupported_groups = [GroupName.secp224r1]
    both_groups = groups + unsupported_groups
    key_shares = []
    for group in unsupported_groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(both_groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))

    ext = OrderedDict()
    if cookie:
        ext[ExtensionType.cookie] = None
    ext[ExtensionType.key_share] = None
    ext[ExtensionType.supported_versions] = None
    if not relaxed:
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                              AlertDescription.illegal_parameter))
        node = node.add_child(ExpectClose())
    else:
        node = node.add_child(ExpectHelloRetryRequest(extensions=ext))
        ext = OrderedDict()
        if cookie:
            ext[ExtensionType.cookie] = ch_cookie_handler
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
                    SignatureScheme.ecdsa_secp256r1_sha256]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(SIG_ALL)
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectServerHello())
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
    conversations["secp256r1 and secp224r1 in supported_groups, secp224r1 in key_share - HRR"] = conversation

    # Check that all the valid groups work correctly
    valid_groups = [GroupName.secp256r1, GroupName.secp384r1,
                    GroupName.secp521r1, GroupName.x25519,
                    GroupName.x448]

    for valid_group in valid_groups:
        groups = [valid_group]
        ext = {}
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        conversation = positive_test(host, port, ext)
        conversation_name = "{0} in supported_groups and key_share"\
            .format(GroupName.toRepr(valid_group))
        conversations[conversation_name] = conversation

    # https://tools.ietf.org/html/rfc8446#appendix-B.3.1.4
    obsolete_groups = chain(range(0x0001, 0x0016 + 1),
                            range(0x001A, 0x001C + 1),
                            range(0xFF01, 0XFF02 + 1))

    for obsolete_group in obsolete_groups:
        obsolete_group_name = (GroupName.toRepr(obsolete_group)
                               or "unknown ({0})".format(obsolete_group))

        ext = {}
        groups = [obsolete_group]
        try:
            key_shares = []
            for group in groups:
                key_shares.append(key_share_gen(group))
        except ValueError:
            # bogus value to move on, if it makes problems, these won't result in handshake_failure
            key_shares = [KeyShareEntry().create(obsolete_group, bytearray(b'\xab'*32))]
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        conversation = negative_test(host, port, ext, alert_desc)
        conversation_name = "{0} in supported_groups and key_share"\
            .format(obsolete_group_name)
        conversations[conversation_name] = conversation

        # check if it's rejected when it's just the one advertised, but not shared
        ext = {}
        groups = [obsolete_group]
        key_shares = []
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        conversation = negative_test(host, port, ext, alert_desc)
        conversation_name = "{0} in supported_groups and empty key_share"\
            .format(obsolete_group_name)
        conversations[conversation_name] = conversation

        # check invalid group advertised together with valid in key share
        ext = {}
        groups = [obsolete_group, GroupName.secp256r1]
        ext[ExtensionType.key_share] = key_share_ext_gen([GroupName.secp256r1])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        if relaxed:
            conversation = positive_test(host, port, ext)
        else:
            conversation = negative_test(host, port, ext, alert_desc)
        conversation_name = "{0} and secp256r1 in supported_groups and "\
                            "secp256r1 in key_share".format(obsolete_group_name)
        conversations[conversation_name] = conversation

        # check with both valid and invalid in key share and supported groups
        ext = {}
        groups = [obsolete_group, GroupName.secp256r1]
        key_shares = []
        for group in groups:
            try:
                key_shares.append(key_share_gen(group))
            except ValueError:
                # bogus value to move on, if it makes problems, these won't result in handshake_failure
                key_shares.append(KeyShareEntry()
                    .create(obsolete_group, bytearray(b'\xab'*32)))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        if relaxed:
            conversation = positive_test(host, port, ext)
        else:
            conversation = negative_test(host, port, ext, alert_desc)
        conversation_name = "{0} and secp256r1 in supported_groups and key_share".format(obsolete_group_name)
        conversations[conversation_name] = conversation

        # also check with inverted order
        ext = {}
        groups = [GroupName.secp256r1, obsolete_group]
        key_shares = []
        for group in groups:
            try:
                key_shares.append(key_share_gen(group))
            except ValueError:
                # bogus value to move on, if it makes problems, these won't result in handshake_failure
                key_shares.append(KeyShareEntry()
                    .create(obsolete_group, bytearray(b'\xab'*32)))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        if relaxed:
            conversation = positive_test(host, port, ext)
        else:
            conversation = negative_test(host, port, ext, alert_desc)
        conversation_name = "secp256r1 and {0} in supported_groups and key_share".format(obsolete_group_name)
        conversations[conversation_name] = conversation

        # check inconsistent key_share with supported_groups
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        try:
            key_shares.append(key_share_gen(obsolete_group))
        except ValueError:
            # bogus value to move on, if it makes problems, these won't result in handshake_failure
            key_shares.append(KeyShareEntry()
                .create(obsolete_group, bytearray(b'\xab'*32)))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        conversation = negative_test(host, port, ext, AlertDescription.illegal_parameter)
        conversation_name = \
            "{0} in key_share and secp256r1 in "\
            "supported_groups (inconsistent extensions)"\
            .format(obsolete_group_name)
        conversations[conversation_name] = conversation

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

    print("Negotiating obsolete curves with TLS 1.3 server")
    print("Check that TLS 1.3 server will not use or accept obsolete curves")
    print("in TLS 1.3.")
    print("Reproduces https://github.com/openssl/openssl/issues/8369\n")

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
