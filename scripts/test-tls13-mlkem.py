# Author: Alicja Kario, (c) 2024
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
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import key_share_gen, SIG_ALL
from tlslite.utils.compat import ML_KEM_AVAILABLE


version = 3


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
    print(" --kems list    Comma separated list of KEMs that the server is expected to support")
    print("                'x25519mlkem768,secp256r1mlkem768,secp384r1mlkem1024' by default")
    print(" --cookie       expect the server to send \"cookie\" extension in")
    print("                Hello Retry Request message")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    ciphers = None
    cookie = False
    kems = [GroupName.secp256r1mlkem768,
            GroupName.x25519mlkem768,
            GroupName.secp384r1mlkem1024]

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:C:",
                               ["help", "kems=", "cookie"])
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
        elif opt == '-C':
            if arg[:2] == '0x':
                ciphers = [int(arg, 16)]
            else:
                try:
                    ciphers = [getattr(CipherSuite, arg)]
                except AttributeError:
                    ciphers = [int(arg)]
        elif opt == "--kems":
            kems = [getattr(GroupName, i) for i in arg.split(",")]
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

    if not ciphers:
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256]

    if not ML_KEM_AVAILABLE:
        raise ValueError("kyber-py library missing!")

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    default_ext = {}
    groups = GroupName.allKEM
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    default_ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    default_ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    default_ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.ed25519,
                SignatureScheme.ed448]
    default_ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    default_ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)
    ext = dict(default_ext)
    node = node.add_child(ClientHelloGenerator(
        ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
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

    for group in GroupName.allKEM:
        conversation = Connect(host, port)
        node = conversation
        ext = dict(default_ext)
        groups = [group]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=ext))
        if group not in kems:
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal,
                AlertDescription.handshake_failure))
            node = node.add_child(ExpectClose())
        else:
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
        conversations["connection with {0}".format(GroupName.toStr(group))] = conversation

        if group in kems:
            conversation = Connect(host, port)
            node = conversation
            ext = dict(default_ext)
            groups = [group]
            ext[ExtensionType.key_share] = ClientKeyShareExtension().create([])
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            node = node.add_child(ClientHelloGenerator(
                ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
                extensions=ext))
            node = node.add_child(ExpectHelloRetryRequest())
            node = node.add_child(ExpectChangeCipherSpec())

            key_shares = []
            ext = dict(default_ext)
            groups = [group]
            for group in groups:
                key_shares.append(key_share_gen(group))
            ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            if cookie:
                ext[ExtensionType.cookie] = ch_cookie_handler
            node = node.add_child(ClientHelloGenerator(
                ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
                extensions=ext))
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
            conversations["connection with {0} with HRR".format(GroupName.toStr(group))] = conversation

            conversation = Connect(host, port)
            node = conversation
            ext = dict(default_ext)
            groups = [group]
            key_shares = [key_share_gen(group)]
            if group == GroupName.x25519mlkem768:
                len_prev = len(key_shares[0].key_exchange)
                key_shares[0].key_exchange[1184:] = bytearray(32)
                assert len(key_shares[0].key_exchange) == len_prev
            elif group == GroupName.secp256r1mlkem768:
                key_shares[0].key_exchange[2] ^= 0xff
            else:
                assert group == GroupName.secp384r1mlkem1024
                key_shares[0].key_exchange[2] ^= 0xff
            ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            node = node.add_child(ClientHelloGenerator(
                ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
                extensions=ext))
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal,
                AlertDescription.illegal_parameter))
            node = node.add_child(ExpectClose())

            conversations["{0}: malformed classical part".format(GroupName.toStr(group))] = conversation

            conversation = Connect(host, port)
            node = conversation
            ext = dict(default_ext)
            groups = [group]
            key_shares = [key_share_gen(group)]
            if group == GroupName.x25519mlkem768:
                key_shares[0].key_exchange[1] = 0xff
            elif group == GroupName.secp256r1mlkem768:
                key_shares[0].key_exchange[67] = 0xff
            else:
                assert group == GroupName.secp384r1mlkem1024
                key_shares[0].key_exchange[98] = 0xff
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
                ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
                extensions=ext))
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal,
                AlertDescription.illegal_parameter))
            node = node.add_child(ExpectClose())

            conversations["{0}: malformed pqc part".format(GroupName.toStr(group))] = conversation

            conversation = Connect(host, port)
            node = conversation
            ext = dict(default_ext)
            groups = [group]
            key_shares = [key_share_gen(group)]
            del key_shares[0].key_exchange[-1]
            ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            node = node.add_child(ClientHelloGenerator(
                ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
                extensions=ext))
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal,
                AlertDescription.illegal_parameter))
            node = node.add_child(ExpectClose())

            conversations["{0}: truncated key share".format(GroupName.toStr(group))] = conversation

            conversation = Connect(host, port)
            node = conversation
            ext = dict(default_ext)
            groups = [group]
            key_shares = [key_share_gen(group)]
            key_shares[0].key_exchange += bytearray([0x02])
            ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            node = node.add_child(ClientHelloGenerator(
                ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
                extensions=ext))
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal,
                AlertDescription.illegal_parameter))
            node = node.add_child(ExpectClose())

            conversations["{0}: padded key share".format(GroupName.toStr(group))] = conversation

            # for NIST curves we do have option to send sort-of valid
            # key shares, but prohibited by the standard
            if group in (GroupName.secp256r1mlkem768,
                         GroupName.secp384r1mlkem1024):
                for point_format in ["compressed", "hybrid", "raw"]:
                    conversation = Connect(host, port)
                    node = conversation
                    ext = dict(default_ext)
                    groups = [group]
                    key_shares = [key_share_gen(group, point_format=point_format)]
                    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
                    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                        .create(groups)
                    node = node.add_child(ClientHelloGenerator(
                        ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
                        extensions=ext))
                    node = node.add_child(ExpectAlert(
                        AlertLevel.fatal,
                        AlertDescription.illegal_parameter))
                    node = node.add_child(ExpectClose())

                    conversations["{0}: invalid ECDH point format: {1}".format(
                        GroupName.toStr(group), point_format)] = conversation


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
        regular_tests = [(k, v) for k, v in conversations.items() if k in run_only]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
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

    print("Test hybrid ML-KEM key share support")
    print("Verify that hybrid ML-KEM key exchange groups are supported and")
    print("basic error handling is implemented correctly.\n")

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
