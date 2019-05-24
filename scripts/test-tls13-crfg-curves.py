# Author: Robert Kolcun, (c) 2018
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
        TCPBufferingEnable, TCPBufferingFlush, TCPBufferingDisable
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme, \
        ECPointFormat
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
        ECPointFormatsExtension
from tlsfuzzer.helpers import key_share_gen, RSA_SIG_ALL
from tlslite.utils.x25519 import X25519_ORDER_SIZE, X448_ORDER_SIZE
from tlslite.utils.cryptomath import numberToByteArray


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
    print(" -n num         only run `num` random tests instead of a full set")
    print("                (excluding \"sanity\" tests)")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
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

    test_groups = {
        GroupName.x25519: X25519_ORDER_SIZE,
        GroupName.x448: X448_ORDER_SIZE,
    }

    # check if server will negotiate x25519/x448 - sanity check
    for test_group, group_size in test_groups.items():
        for compression_format in [ECPointFormat.ansiX962_compressed_prime,
                                   ECPointFormat.ansiX962_compressed_char2,
                                   ECPointFormat.uncompressed]:
            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {}
            ext[ExtensionType.ec_point_formats] = ECPointFormatsExtension().create([compression_format])
            groups = [test_group]
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
            conversations["sanity {0} with compression {1}".format(
                GroupName.toRepr(test_group), ECPointFormat.toRepr(compression_format))] = conversation

        # check if server will reject an all-zero key share for x25519/x448
        # (it should result in all-zero shared secret)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [test_group]

        key_shares = [KeyShareEntry().create(test_group,  bytearray(group_size))]
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
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.illegal_parameter))
        node.add_child(ExpectClose())
        conversations["all zero {0} key share".format(GroupName.toRepr(test_group))] = conversation

        # check if server will reject a key share or 1 for x25519/x448
        # (it should result in all-zero shared secret)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [test_group]

        key_shares = [KeyShareEntry().create(test_group,
            numberToByteArray(1, group_size, "little"))]
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
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.illegal_parameter))
        node.add_child(ExpectClose())
        conversations["{0} key share of \"1\"".format(GroupName.toRepr(test_group))] = conversation

        # check if server will reject too small x25519/x448 share
        # (one with too few bytes in the key share)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [test_group]

        key_shares = [KeyShareEntry().create(test_group, bytearray([55] * (group_size - 1)))]
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
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.illegal_parameter))
        node.add_child(ExpectClose())
        conversations["too small {0} key share".format(GroupName.toRepr(test_group))] = conversation

        # check if server will reject empty x25519/x448 share
        # no compression
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [test_group]

        key_shares = [KeyShareEntry().create(test_group, bytearray())]
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
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.illegal_parameter))
        node.add_child(ExpectClose())
        conversations["empty {0} key share".format(GroupName.toRepr(test_group))] = conversation

        # check if server will reject too big x25519/x448 share
        # (one with too many bytes in the key share)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [test_group]

        key_shares = [KeyShareEntry().create(test_group, bytearray([55] * (group_size + 1)))]
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
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.illegal_parameter))
        node.add_child(ExpectClose())
        conversations["too big {0} key share".format(GroupName.toRepr(test_group))] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except Exception:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Basic test to verify that server selects same ECDHE parameters")
    print("and ciphersuites when x25519 or x448 curve is an option\n")
    print("version: {0}\n".format(version))

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
