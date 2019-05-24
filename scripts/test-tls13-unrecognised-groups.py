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
from tlsfuzzer.helpers import key_share_gen, RSA_SIG_ALL


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
    print(" --cookie       expect the server to send \"cookie\" extension in")
    print("                Hello Retry Request message")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    cookie = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:", ["help", "cookie"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '--cookie':
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

    unknown_groups = {
        'EC': list(range(34, 255)),  # Unassigned groups from EC range
        'FFDHE': list(range(261, 507)),  # Unassigned groups from FFDHE range
    }
    known_groups = [GroupName.secp256r1, GroupName.ffdhe2048]

    # Unknown key_shares, one known group and range of unknown groups in supported_groups
    for group_name, unknown_group in unknown_groups.items():
        for size in [64, 128, 256]:
            for known_group in known_groups:
                conversation = Connect(host, port)
                node = conversation
                ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
                ext = OrderedDict()

                groups = [known_group] + unknown_group
                key_shares = [KeyShareEntry().create(un_group, bytearray(b'\xab'*size)) for un_group in unknown_group]

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

                ext = OrderedDict()
                if cookie:
                    ext[ExtensionType.cookie] = None
                ext[ExtensionType.key_share] = None
                ext[ExtensionType.supported_versions] = None
                node = node.add_child(ExpectHelloRetryRequest(extensions=ext))
                node = node.add_child(ExpectChangeCipherSpec())

                ext = OrderedDict()
                groups = [known_group] + unknown_group
                key_shares = [key_share_gen(groups[0])]
                ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
                ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
                    .create([TLS_1_3_DRAFT, (3, 3)])
                ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                    .create(groups)
                if cookie:
                    ext[ExtensionType.cookie] = ch_cookie_handler
                sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                            SignatureScheme.rsa_pss_pss_sha256]
                ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
                    .create(sig_algs)
                ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
                    .create(RSA_SIG_ALL)
                node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
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

                conversations["only unknown key_share from {0} range, key_share of size {1} + {2} in supported_groups".format(
                    group_name, size, GroupName.toRepr(known_group))] = conversation

                # One known group and list of unknown groups, unknown ones are listed first
                conversation = Connect(host, port)
                node = conversation
                ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
                ext = OrderedDict()

                groups = unknown_group + [known_group]
                key_shares = [KeyShareEntry().create(un_group, bytearray(b'\xab'*size)) for un_group in unknown_group]
                key_shares.append(key_share_gen(groups[-1]))

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

                conversations["known group {0} and unknown groups from {1} range, key_share of size {2}".format(
                    GroupName.toRepr(known_group), group_name, size)] = conversation

            # Unknown supported_groups and key_shares
            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = OrderedDict()

            groups = unknown_group
            key_shares = [KeyShareEntry().create(un_group, bytearray(b'\xab'*size)) for un_group in unknown_group]

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
                                            AlertDescription.handshake_failure))
            node.add_child(ExpectClose())

            conversations["only unknown supported_groups from {0} range, key_share of size {1}".format(
                group_name, size)] = conversation

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

    print("Unrecognised groups in TLS 1.3")
    print("Check that server replies with HRR, aborts the connection")
    print("with handshake_failure or chooses a known group from client list.")
    print("Groups with IDs from FFDHE and ECDH range.\n")
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
