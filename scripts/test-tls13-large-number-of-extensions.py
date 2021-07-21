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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
        TLSExtension
from tlsfuzzer.helpers import key_share_gen, RSA_SIG_ALL, AutoEmptyExtension
from tlsfuzzer.fuzzers import structured_random_iter


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(20)")
    print("                (excluding \"sanity\" tests)")
    print(" --exc ext-id   exclude specific extenion id from a list")
    print("                of unassigned extenions,")
    print("                may be specified multiple times")
    print(" --supgroup     if present, test expect supported_groups extension")
    print("                in EncryptedExtension message")
    print(" --separate ext-id test one extension in isolation, may be")
    print("                specified multiple times")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = 20
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    ext_exclude = set()
    exp_sup_groups = False
    individual_ext = []

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:",
                               ["help", "exc=", "supgroup", "separate="])
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
        elif opt == '--exc':
            ext_exclude.add(int(arg))
        elif opt == '--supgroup':
            exp_sup_groups = True
        elif opt == "--separate":
            individual_ext.append(int(arg))
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
        .create([TLS_1_3_DRAFT])
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

    expect_exts_sh = {ExtensionType.key_share: None,
                      ExtensionType.supported_versions: None}
    expect_exts_ee = {}
    if exp_sup_groups:
        expect_exts_ee[ExtensionType.supported_groups] = None

    unassigned_ext_id = []
    unassigned_ext_id.extend(range(2, 5))
    unassigned_ext_id.extend(range(6, 10))
    unassigned_ext_id.extend([11, 12, 17])
    unassigned_ext_id.extend(range(22, 28))
    unassigned_ext_id.extend(range(29, 41))
    unassigned_ext_id.extend([46])
    unassigned_ext_id.extend(range(52, 65536))

    # Exclude extensions from a list of unassigned ones
    unassigned_ext_id = [ext for ext in unassigned_ext_id if ext not in ext_exclude]

    chunk_size = 4096
    for ext_chunk in (unassigned_ext_id[j:j + chunk_size]
                      for j in range(0, len(unassigned_ext_id), chunk_size)):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = OrderedDict()
        for ext_id in ext_chunk:
            ext[ext_id] = AutoEmptyExtension()
        if ExtensionType.renegotiation_info in ext:
            ext[ExtensionType.renegotiation_info] = None

        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([TLS_1_3_DRAFT])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(extensions=expect_exts_sh))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions(
            extensions=expect_exts_ee))
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
        conversations["empty unassigned extensions, ids in range from {0} to {1}".format(
            ext_chunk[0], ext_chunk[-1])] = conversation

    chunk_size = 1024
    for ext_chunk in (unassigned_ext_id[j:j + chunk_size]
                      for j in range(0, len(unassigned_ext_id), chunk_size)):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        random_payload = structured_random_iter(max_length=2**6,
                                                count=len(ext_chunk))
        ext = OrderedDict()
        for ext_id in ext_chunk:
            ext[ext_id] = TLSExtension(extType=ext_id).create(next(random_payload).data)
        if ExtensionType.renegotiation_info in ext:
            ext[ExtensionType.renegotiation_info] = None

        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([TLS_1_3_DRAFT])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(extensions=expect_exts_sh))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions(
            extensions=expect_exts_ee))
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
        conversations["unassigned extensions with random payload, ids in range from {0} to {1}".format(
            ext_chunk[0], ext_chunk[-1])] = conversation

    # test the special one user asked for
    for ext_id in individual_ext:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = OrderedDict()
        if ExtensionType.renegotiation_info in ext:
            ext[ExtensionType.renegotiation_info] = None

        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([TLS_1_3_DRAFT])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(RSA_SIG_ALL)
        ext[ext_id] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(extensions=expect_exts_sh))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions(
            extensions=expect_exts_ee))
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
        conversations["empty unassigned extension id {0}".format(
            ext_id)] = conversation

        # and now with random payload
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = OrderedDict()
        if ExtensionType.renegotiation_info in ext:
            ext[ExtensionType.renegotiation_info] = None

        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([TLS_1_3_DRAFT])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(RSA_SIG_ALL)
        random_payload = structured_random_iter(max_length=2**6,
                                                count=1)
        ext[ext_id] = TLSExtension(extType=ext_id)\
            .create(next(random_payload).data)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(extensions=expect_exts_sh))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions(
            extensions=expect_exts_ee))
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
        conversations["unassigned extension with random payload, id {0}"
            .format(ext_id)] = conversation

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

    print("Test with large number of unassigned extensions in TLS 1.3")
    print("Verify that server does not reply to any of these extensions")
    print("and establish regular session.\n")

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
