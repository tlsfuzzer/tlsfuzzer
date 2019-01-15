# Author: Hubert Kario, (c) 2015-2018
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain, islice

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        gen_srv_ext_handler_record_limit, ExpectEncryptedExtensions, \
        ExpectCertificateVerify, ExpectNewSessionTicket
from tlsfuzzer.helpers import key_share_ext_gen, RSA_SIG_ALL
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName, TLS_1_3_DRAFT, SignatureScheme
from tlslite.extensions import RecordSizeLimitExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension


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
    print(" --expect-size  size to expect from server (+1 for TLS 1.3), 2^14")
    print("                by default")
    print(" --supported-groups expect the server to send supported_groups")
    print("                extension in EncryptedExtensions in TLS 1.3")
    print(" --reply-AD-size size in bytes of the server reply (Application Data)")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expect_size = 2**14
    supported_groups = False
    reply_size = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:",
                               ["help", "expect-size=",
                                "supported-groups", "reply-AD-size="])
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
        elif opt == '--expect-size':
            expect_size = int(arg)
        elif opt == '--supported-groups':
            supported_groups = True
        elif opt == '--reply-AD-size':
            reply_size = int(arg)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if not reply_size:
        raise ValueError("--reply-AD-size not provided")

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    extensions = {ExtensionType.record_size_limit:
                  RecordSizeLimitExtension().create(2**14+1)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=extensions))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
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

    # sanity in TLS 1.3 (just check if server accepts it)
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**14+1)
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
    conversations["sanity in TLS 1.3"] = conversation

    # check sizes
    for name, vers in [("TLS 1.0", (3, 1)),
                       ("TLS 1.1", (3, 2)),
                       ("TLS 1.2", (3, 3))]:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        extensions = {ExtensionType.record_size_limit:
                      RecordSizeLimitExtension().create(2**14+1)}
        node = node.add_child(ClientHelloGenerator(
            ciphers, version=vers, extensions=extensions))
        ext = {ExtensionType.record_size_limit:
               gen_srv_ext_handler_record_limit(expect_size),
               ExtensionType.renegotiation_info: None}
        node = node.add_child(ExpectServerHello(extensions=ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        if vers == (3, 1):
            # 1/n-1 record splitting
            node = node.add_child(ExpectApplicationData(size=1))
            node = node.add_child(ExpectApplicationData(size=reply_size-1))
        else:
            node = node.add_child(ExpectApplicationData(size=reply_size))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["check server sent size in {0}".format(name)] = conversation

        # minimal size test
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        extensions = {ExtensionType.record_size_limit:
                      RecordSizeLimitExtension().create(64)}
        node = node.add_child(ClientHelloGenerator(
            ciphers, version=vers, extensions=extensions))
        ext = {ExtensionType.record_size_limit:
               gen_srv_ext_handler_record_limit(expect_size),
               ExtensionType.renegotiation_info: None}
        node = node.add_child(ExpectServerHello(extensions=ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        remaining_size = reply_size
        if vers == (3, 1):
            # 1/n-1 record splitting
            node = node.add_child(ExpectApplicationData(size=1))
            remaining_size -= 1
        for _ in range(0, max(0, remaining_size - 64), 64):
            node = node.add_child(ExpectApplicationData(size=64))
        node = node.add_child(ExpectApplicationData(size=remaining_size % 64))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["check if server accepts minimal size in {0}".format(name)] = conversation

        # maximal size test
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        extensions = {ExtensionType.record_size_limit:
                      RecordSizeLimitExtension().create(2**16-1)}
        node = node.add_child(ClientHelloGenerator(
            ciphers, version=vers, extensions=extensions))
        ext = {ExtensionType.record_size_limit:
               gen_srv_ext_handler_record_limit(expect_size),
               ExtensionType.renegotiation_info: None}
        node = node.add_child(ExpectServerHello(extensions=ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        if vers == (3, 1):
            # 1/n-1 record splitting
            node = node.add_child(ExpectApplicationData(size=1))
            node = node.add_child(ExpectApplicationData(size=reply_size-1))
        else:
            node = node.add_child(ExpectApplicationData(size=reply_size))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["check if server accepts maximum size in {0}".format(name)] = conversation

    # verify that the size advertised by server is the expected one
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**14+1)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
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

    node.next_sibling = ExpectApplicationData(size=reply_size)
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["check server sent size in TLS 1.3"] = conversation

    # check if server accepts small sizes
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(64)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
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

    node.next_sibling = ExpectApplicationData(size=63)
    node = node.next_sibling
    # in TLS 1.3 the content type is included in the limit so every
    # record will send one byte less than simple reading of extension would
    # indicate
    for _ in range(0, max(reply_size-63*2, 0), 63):
        node = node.add_child(ExpectApplicationData(size=63))
    node = node.add_child(ExpectApplicationData(size=reply_size%63))
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                          AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["check if server accepts minimal size in TLS 1.3"] = conversation

    # maximum size test
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.record_size_limit] = RecordSizeLimitExtension()\
        .create(2**16-1)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    ext = {}
    ext[ExtensionType.record_size_limit] = \
        gen_srv_ext_handler_record_limit(expect_size + 1)
    if supported_groups:
        ext[ExtensionType.supported_groups] = None
    node = node.add_child(ExpectEncryptedExtensions(extensions=ext))
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

    node.next_sibling = ExpectApplicationData(size=reply_size)
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["check if server accepts maximum size in TLS 1.3"] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throught
    sanity_test = ('sanity', conversations['sanity'])
    ordered_tests = chain([sanity_test],
                          islice(filter(lambda x: x[0] != 'sanity',
                                        conversations.items()), num_limit),
                          [sanity_test])

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

    print("Checks for record_size_limit extension")
    print("Verify that the record_size_limit extension is correctly handled")
    print("by the server: parsing, validation and interaction with basic TLS")
    print("features")
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
