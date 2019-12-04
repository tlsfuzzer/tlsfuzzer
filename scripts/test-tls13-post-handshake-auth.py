# Author: Hubert Kario, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain, islice

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        CertificateVerifyGenerator, CertificateGenerator, KeyUpdateGenerator, \
        ClearContext
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket, ExpectCertificateRequest, ExpectKeyUpdate

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme, \
        KeyUpdateMessageType
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import key_share_gen, RSA_SIG_ALL, AutoEmptyExtension
from tlslite.x509certchain import X509CertChain
from tlslite.x509 import X509
from tlslite.utils.keyfactory import parsePEMKey


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
    print("                (\"sanity\" tests are always executed)")
    print(" -k keyfile     file with private key")
    print(" -c certfile    file with certificate of client")
    print(" --pha-as-reply expect post-handshake auth request as a reply to")
    print("                the HTTP GET instead of right after handshake")
    print(" --cert-required expect the server to require a client certificate")
    print("                and reply with certificate_required")
    print(" --min-tickets n Require the server to provide at least 'n' tickets")
    print("                before performing PHA. Defaults to 0.")
    print(" --query txt    Message to send to server to cause it to request")
    print("                post-handshake authentication.")
    print("                \"GET /secret HTTP/1.0\\r\\n\\r\\n\" by default")
    print(" --pha-in-sanity Set when server requires the connections to always")
    print("                advertise support for PHA. This will cause")
    print("                \"sanity\" to be equal to \"post-handshake")
    print("                authentication\" test case.")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    pha_as_reply = False
    cert_required = False
    pha_in_sanity = False
    min_tickets = 0
    pha_query = b'GET /secret HTTP/1.0\r\n\r\n'

    argv = sys.argv[1:]
    opts, args = getopt.getopt(
        argv, "h:p:e:n:k:c:",
        ["help", "pha-as-reply", "cert-required", "min-tickets=", "query=",
         "pha-in-sanity"])
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
        elif opt == '--pha-as-reply':
            pha_as_reply = True
        elif opt == '--pha-in-sanity':
            pha_in_sanity = True
        elif opt == '--cert-required':
            cert_required = True
        elif opt == '--query':
            pha_query = arg
        elif opt == '--min-tickets':
            min_tickets = int(arg)
        elif opt == '-k':
            text_key = open(arg, 'rb').read()
            if sys.version_info[0] >= 3:
                text_key = str(text_key, 'utf-8')
            private_key = parsePEMKey(text_key, private=True)
        elif opt == '-c':
            text_cert = open(arg, 'rb').read()
            if sys.version_info[0] >= 3:
                text_cert = str(text_cert, 'utf-8')
            cert = X509()
            cert.parse(text_cert)
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

    for _ in range(min_tickets):
        node = node.add_child(ExpectNewSessionTicket(note="counted"))

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

    # test post-handshake authentication
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
    ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    if pha_as_reply:
        node = node.add_child(ApplicationDataGenerator(
            bytearray(pha_query)))

    for _ in range(min_tickets):
        node = node.add_child(ExpectNewSessionTicket(note="counted"))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket(note="first set")
    node = node.add_child(cycle)
    node.add_child(cycle)

    context = []
    node.next_sibling = ExpectCertificateRequest(context=context)
    node = node.next_sibling.add_child(CertificateGenerator(X509CertChain([cert]), context=context))
    node = node.add_child(CertificateVerifyGenerator(private_key, context=context))
    node = node.add_child(FinishedGenerator(context=context))
    node = node.add_child(ClearContext(context))
    if not pha_as_reply:
        node = node.add_child(ApplicationDataGenerator(
            bytearray(pha_query)))

    # just like after the first handshake, after PHA, the NST can be sent
    # multiple times
    cycle = ExpectNewSessionTicket(note="second set")
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["post-handshake authentication"] = conversation
    if pha_in_sanity:
        conversations["sanity"] = conversation

    # test post-handshake authentication with KeyUpdate
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
    ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    if pha_as_reply:
        node = node.add_child(ApplicationDataGenerator(
            bytearray(pha_query)))

    for _ in range(min_tickets):
        node = node.add_child(ExpectNewSessionTicket(note="counted"))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket(note="first set")
    node = node.add_child(cycle)
    node.add_child(cycle)

    context = []
    node.next_sibling = ExpectCertificateRequest(context=context)
    node = node.next_sibling.add_child(KeyUpdateGenerator(
        KeyUpdateMessageType.update_requested))
    node = node.add_child(CertificateGenerator(X509CertChain([cert]), context=context))
    node = node.add_child(CertificateVerifyGenerator(private_key, context=context))
    node = node.add_child(FinishedGenerator(context=context))
    if not pha_as_reply:
        node = node.add_child(ApplicationDataGenerator(
            bytearray(pha_query)))

    # just like after the first handshake, after PHA, the NST can be sent
    # multiple times
    cycle = ExpectNewSessionTicket(note="second set")
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectKeyUpdate(
        KeyUpdateMessageType.update_not_requested)
    node = node.next_sibling.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["post-handshake authentication with KeyUpdate"] = conversation

    # test post-handshake with client not providing a certificate
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
    ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    if pha_as_reply:
        node = node.add_child(ApplicationDataGenerator(
            bytearray(pha_query)))

    for _ in range(min_tickets):
        node = node.add_child(ExpectNewSessionTicket(note="counted"))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket(note="first set")
    node = node.add_child(cycle)
    node.add_child(cycle)

    context = []
    node.next_sibling = ExpectCertificateRequest(context=context)
    node = node.next_sibling.add_child(CertificateGenerator(X509CertChain([]), context=context))
    node = node.add_child(FinishedGenerator(context=context))
    if not pha_as_reply:
        node = node.add_child(ApplicationDataGenerator(
            bytearray(pha_query)))

    if cert_required:
        node = node.add_child(ExpectAlert(
            AlertLevel.fatal,
            AlertDescription.certificate_required))
        node.add_child(ExpectClose())
    else:
        # just like after the first handshake, after PHA, the NST can be sent
        # multiple times
        cycle = ExpectNewSessionTicket(note="second set")
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectApplicationData()
        node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                           AlertDescription.close_notify))

        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
    conversations["post-handshake authentication with no client cert"] = conversation

    # malformed signatures in post-handshake authentication
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
    ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    if pha_as_reply:
        node = node.add_child(ApplicationDataGenerator(
            bytearray(pha_query)))

    for _ in range(min_tickets):
        node = node.add_child(ExpectNewSessionTicket(note="counted"))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    context = []
    node.next_sibling = ExpectCertificateRequest(context=context)
    node = node.next_sibling.add_child(CertificateGenerator(X509CertChain([cert]), context=context))
    node = node.add_child(CertificateVerifyGenerator(private_key, padding_xors={-1: 0xff}, context=context))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decrypt_error))
    node.add_child(ExpectClose())
    #node = node.add_child(FinishedGenerator(context=context))
    conversations["malformed signature in PHA"] = conversation


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

    print("Basic post-handshake authentication test case")
    print("Check if server will accept PHA, check if server rejects invalid")
    print("signatures on PHA CertificateVerify, etc.")
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
