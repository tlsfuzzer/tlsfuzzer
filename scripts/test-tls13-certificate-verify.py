# Author: Simo Sorce, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test with CertificateVerify"""

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, \
        AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData, ExpectEncryptedExtensions, \
        ExpectCertificateVerify, ExpectNewSessionTicket
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import key_share_gen, sig_algs_to_ids, RSA_SIG_ALL
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType, SignatureScheme, \
        GroupName
from tlslite.utils.cryptomath import numBytes
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain


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
    print(" -s sigalgs     hash and signature algorithm pairs that the server")
    print("                is expected to support.")
    print(" -k keyfile     file with private key of client")
    print(" -c certfile    file with the certificate of client")
    print(" --help         this message")


def main():
    """Check that server propoerly rejects pkcs1 signatures in TLS 1.3"""
    hostname = "localhost"
    port = 4433
    run_exclude = set()
    cert = None
    private_key = None

    sigalgs = [SignatureScheme.rsa_pss_rsae_sha512,
               SignatureScheme.rsa_pss_pss_sha512,
               SignatureScheme.rsa_pss_rsae_sha384,
               SignatureScheme.rsa_pss_pss_sha384,
               SignatureScheme.rsa_pss_rsae_sha256,
               SignatureScheme.rsa_pss_pss_sha256,
               SignatureScheme.rsa_pkcs1_sha512,
               SignatureScheme.rsa_pkcs1_sha384,
               SignatureScheme.rsa_pkcs1_sha256,
               SignatureScheme.rsa_pkcs1_sha224,
               SignatureScheme.rsa_pkcs1_sha1]

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:s:k:c:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '-s':
            sigalgs = sig_algs_to_ids(arg)
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

    if not cert or not private_key:
        raise Exception("A Client certificate and a private key are required")

    certType = cert.certAlg

    conversations = {}

    # sanity check for Client Certificates
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = \
        ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = \
        SupportedVersionsExtension().create([(3, 4), (3, 3)])
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(CertificateVerifyGenerator(private_key))
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

    # verify the advertised hashes
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = \
        ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = \
        SupportedVersionsExtension().create([(3, 4), (3, 3)])
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificateRequest(sigalgs))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(CertificateGenerator())
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

    conversations["check sigalgs in cert request"] = conversation

    for sigalg in ((HashAlgorithm.md5, SignatureAlgorithm.rsa),
                   SignatureScheme.rsa_pkcs1_sha1,
                   SignatureScheme.rsa_pkcs1_sha224,
                   SignatureScheme.rsa_pkcs1_sha256,
                   SignatureScheme.rsa_pkcs1_sha384,
                   SignatureScheme.rsa_pkcs1_sha512):
        # verify that pkcs1 signatures are refused
        conversation = Connect(hostname, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([(3, 4), (3, 3)])
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        # force pkcs1 sigalg
        node = node.add_child(CertificateVerifyGenerator(private_key, msg_alg=
            sigalg))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(
            AlertLevel.fatal, AlertDescription.illegal_parameter))
        node.add_child(ExpectClose())

        scheme = SignatureScheme.toRepr(sigalg)
        if not scheme:
            scheme = "RSA with MD5"
        conversations["check {0} signature is refused".format(
                      scheme)] = conversation

    for sigalg in sigalgs:
        # we want to check only non-pkcs1 sigalgs here:
        scheme = SignatureScheme.toRepr(sigalg)
        if SignatureScheme.getPadding(scheme) == "pkcs1":
            continue
        # set if test should succeed or fail based on cert type
        expectPass = True
        if certType == "rsa" and sigalg in (
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512):
            expectPass = False
        elif certType == "rsa-pss" and sigalg in (
            SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512):
            expectPass = False
        # verify that advertised signatures are accepted
        conversation = Connect(hostname, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([(3, 4), (3, 3)])
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sigalgs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        # force sigalg
        node = node.add_child(CertificateVerifyGenerator(private_key, msg_alg=
            sigalg))
        node = node.add_child(FinishedGenerator())
        # only signatures of matching certificate type should work
        if expectPass:
            node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
            # This message is optional and may show up 0 to many times
            cycle = ExpectNewSessionTicket()
            node = node.add_child(cycle)
            node.add_child(cycle)

            node.next_sibling = ExpectApplicationData()
            node = node.next_sibling.add_child(AlertGenerator(
                AlertLevel.warning, AlertDescription.close_notify))

            node = node.add_child(ExpectAlert())
            node.next_sibling = ExpectClose()

            conversations["check {0} signature works".format(
                          scheme)] = conversation
        else:
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal, AlertDescription.illegal_parameter))
            node.add_child(ExpectClose())

            conversations["check {0} signature is refused".format(
                          scheme)] = conversation

    for saltlen in (0, 1, 129):
        # verify that rsa-pss signatures with too short, too long, or empty
        # salt fail
        if certType != 'rsa-pss':
            continue
        conversation = Connect(hostname, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([(3, 4), (3, 3)])
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        # force salt length
        node = node.add_child(CertificateVerifyGenerator(
            private_key, rsa_pss_salt_len=saltlen))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(
            AlertLevel.fatal, AlertDescription.decrypt_error))
        node.add_child(ExpectClose())

        scheme = SignatureScheme.toRepr(sigalg)
        conversations["check signature with salt length {0}".format(
                      saltlen)] = conversation

    # verify that a rsa-pkcs1 signature in a rsa-pss ID envelope fails
    if certType == 'rsa-pss':
        conversation = Connect(hostname, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([(3, 4), (3, 3)])
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        node = node.add_child(CertificateVerifyGenerator(
            private_key, sig_alg=SignatureScheme.rsa_pkcs1_sha256,
            msg_alg=SignatureScheme.rsa_pss_pss_sha256))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(
            AlertLevel.fatal, AlertDescription.decrypt_error))
        node.add_child(ExpectClose())

        scheme = SignatureScheme.toRepr(sigalg)
        conversations["check pkcs1 signature with rsa-pss envelope fails"] = \
            conversation

    # verify that a rsa-pss signature with mismatched message hash fails
    if certType == 'rsa-pss':
        conversation = Connect(hostname, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([(3, 4), (3, 3)])
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        node = node.add_child(CertificateVerifyGenerator(
            private_key, sig_alg=SignatureScheme.rsa_pss_pss_sha384,
            msg_alg=SignatureScheme.rsa_pss_pss_sha256))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(
            AlertLevel.fatal, AlertDescription.decrypt_error))
        node.add_child(ExpectClose())

        scheme = SignatureScheme.toRepr(sigalg)
        conversations["check rsa-pss signature with mismatched hash fails"] = \
            conversation

    # verify that a rsa-pss signature with mismatched MGF1 hash fails
    if certType == 'rsa-pss':
        conversation = Connect(hostname, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([(3, 4), (3, 3)])
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        node = node.add_child(CertificateVerifyGenerator(
            private_key, mgf1_hash='sha384',
            msg_alg=SignatureScheme.rsa_pss_pss_sha256))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(
            AlertLevel.fatal, AlertDescription.decrypt_error))
        node.add_child(ExpectClose())

        scheme = SignatureScheme.toRepr(sigalg)
        conversations["check rsa-pss signature with mismatched mgf1 fails"] = \
            conversation

    # check that fuzzed signatures are rejected
    for pos in range(numBytes(private_key.n)):
        for xor in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            conversation = Connect(hostname, port)
            node = conversation
            ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {}
            groups = [GroupName.secp256r1]
            key_shares = []
            for group in groups:
                key_shares.append(key_share_gen(group))
            ext[ExtensionType.key_share] = \
                ClientKeyShareExtension().create(key_shares)
            ext[ExtensionType.supported_versions] = \
                SupportedVersionsExtension().create([(3, 4), (3, 3)])
            ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
            sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                        SignatureScheme.rsa_pss_pss_sha256]
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sig_algs)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
            node = node.add_child(ClientHelloGenerator(
                ciphers, extensions=ext))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectEncryptedExtensions())
            node = node.add_child(ExpectCertificateRequest())
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectCertificateVerify())
            node = node.add_child(ExpectFinished())
            node = node.add_child(CertificateGenerator(X509CertChain([cert])))
            node = node.add_child(CertificateVerifyGenerator(
                private_key, padding_xors={pos:xor}))
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal, AlertDescription.decrypt_error))
            node.add_child(ExpectClose())

            scheme = SignatureScheme.toRepr(sigalg)
            conversations["check that fuzzed signatures are rejected"] = \
                conversation


    # run the conversation
    good = 0
    bad = 0
    failed = []

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throught
    sanity_test = ('sanity', conversations['sanity'])
    ordered_tests = chain([sanity_test],
                          filter(lambda x: x[0] != 'sanity',
                                 conversations.items()),
                          [sanity_test])

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Test to verify that server properly accepts or refuses")
    print("signatures in TLS1.3; PKCS1 signatures are always refused.")
    print("Other signatures are accepted or refused accordingly to")
    print("the certificate type provided ('rsa' vs 'rsa-pss').\n")
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
