# Author: Simo Sorce, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test with CertificateRequest"""

from __future__ import print_function
import traceback
import sys
import getopt
import re
from random import sample
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
    """Check what signature algorithms server advertises"""
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
    conversations["sanity"] = conversation

    if cert and private_key:
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
        conversations["with certificate"] = conversation

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

    # run the conversation
    good = 0
    bad = 0
    failed = []

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
    shuffled_tests = sample(regular_tests, len(regular_tests))
    ordered_tests = chain(sanity_tests, shuffled_tests, sanity_tests)

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

    print("Test to verify if server accepts empty certificate messages and")
    print("advertises only expected signature algotithms in Certificate")
    print("Request message\n")
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
