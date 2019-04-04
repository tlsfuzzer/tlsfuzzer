# Author: Simo Sorce, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test of ECDSA in CertificateVerify"""

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain, islice

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, \
        AlertGenerator, fuzz_message
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData, ExpectEncryptedExtensions, \
        ExpectCertificateVerify, ExpectNewSessionTicket
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import key_share_ext_gen, sig_algs_to_ids, RSA_SIG_ALL,\
        ECDSA_SIG_ALL
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType, SignatureScheme, \
        GroupName
from tlslite.utils import tlshashlib
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
    print(" -n num         only run `num` long random fuzzing tests")
    print("                instead of a full set")
    print("                (excluding \"sanity\" and other short tests)")
    print(" -s sigalgs     hash and signature algorithm pairs that the server")
    print("                is expected to support. Either pairs of algorithms")
    print("                (\"sha1+ecdsa\"), pairs of identifiers (\"1+1\")")
    print("                or the TLS 1.3 names (\"rsa_pss_rsae_sha256\").")
    print("                Multiple values separated by spaces.")
    print(" --hash-order   the order in which hashes are preferred in some")
    print("                tests, can be used to test different combinations")
    print(" -k keyfile     file with private key of client")
    print(" -c certfile    file with the certificate of client")
    print(" --help         this message")


def hashes_to_list(arg):
    hlist = []
    for h in arg.split():
        name = None
        hnum = getattr(HashAlgorithm, h, None)
        if not hnum:
            try:
                hnum = int(h)
            except ValueError:
                pass
        if hnum:
            name = HashAlgorithm.toRepr(hnum)
        if not name:
            raise ValueError("Invalid Hash Id or Name {0}".format(h))
        hlist.append(name)
    if len(hlist) < 2:
        raise ValueError(
            "The ordered list of hashes must contain at least 2 elements," +
            " found {0}".format(len(hlist)))
    return hlist


def sigalg_select(alg_type, hash_pref, supported=None, cert_type=None):
    for hash_name in hash_pref:
        if not cert_type:
            name = "_".join([alg_type, hash_name])
        elif cert_type == "rsa":
            name = "_".join([alg_type, "rsae", hash_name])
        elif cert_type == "rsa-pss":
            name = "_".join([alg_type, "pss", hash_name])
        elif cert_type == "ecdsa":
            name = "_".join([alg_type, hash_name])
        else:
            raise ValueError("Unknown certificate type {0}".format(cert_type))

        sigalg = getattr(SignatureScheme, name)

        if supported is None:
            return sigalg
        if sigalg in supported:
            return sigalg

    raise ValueError(
        "Couldn't find a supported Signature Algorithm that  matches the" +
        " provided parameters: {0}, {1}, {3}".format(alg_type, hash_pref,
                                                    cert_type))


def main():
    """Check that server propoerly rejects pkcs1 signatures in TLS 1.3"""
    hostname = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    cert = None
    private_key = None

    # algorithms to expect from server in Certificate Request
    cr_sigalgs = [SignatureScheme.ecdsa_secp521r1_sha512,
                  SignatureScheme.ecdsa_secp384r1_sha384,
                  SignatureScheme.ecdsa_secp256r1_sha256,
                  (HashAlgorithm.sha224, SignatureAlgorithm.ecdsa),
                  (HashAlgorithm.sha1, SignatureAlgorithm.ecdsa),
                  SignatureScheme.rsa_pss_rsae_sha512,
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

    # algorithms to advertise in ClientHello
    sig_algs = [SignatureScheme.ecdsa_secp521r1_sha512,
                SignatureScheme.ecdsa_secp384r1_sha384,
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_pss_sha384]

    hashalgs = hashes_to_list("sha256 sha384 sha512")

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:s:k:c:", ["help", "hash-order="])
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
        elif opt == '-s':
            cr_sigalgs = sig_algs_to_ids(arg)
        elif opt == '--hash-order':
            hashalgs = hashes_to_list(arg)
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
    conversations_long = {}

    # sanity check for Client Certificates
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = \
        SupportedVersionsExtension().create([(3, 4), (3, 3)])
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL + RSA_SIG_ALL)
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
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = \
        SupportedVersionsExtension().create([(3, 4), (3, 3)])
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL + RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificateRequest(cr_sigalgs))
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

    for sigalg in ECDSA_SIG_ALL:
        # set if test should succeed or fail based on cert type,
        # advertisement and forbidden algorithms
        expectPass = False
        if len(private_key) == 256 and \
                sigalg == SignatureScheme.ecdsa_secp256r1_sha256:
            expectPass = True
        elif len(private_key) == 384 and \
                sigalg == SignatureScheme.ecdsa_secp384r1_sha384:
            expectPass = True
        elif len(private_key) == 521 and \
                sigalg == SignatureScheme.ecdsa_secp521r1_sha512:
            expectPass = True
        # expect failure if an algorithm is not advertized
        if sigalg not in cr_sigalgs:
            expectPass = False

        conversation = Connect(hostname, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        # NOTE: groups do NOT influence the signature negotiation
        groups = [GroupName.secp256r1]
        ext[ExtensionType.key_share] = key_share_ext_gen(groups)
        ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([(3, 4), (3, 3)])
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL +
                                                      RSA_SIG_ALL)
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

        result = "works"
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

        else:
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal, AlertDescription.illegal_parameter))
            node.add_child(ExpectClose())

            result = "is refused"

        name = SignatureScheme.toRepr(sigalg)
        if not name:
            name = "{0}+{1}".format(HashAlgorithm.toStr(sigalg[0]),
                                    SignatureAlgorithm.toStr(sigalg[1]))
        conversations["check {0} signature {1}".format(
                      name, result)] = conversation

    # verify that an ECDSA signature with mismatched message hash fails
    if len(private_key) == 256:
        sig_alg = SignatureScheme.ecdsa_secp384r1_sha384
        msg_alg = SignatureScheme.ecdsa_secp256r1_sha256
    elif len(private_key) == 384:
        sig_alg = SignatureScheme.ecdsa_secp256r1_sha256
        msg_alg = SignatureScheme.ecdsa_secp384r1_sha384
    else:
        assert len(private_key) == 521
        sig_alg = SignatureScheme.ecdsa_secp384r1_sha384
        msg_alg = SignatureScheme.ecdsa_secp521r1_sha512

    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = \
        SupportedVersionsExtension().create([(3, 4), (3, 3)])
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL + RSA_SIG_ALL)
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
        private_key, sig_alg=sig_alg, msg_alg=msg_alg))
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectAlert(
        AlertLevel.fatal, AlertDescription.decrypt_error))
    node.add_child(ExpectClose())

    conversations["check ecdsa signature with mismatched hash fails"] = \
        conversation


    # check that fuzzed signatures are rejected
    if len(private_key) == 256:
        # bacause of DER encoding of the signature, the mapping between key size
        # and signature size is non-linear
        siglen = 70
    elif len(private_key) == 384:
        siglen = 103
    else:
        assert len(private_key) == 521
        siglen = 137
    for pos in range(siglen):
        for xor in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            conversation = Connect(hostname, port)
            node = conversation
            ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {}
            groups = [GroupName.secp256r1]
            ext[ExtensionType.key_share] = key_share_ext_gen(groups)
            ext[ExtensionType.supported_versions] = \
                SupportedVersionsExtension().create([(3, 4), (3, 3)])
            ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sig_algs)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL + \
                                                          RSA_SIG_ALL)
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
            node = node.add_child(
                CertificateVerifyGenerator(private_key,
                                           padding_xors={pos:xor}))
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectAlert(
                AlertLevel.fatal, AlertDescription.decrypt_error))
            node.add_child(ExpectClose())

            conversations_long["check that fuzzed signatures are rejected." +
                               " Malformed {0} - xor {1} at {2}".format(
                               certType, hex(xor), pos)] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations_long)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throught
    sanity_test = ('sanity', conversations['sanity'])
    ordered_tests = chain([sanity_test],
                          filter(lambda x: x[0] != 'sanity',
                                 conversations.items()),
                          islice(conversations_long.items(), num_limit),
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

    print("Test to verify that server properly accepts or refuses")
    print("ECDSA signatures in TLS1.3; SHA224 and SHA1 signatures are always")
    print("refused, Other signatures are accepted or refused accordingly to")
    print("the key provided.\n")
    print("Test should be run three times, once each with P-256, P-384 and")
    print("P-521 client certificate.\n")
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
