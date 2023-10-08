# Author: Simo Sorce, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test with CertificateVerify"""

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain
from random import sample

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
from tlsfuzzer.helpers import key_share_ext_gen, sig_algs_to_ids, RSA_SIG_ALL
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


version = 8


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
    print(" -n num         run 'num' or all(if 0) long fuzzing tests instead of default(10)")
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


def initiate_connect(host, port):
    """Code reuse"""
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

    return (conversation, node)

def main():
    """Check that server propoerly rejects pkcs1 signatures in TLS 1.3"""
    hostname = "localhost"
    port = 4433
    num_limit = 10
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    cert = None
    private_key = None

    # algorithms to expect from server in Certificate Request
    cr_sigalgs = [SignatureScheme.ed25519,
                  SignatureScheme.ed448,
                  SignatureScheme.ecdsa_secp521r1_sha512,
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
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_pss_sha384]

    hashalgs = hashes_to_list("sha256 sha384 sha512")

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:s:k:c:", ["help", "hash-order="])
    for opt, arg in opts:
        if opt == '-h':
            hostname = arg
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
    (conversation, node) = initiate_connect(hostname, port)

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
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
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

    for sigalg in RSA_SIG_ALL:
        # set if test should succeed or fail based on cert type,
        # advertisement and forbidden algorithms
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
        # also verify that pkcs1 signatures are unconditionally refused
        if sigalg in ((HashAlgorithm.md5, SignatureAlgorithm.rsa),
                      SignatureScheme.rsa_pkcs1_sha1,
                      SignatureScheme.rsa_pkcs1_sha224,
                      SignatureScheme.rsa_pkcs1_sha256,
                      SignatureScheme.rsa_pkcs1_sha384,
                      SignatureScheme.rsa_pkcs1_sha512):
            expectPass = False
        # also expect failure if an algorithm is not advertized
        if sigalg not in cr_sigalgs:
            expectPass = False

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

        conversations["check {0} signature {1}".format(
                      SignatureScheme.toStr(sigalg), result)] = conversation

    # verify that rsa-pss signatures with empty, too short or too long
    # salt fail
    msgalg = sigalg_select("rsa_pss", hashalgs, cr_sigalgs, certType)
    hash_name = SignatureScheme.getHash(SignatureScheme.toRepr(msgalg))
    digest_len = getattr(tlshashlib, hash_name)().digest_size
    for saltlen in (0, digest_len - 1, digest_len + 1):
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

        conversations["check signature with salt length {0}".format(
                      saltlen)] = conversation

    # verify that a rsa-pkcs1 signature in a rsa-pss ID envelope fails
    sigalg = sigalg_select("rsa_pkcs1", hashalgs)
    msgalg = sigalg_select("rsa_pss", hashalgs, cr_sigalgs, certType)
    
    (conversation, node) = initiate_connect(hostname, port)

    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(CertificateVerifyGenerator(
        private_key, sig_alg=sigalg, msg_alg=msgalg))
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectAlert(
        AlertLevel.fatal, AlertDescription.decrypt_error))
    node.add_child(ExpectClose())

    scheme = SignatureScheme.toRepr(sigalg)
    conversations["check pkcs1 signature with rsa-pss envelope fails"] = \
        conversation

    # verify that a rsa-pss signature with mismatched message hash fails
    msgalg = sigalg_select("rsa_pss", hashalgs, cr_sigalgs, certType)

    # choose a similar scheme with just a different hash, doesn't need to be
    # a server supported sigalg
    hash_name = SignatureScheme.getHash(SignatureScheme.toRepr(msgalg))
    _hashalgs = [x for x in hashalgs if x != hash_name]
    sigalg = sigalg_select("rsa_pss", _hashalgs, cert_type=certType)

    (conversation, node) = initiate_connect(hostname, port)

    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(CertificateVerifyGenerator(
        private_key, sig_alg=sigalg, msg_alg=msgalg))
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectAlert(
        AlertLevel.fatal, AlertDescription.decrypt_error))
    node.add_child(ExpectClose())

    conversations["check rsa-pss signature with mismatched hash fails"] = \
        conversation

    # verify that a rsa-pss signature with mismatched MGF1 hash fails
    sigalg = sigalg_select("rsa_pss", hashalgs, cr_sigalgs, certType)

    # choose a different hash to cause mismtach
    hash_name = SignatureScheme.getHash(SignatureScheme.toRepr(msgalg))
    mgf1_hash = [x for x in hashalgs if x != hash_name][0]

    (conversation, node) = initiate_connect(hostname, port)
    
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(CertificateVerifyGenerator(
        private_key, mgf1_hash=mgf1_hash, msg_alg=sigalg))
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectAlert(
        AlertLevel.fatal, AlertDescription.decrypt_error))
    node.add_child(ExpectClose())

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
            ext[ExtensionType.key_share] = key_share_ext_gen(groups)
            ext[ExtensionType.supported_versions] = \
                SupportedVersionsExtension().create([(3, 4), (3, 3)])
            ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
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
            conversations_long["check that fuzzed signatures are rejected." +
                               " Malformed {0} - xor {1} at {2}".format(
                               certType, hex(xor), pos)] = conversation


    # run the conversation
    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    if not num_limit:
        num_limit = len(conversations_long)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout

    sanity_tests = [('sanity', conversations['sanity'])]
    if run_only:
        short_tests = [(k, v) for k, v in conversations.items() if
                        (k != 'sanity') and k in run_only]
        long_tests = [(k, v) for k, v in conversations_long.items() if
                        k in run_only]
    else:
        short_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
        long_tests = [(k, v) for k, v in conversations_long.items() if
                        k not in run_exclude]
    sampled_tests = sample(long_tests, min(num_limit, len(long_tests)))
    ordered_tests = chain(sanity_tests, short_tests, sampled_tests, sanity_tests)

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

    print("Test to verify that server properly accepts or refuses")
    print("signatures in TLS1.3; PKCS1 signatures are always refused.")
    print("Other signatures are accepted or refused accordingly to")
    print("the certificate type provided ('rsa' vs 'rsa-pss').\n")

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + len(short_tests) + 2*len(sanity_tests)))
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
