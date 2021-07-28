# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, \
        TCPBufferingEnable, TCPBufferingDisable, TCPBufferingFlush
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange, ExpectCertificateRequest
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import sig_algs_to_ids, RSA_SIG_ALL

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, HashAlgorithm, SignatureAlgorithm, SignatureScheme
from tlslite.extensions import SignatureAlgorithmsExtension, TLSExtension, \
        SignatureAlgorithmsCertExtension
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.utils.cryptomath import numBytes


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
    print(" -n num         run 'num' or all(if 0) long fuzzing tests instead of default(15)")
    print("                (excluding \"sanity\" and other short tests)")
    print(" -s sigalgs     signature algorithms expected in")
    print("                CertificateRequest. Format is either the new")
    print("                signature scheme (rsa_pss_rsae_sha256) or old one")
    print("                (sha512+rsa) separated by spaces")
    print(" -k keyfile     file with private key")
    print(" -c certfile    file with certificate of client")
    print(" --illegpar     expect illegal_parameter instead of decrypt_error")
    print("                alert for mismatched signatures. Should be used")
    print("                with TLS implementations that do inspect")
    print("                certificiate type and check if it is compatible")
    print("                with given CertificateVerify signature before")
    print("                passing both of them to verification.")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = 15
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    private_key = None
    cert = None
    exp_illeg_param = False

    sigalgs = [SignatureScheme.ed25519,
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
               (HashAlgorithm.sha512, SignatureAlgorithm.rsa),
               (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
               (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
               (HashAlgorithm.sha224, SignatureAlgorithm.rsa),
               (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:k:c:s:", ["help", "illegpar"])
    for opt, arg in opts:
        if opt == '-k':
            text_key = open(arg, 'rb').read()
            if sys.version_info[0] >= 3:
                text_key = str(text_key, 'utf-8')
            private_key = parsePEMKey(text_key, private=True,
                                      implementations=["python"])
        elif opt == '-c':
            text_cert = open(arg, 'rb').read()
            if sys.version_info[0] >= 3:
                text_cert = str(text_cert, 'utf-8')
            cert = X509()
            cert.parse(text_cert)
        elif opt == '-s':
            sigalgs = sig_algs_to_ids(arg)
        elif opt == '-h':
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
        elif opt == '--illegpar':
            exp_illeg_param = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if not private_key:
        raise ValueError("Specify private key file using -k")
    if not cert:
        raise ValueError("Specify certificate file using -c")

    conversations = {}
    conversations_long = {}

    conversation = Connect(host, port)
    node = conversation
    sigs = [SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512,
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512,
            (HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha224, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    algs = [SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512,
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512
            ]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=algs))
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(CertificateVerifyGenerator(private_key))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity"] = conversation

    # check if RSA-PSS can be the only one
    conversation = Connect(host, port)
    node = conversation
    sigs = [SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512,
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512
            ]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(CertificateVerifyGenerator(private_key))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["RSA-PSS only"] = conversation

    # check if algs in CertificateRequest are expected
    conversation = Connect(host, port)
    node = conversation
    sigs = [SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512,
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512
            ]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest(sig_algs=sigalgs))
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(CertificateVerifyGenerator(private_key))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["check CertificateRequest sigalgs"] = conversation

    if cert.certAlg == "rsa":
        schemes = [SignatureScheme.rsa_pss_rsae_sha256,
                   SignatureScheme.rsa_pss_rsae_sha384,
                   SignatureScheme.rsa_pss_rsae_sha512]
        invalid_schemes = [SignatureScheme.rsa_pss_pss_sha256,
                           SignatureScheme.rsa_pss_pss_sha384,
                           SignatureScheme.rsa_pss_pss_sha512]
    else:
        schemes = [SignatureScheme.rsa_pss_pss_sha256,
                   SignatureScheme.rsa_pss_pss_sha384,
                   SignatureScheme.rsa_pss_pss_sha512]
        invalid_schemes = [SignatureScheme.rsa_pss_rsae_sha256,
                           SignatureScheme.rsa_pss_rsae_sha384,
                           SignatureScheme.rsa_pss_rsae_sha512]

    for scheme in invalid_schemes:
        conversation = Connect(host, port)
        node = conversation
        sigs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_rsae_sha512,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.rsa_pss_pss_sha384,
                SignatureScheme.rsa_pss_pss_sha512
                ]
        ext = {ExtensionType.signature_algorithms:
                SignatureAlgorithmsExtension().create(sigs),
               ExtensionType.signature_algorithms_cert:
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(CertificateVerifyGenerator(private_key,
                                                         msg_alg=scheme))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        if exp_illeg_param:
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.illegal_parameter))
        else:
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.decrypt_error))
        node = node.add_child(ExpectClose())
        conversations["{0} in CertificateVerify with {1} key"
                      .format(SignatureScheme.toRepr(scheme), cert.certAlg)] = conversation

    # check if CertificateVerify can be signed with any algorithm
    for scheme in schemes:
        conversation = Connect(host, port)
        node = conversation
        sigs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_rsae_sha512,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.rsa_pss_pss_sha384,
                SignatureScheme.rsa_pss_pss_sha512
                ]
        ext = {ExtensionType.signature_algorithms:
                SignatureAlgorithmsExtension().create(sigs),
               ExtensionType.signature_algorithms_cert:
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(CertificateVerifyGenerator(private_key,
                                                         msg_alg=scheme))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())
        conversations["{0} in CertificateVerify with {1} key"
                      .format(SignatureScheme.toRepr(scheme), cert.certAlg)] = conversation

    # check if CertificateVerify with wrong salt size is rejected
    for scheme in schemes:
        conversation = Connect(host, port)
        node = conversation
        sigs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_rsae_sha512,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.rsa_pss_pss_sha384,
                SignatureScheme.rsa_pss_pss_sha512
                ]
        ext = {ExtensionType.signature_algorithms:
                SignatureAlgorithmsExtension().create(sigs),
               ExtensionType.signature_algorithms_cert:
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(CertificateVerifyGenerator(private_key,
                                                         msg_alg=scheme,
                                                         rsa_pss_salt_len=20))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decrypt_error))
        node = node.add_child(ExpectClose())
        conversations["{0} in CertificateVerify with incorrect salt len"
                      .format(SignatureScheme.toRepr(scheme))] = conversation

    # check if CertificateVerify with wrong salt size is rejected
    for pos in range(numBytes(private_key.n)):
        for xor in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
            conversation = Connect(host, port)
            node = conversation
            sigs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_rsae_sha384,
                    SignatureScheme.rsa_pss_rsae_sha512,
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.rsa_pss_pss_sha384,
                    SignatureScheme.rsa_pss_pss_sha512
                    ]
            ext = {ExtensionType.signature_algorithms:
                    SignatureAlgorithmsExtension().create(sigs),
                   ExtensionType.signature_algorithms_cert:
                    SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
            ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       extensions=ext))
            node = node.add_child(ExpectServerHello(version=(3, 3)))
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectServerKeyExchange())
            node = node.add_child(ExpectCertificateRequest())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(TCPBufferingEnable())
            node = node.add_child(CertificateGenerator(X509CertChain([cert])))
            node = node.add_child(ClientKeyExchangeGenerator())
            if cert.certAlg == "rsa":
                scheme = SignatureScheme.rsa_pss_rsae_sha256
            else:
                scheme = SignatureScheme.rsa_pss_pss_sha256
            node = node.add_child(CertificateVerifyGenerator(private_key,
                                                             msg_alg=scheme,
                                                             padding_xors={pos:xor}))
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(TCPBufferingDisable())
            node = node.add_child(TCPBufferingFlush())
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.decrypt_error))
            node = node.add_child(ExpectClose())
            conversations_long["malformed {0} in CertificateVerify - xor {1} at {2}"
                               .format(cert.certAlg, hex(xor), pos)] = conversation

    if cert.certAlg == "rsa-pss":
        conversation = Connect(host, port)
        node = conversation
        sigs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_rsae_sha512,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.rsa_pss_pss_sha384,
                SignatureScheme.rsa_pss_pss_sha512
                ]
        ext = {ExtensionType.signature_algorithms:
                SignatureAlgorithmsExtension().create(sigs),
               ExtensionType.signature_algorithms_cert:
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(CertificateGenerator(X509CertChain([cert])))
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(CertificateVerifyGenerator(private_key,
                                                         msg_alg=SignatureScheme.rsa_pkcs1_sha256,
                                                         sig_alg=SignatureScheme.rsa_pkcs1_sha256))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        if exp_illeg_param:
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.illegal_parameter))
        else:
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.decrypt_error))
        node = node.add_child(ExpectClose())
        conversations["rsa_pkcs1_sha256 signature in CertificateVerify "
                      "with rsa-pss key"] = conversation

    conversation = Connect(host, port)
    node = conversation
    sigs = [SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512,
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512
            ]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    if cert.certAlg == "rsa":
        sig_alg = SignatureScheme.rsa_pss_rsae_sha256
    else:
        sig_alg = SignatureScheme.rsa_pss_pss_sha256
    node = node.add_child(CertificateVerifyGenerator(private_key,
                                                     msg_alg=SignatureScheme.rsa_pkcs1_sha256,
                                                     sig_alg=sig_alg))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    if exp_illeg_param and cert.certAlg != "rsa":
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.illegal_parameter))
    else:
        # with rsaEncryption key in certificate, there is nothing the TLS
        # layer can inspect to decide if the signature is valid before actually
        # verifying it
        # for rsassa-pss, rsa_pkcs1 signature is illegal
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decrypt_error))
    node = node.add_child(ExpectClose())
    conversations["{0} signature in CertificateVerify with rsa_pkcs1_sha256 id"
                  .format(SignatureScheme.toRepr(sig_alg))] = conversation

    conversation = Connect(host, port)
    node = conversation
    sigs = [SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512,
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512
            ]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    if cert.certAlg == "rsa":
        scheme = SignatureScheme.rsa_pss_rsae_sha256
    else:
        scheme = SignatureScheme.rsa_pss_pss_sha256
    sig = bytearray(b'\xfa\xbc\x0f\x4c')
    node = node.add_child(CertificateVerifyGenerator(private_key,
                                                     msg_alg=scheme,
                                                     signature=sig))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decrypt_error))
    node = node.add_child(ExpectClose())
    conversations["short sig with {0} id".format(
                  SignatureScheme.toRepr(scheme))] = conversation

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
        if num_limit > len(run_only):
            num_limit = len(run_only)
        long_tests = [(k, v) for k, v in conversations_long.items() if k in run_only]
        short_tests = [(k, v) for k, v in conversations.items() if (k != 'sanity') and k in run_only]
    else:
        long_tests = [(k, v) for k, v in conversations_long.items() if
                        k not in run_exclude]
        short_tests = [(k, v) for k, v in conversations.items() if
                        (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(long_tests, min(num_limit, len(long_tests)))
    ordered_tests = chain(sanity_tests, short_tests, sampled_tests, sanity_tests)

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

    print("Check handling of rsa-pss signatures")
    print("Test should be run twice, once with certificate with")
    print("rsaEncryption key and once with certificate with rsassa-pss key.")
    print("Implementations that inspect certificate type and check signature")
    print("scheme in CertificateVerify before verifying signature need to use")
    print("--illegpar option")

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
