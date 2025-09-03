# Author: Hubert Kario, (c) 2021
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test for EdDSA support in Certificate Verify"""

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain, islice
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, \
        AlertGenerator, TCPBufferingEnable, TCPBufferingDisable, \
        TCPBufferingFlush
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData, ExpectServerKeyExchange
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension, SupportedGroupsExtension, \
        ECPointFormatsExtension
from tlslite.constants import CipherSuite, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType, GroupName, \
        ECPointFormat, AlertLevel, AlertDescription, SignatureScheme
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import RSA_SIG_ALL, ECDSA_SIG_ALL, EDDSA_SIG_ALL


version = 3


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(10)")
    print("                (excluding \"sanity\" tests)")
    print(" -k file.pem    file with private key for client")
    print(" -c file.pem    file with certificate for client")
    print(" --help         this message")


def main():
    """Check if EdDSA signatures are handled correctly."""
    host = "localhost"
    port = 4433
    num_limit = 200
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    private_key = None
    cert = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:k:c:", ["help"])
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
        elif opt == '--help':
            help_msg()
            sys.exit(0)
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

    if not private_key:
        raise ValueError("Specify private key file using -k")
    if not cert:
        raise ValueError("Specify certificate file using -c")

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    # sanity check for Client Certificates
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.supported_groups :
           SupportedGroupsExtension().create([
               GroupName.secp256r1, GroupName.secp384r1, GroupName.secp521r1]),
           ExtensionType.ec_point_formats :
           ECPointFormatsExtension().create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
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
    node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertDescription.close_notify))
    node = node.add_child(ExpectClose())
    node.next_sibling = ExpectAlert()
    node.next_sibling.add_child(ExpectClose())

    conversations["sanity"] = conversation

    real_sig = getattr(SignatureScheme, private_key.key_type.lower())

    # force MD5 signature on CertificateVerify
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.supported_groups :
           SupportedGroupsExtension().create([
               GroupName.secp256r1, GroupName.secp384r1, GroupName.secp521r1]),
           ExtensionType.ec_point_formats :
           ECPointFormatsExtension().create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(TCPBufferingEnable())
    sig_type = (HashAlgorithm.md5, SignatureAlgorithm.ecdsa)
    node = node.add_child(CertificateVerifyGenerator(private_key,
                                                     msg_alg=sig_type,
                                                     sig_alg=real_sig,
                                                     ))
    # the other side can close connection right away, add options to handle it
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    # we expect closure or Alert and then closure of socket
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node.add_child(ExpectClose())

    conversations["md5+ecdsa forced"] = conversation

    # force sha512+ecdsa signature on CertificateVerify
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.supported_groups :
           SupportedGroupsExtension().create([
               GroupName.secp256r1, GroupName.secp384r1, GroupName.secp521r1]),
           ExtensionType.ec_point_formats :
           ECPointFormatsExtension().create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(TCPBufferingEnable())
    sig_type = (HashAlgorithm.sha512, SignatureAlgorithm.ecdsa)
    node = node.add_child(CertificateVerifyGenerator(private_key,
                                                     msg_alg=sig_type,
                                                     sig_alg=real_sig,
                                                     ))
    # the other side can close connection right away, add options to handle it
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    # we expect closure or Alert and then closure of socket
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node.add_child(ExpectClose())

    conversations["sha512+ecdsa forced"] = conversation

    if cert.certAlg == "Ed25519":
        sig_type = SignatureScheme.ed448
        real_sig = SignatureScheme.ed25519
    else:
        assert cert.certAlg == "Ed448"
        sig_type = SignatureScheme.ed25519
        real_sig = SignatureScheme.ed448

    # force wrong EdDSA signature with an EdDSA key
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.supported_groups :
           SupportedGroupsExtension().create([
               GroupName.secp256r1, GroupName.secp384r1, GroupName.secp521r1]),
           ExtensionType.ec_point_formats :
           ECPointFormatsExtension().create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(CertificateVerifyGenerator(private_key,
                                                     msg_alg=sig_type,
                                                     sig_alg=real_sig
                                                     ))
    # the other side can close connection right away, add options to handle it
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    # we expect closure or Alert and then closure of socket
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node.add_child(ExpectClose())

    conversations["advertise {0} sig as {1}".format(
        SignatureScheme.toRepr(real_sig),
        SignatureScheme.toRepr(sig_type))] = conversation

    # empty signature
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(
               ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
           ExtensionType.supported_groups :
           SupportedGroupsExtension().create([
               GroupName.secp256r1, GroupName.secp384r1, GroupName.secp521r1]),
           ExtensionType.ec_point_formats :
           ECPointFormatsExtension().create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(CertificateVerifyGenerator(private_key,
                                                     signature=bytearray(0)))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decrypt_error))
    node.add_child(ExpectClose())

    conversations["empty signature"] = conversation

    # malformed signatures
    if private_key.key_type == "Ed25519":
        siglen = 64
    else:
        assert private_key.key_type == "Ed448"
        siglen = 114

    for pos in range(siglen):
        for xor in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:

            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {ExtensionType.signature_algorithms :
                   SignatureAlgorithmsExtension().create(
                       ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
                   ExtensionType.signature_algorithms_cert :
                   SignatureAlgorithmsCertExtension().create(
                       ECDSA_SIG_ALL + RSA_SIG_ALL + EDDSA_SIG_ALL),
                   ExtensionType.supported_groups :
                   SupportedGroupsExtension().create([
                       GroupName.secp256r1, GroupName.secp384r1, GroupName.secp521r1]),
                   ExtensionType.ec_point_formats :
                   ECPointFormatsExtension().create([ECPointFormat.uncompressed])}
            node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
            node = node.add_child(ExpectServerHello(version=(3, 3)))
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectServerKeyExchange())
            node = node.add_child(ExpectCertificateRequest())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(TCPBufferingEnable())
            node = node.add_child(CertificateGenerator(X509CertChain([cert])))
            node = node.add_child(ClientKeyExchangeGenerator())
            node = node.add_child(CertificateVerifyGenerator(
                private_key,
                padding_xors={pos: xor}))
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(TCPBufferingDisable())
            node = node.add_child(TCPBufferingFlush())
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.decrypt_error))
            node.add_child(ExpectClose())

            conversations["fuzzed, pos: {0}, xor with {1}".format(
                pos, xor)] = conversation


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
    # to verify that server was running and kept running throught
    sanity_tests = [('sanity', conversations['sanity'])]
    run_sanity = True
    if run_only:
        if len(run_only) == 1 and 'sanity' in run_only:
            run_sanity = False
            regular_tests = sanity_tests
        else:
            if not 'sanity' in run_only:
                run_sanity = False
            regular_tests = [(k, v) for k, v in conversations.items() if
                             k in run_only and (k != 'sanity')]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    if run_sanity:
        ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)
    else:
        ordered_tests = sampled_tests

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

    print("Test support for EdDSA signatures in CertificateVerify\n")
    print("You should run this script twice, once with Ed25519 certificate")
    print("and once with Ed448 certificate (if server supports both)\n")

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    if run_sanity:
        print("TOTAL: {0}".format(len(sampled_tests) + 2 * len(sanity_tests)))
    else:
        print("TOTAL: {0}".format(len(sampled_tests)))
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
