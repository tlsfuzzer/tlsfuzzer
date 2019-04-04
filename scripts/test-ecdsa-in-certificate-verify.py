# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test for ECDSA support in Certificate Verify"""

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain, islice

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
        ECPointFormat, AlertLevel, AlertDescription
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import RSA_SIG_ALL, ECDSA_SIG_ALL


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
    print(" -k file.pem    file with private key for client")
    print(" -c file.pem    file with certificate for client")
    print(" --help         this message")


def main():
    """check if obsolete signature algorithm is rejected by server"""
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    private_key = None
    cert = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:k:c:", ["help"])
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
           SignatureAlgorithmsExtension().create(ECDSA_SIG_ALL + RSA_SIG_ALL),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL + RSA_SIG_ALL),
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

    # force MD5 signature on CertificateVerify
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(ECDSA_SIG_ALL + RSA_SIG_ALL),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL + RSA_SIG_ALL),
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
                                                     msg_alg=sig_type
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

    for h_alg in ["sha512", "sha384", "sha256", "sha224", "sha1"]:
        for real_h_alg in ["sha512", "sha384", "sha256", "sha224", "sha1"]:
            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {ExtensionType.signature_algorithms :
                   SignatureAlgorithmsExtension().create(ECDSA_SIG_ALL +
                                                         RSA_SIG_ALL),
                   ExtensionType.signature_algorithms_cert :
                   SignatureAlgorithmsCertExtension().create(ECDSA_SIG_ALL +
                                                             RSA_SIG_ALL),
                   ExtensionType.supported_groups :
                   SupportedGroupsExtension().create([
                       GroupName.secp256r1, GroupName.secp384r1,
                       GroupName.secp521r1]),
                   ExtensionType.ec_point_formats :
                   ECPointFormatsExtension().create([
                       ECPointFormat.uncompressed])}
            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       extensions=ext))
            node = node.add_child(ExpectServerHello(version=(3, 3)))
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectServerKeyExchange())
            node = node.add_child(ExpectCertificateRequest())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(CertificateGenerator(X509CertChain([cert])))
            node = node.add_child(ClientKeyExchangeGenerator())
            alg = (getattr(HashAlgorithm, h_alg), SignatureAlgorithm.ecdsa)
            real_alg = (getattr(HashAlgorithm, real_h_alg),
                        SignatureAlgorithm.ecdsa)
            if alg == real_alg:
                node = node.add_child(CertificateVerifyGenerator(
                    private_key,
                    msg_alg=alg,
                    sig_alg=real_alg))
                node = node.add_child(ChangeCipherSpecGenerator())
                node = node.add_child(FinishedGenerator())
                node = node.add_child(ExpectChangeCipherSpec())
                node = node.add_child(ExpectFinished())
                node = node.add_child(ApplicationDataGenerator(
                    b"GET / HTTP/1.0\n\n"))
                node = node.add_child(ExpectApplicationData())
                node = node.add_child(AlertGenerator(
                    AlertDescription.close_notify))
                node = node.add_child(ExpectClose())
                node.next_sibling = ExpectAlert()
                node.next_sibling.add_child(ExpectClose())

                conversations["make {0}+ecdsa signature in CertificateVerify"
                              .format(h_alg)] = conversation
            else:
                node = node.add_child(TCPBufferingEnable())
                node = node.add_child(CertificateVerifyGenerator(
                    private_key,
                    msg_alg=alg,
                    sig_alg=real_alg))
                node = node.add_child(ChangeCipherSpecGenerator())
                node = node.add_child(FinishedGenerator())
                node = node.add_child(TCPBufferingDisable())
                node = node.add_child(TCPBufferingFlush())
                node = node.add_child(ExpectAlert(
                    AlertLevel.fatal,
                    AlertDescription.decrypt_error))
                node = node.add_child(ExpectClose())
                conversations["make {0}+ecdsa signature, advertise it as "
                              "{1}+ecdsa in CertificateVerify"
                              .format(h_alg, real_h_alg)] = conversation

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

    print("Test support for ECDSA signatures in CertificateVerify\n")
    print("Version: {0}".format(version))

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
