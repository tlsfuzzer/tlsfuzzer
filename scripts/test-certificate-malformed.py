# Author: Hubert Kario, (c) 2016
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
        FinishedGenerator, ApplicationDataGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, \
        AlertGenerator, pad_handshake, TCPBufferingEnable, \
        TCPBufferingDisable, TCPBufferingFlush, truncate_handshake, \
        fuzz_message, RawMessageGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension
from tlslite.constants import CipherSuite, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType, AlertLevel, \
        AlertDescription, ContentType
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlsfuzzer.helpers import RSA_SIG_ALL


def natural_sort_keys(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(_nsre, s)]


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -k file.pem    file with private key for client")
    print(" -c file.pem    file with certificate for client")
    print(" --help         this message")



def main():
    """Check if malformed messages related to client certs are rejected."""
    conversations = {}
    host = "localhost"
    port = 4433
    run_exclude = set()
    private_key = None
    cert = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:k:c:", ["help"])
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

    # sanity check for Client Certificates
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1', 'md5']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
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

    # sanity check for no client certificate
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1', 'md5']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator(None))
    node = node.add_child(ClientKeyExchangeGenerator())
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

    conversations["sanity - no client cert"] = conversation

    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {ExtensionType.signature_algorithms :
               SignatureAlgorithmsExtension().create([
                 (getattr(HashAlgorithm, x),
                  SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                    'sha224', 'sha1', 'md5']]),
               ExtensionType.signature_algorithms_cert :
               SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(fuzz_message(CertificateGenerator(X509CertChain([cert])),
                                           xors={7: i}))
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(CertificateVerifyGenerator(private_key))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decode_error))
        node = node.add_child(ExpectClose())

        conversations["fuzz certificates length with {0}".format(i)] = conversation

    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {ExtensionType.signature_algorithms :
               SignatureAlgorithmsExtension().create([
                 (getattr(HashAlgorithm, x),
                  SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                    'sha224', 'sha1', 'md5']]),
               ExtensionType.signature_algorithms_cert :
               SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(fuzz_message(CertificateGenerator(X509CertChain([cert])),
                                           xors={9: i}))
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(CertificateVerifyGenerator(private_key))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decode_error))
        node = node.add_child(ExpectClose())

        conversations["fuzz first certificate length with {0}".format(i)] = conversation

    # fuzz empty certificates message
    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {ExtensionType.signature_algorithms :
               SignatureAlgorithmsExtension().create([
                 (getattr(HashAlgorithm, x),
                  SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                    'sha224', 'sha1', 'md5']]),
               ExtensionType.signature_algorithms_cert :
               SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(fuzz_message(CertificateGenerator(None),
                                           xors={-1:i}))
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decode_error))
        node = node.add_child(ExpectClose())

        conversations["fuzz empty certificates length - {0}"
                      .format(i)] = conversation

    # sanity check for no client certificate
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1', 'md5']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    # technically, it's an invalid encoding as the items are defined as
    # <1..2^24-1>, but some implementations, like OpenSSL, accept it;
    # don't be too precise for now
    msg = CertificateGenerator()
    msg = pad_handshake(msg, 3)
    msg = fuzz_message(msg, substitutions={-4:3})
    node = node.add_child(msg)
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectChangeCipherSpec())
    # if the implementation is proper, it will reject the message
    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.decode_error)
    node.next_sibling.add_child(ExpectClose())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertDescription.close_notify))
    node = node.add_child(ExpectClose())
    node.next_sibling = ExpectAlert()
    node.next_sibling.add_child(ExpectClose())

    conversations["sanity - empty client cert"] = conversation

    # fuzz empty certificate message
    for i, j, k in ((i, j, k) for i in range(8)
                    for j in range(8) for k in range(6)):
        if i == 3 and j == 0 or k == 0 and i == 0:
            continue
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {ExtensionType.signature_algorithms :
               SignatureAlgorithmsExtension().create([
                 (getattr(HashAlgorithm, x),
                  SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                    'sha224', 'sha1', 'md5']]),
               ExtensionType.signature_algorithms_cert :
               SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        msg = CertificateGenerator()
        msg = pad_handshake(msg, k)
        subs = {6: i}
        if k >= 3:
            subs[9] = j
        msg = fuzz_message(msg, substitutions=subs)
        node = node.add_child(msg)
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decode_error))
        node = node.add_child(ExpectClose())

        conversations["fuzz empty certificate - overall {2}, certs {0}, cert {1}"
                      .format(i, j, k + 3)] = conversation

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

    print("Malformed Certificate test version 1\n")
    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
