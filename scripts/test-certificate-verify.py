# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test for CVE-2015-7575 (SLOTH)"""

from __future__ import print_function
import traceback
import sys
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, \
        AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData
from tlslite.extensions import SignatureAlgorithmsExtension
from tlslite.constants import CipherSuite, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain

def main():
    """check if obsolete signature algorithm is rejected by server"""
    conversations = {}
    hostname = "localhost"
    port = 4433

    argv = sys.argv[1:]
    if len(argv) != 4:
        raise ValueError("You need to specify key (-k file.pem) and "
                         "certificate (-c file.pem)")
    opts, argv = getopt.getopt(argv, "k:c:")

    for opt, arg in opts:
        if opt == '-k':
            text_key = open(arg, 'rb').read()
            if sys.version_info[0] >= 3:
                text_key = str(text_key, 'utf-8')
            private_key = parsePEMKey(text_key, private=True)
        if opt == '-c':
            text_cert = open(arg, 'rb').read()
            if sys.version_info[0] >= 3:
                text_cert = str(text_cert, 'utf-8')
            cert = X509()
            cert.parse(text_cert)

    if not private_key:
        raise ValueError("Specify private key file using -k")
    if not cert:
        raise ValueError("Specify certificate file using -c")

    # sanity check for Client Certificates
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1', 'md5']])}
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

    conversations["Sanity check"] = conversation

    # force MD5 signature on CertificateVerify
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1', 'md5']])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(ClientKeyExchangeGenerator())
    sig_type = (HashAlgorithm.md5, SignatureAlgorithm.rsa)
    node = node.add_child(CertificateVerifyGenerator(private_key,
                                                     msg_alg=sig_type
                                                     ))
    # the other side can close connection right away, add options to handle it
    node.next_sibling = ExpectClose()
    node = node.add_child(ChangeCipherSpecGenerator())
    node.next_sibling = ExpectClose()
    node = node.add_child(FinishedGenerator())
    node.next_sibling = ExpectClose()
    # we expect closure or Alert and then closure of socket
    node = node.add_child(ExpectClose())
    node.next_sibling = ExpectAlert()
    node.next_sibling.add_child(ExpectClose())

    conversations["MD5 forced"] = conversation

    # run the conversation
    good = 0
    bad = 0

    print("MD5 CertificateVerify (CVE-2015-7575 aka SLOTH) test version 4")

    for conversation_name in conversations:
        conversation = conversations[conversation_name]

        print(conversation_name + "...")

        runner = Runner(conversation)

        res = True
        #because we don't want to abort the testing and we are reporting
        #the errors to the user, using a bare except is OK
        #pylint: disable=bare-except
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            res = False
        #pylint: enable=bare-except

        if res:
            good+=1
            print("OK")
        else:
            bad+=1

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
