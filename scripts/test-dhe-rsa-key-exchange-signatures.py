# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Hash algorithms testing in DHE_RSA ciphers"""

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectServerKeyExchange, \
        ExpectApplicationData
from tlslite.extensions import SignatureAlgorithmsExtension

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, HashAlgorithm, SignatureAlgorithm

def main():
    """Test if server supports all common hash algorithms in DHE_RSA kex"""
    conversations = {}

    for cipher in [CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256]:
        for hash_alg in ["sha1", "sha224", "sha256", "sha384", "sha512"]:
            conversation = Connect("localhost", 4433)
            node = conversation
            ciphers = [cipher]
            sig_algs = [(getattr(HashAlgorithm, hash_alg), SignatureAlgorithm.rsa)]
            ext = SignatureAlgorithmsExtension().create(sig_algs)
            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       extensions={ExtensionType.
                                                           renegotiation_info:None,
                                                           ExtensionType.
                                                           signature_algorithms:
                                                           ext}))
            node = node.add_child(ExpectServerHello(version=(3, 3),
                                                    extensions={ExtensionType.
                                                             renegotiation_info:None}))
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=sig_algs))
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(ClientKeyExchangeGenerator())
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

            conversations[CipherSuite.ietfNames[cipher] + " " + hash_alg
                          + " signature"] = conversation

    good = 0
    bad = 0

    for conversation_name, conversation in conversations.items():
        print("{0} ...".format(conversation_name))

        runner = Runner(conversation)

        res = True
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            print("")
            res = False

        if res:
            good+=1
            print("OK\n")
        else:
            bad+=1

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
