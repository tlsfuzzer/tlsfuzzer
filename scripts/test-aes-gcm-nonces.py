# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Check if AES-GCM nonces used by server are secure"""

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        CollectNonces
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectApplicationData

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType
from tlslite.utils.cryptomath import bytesToNumber

def main():
    """Check if nonces used by server are monotonically increasing"""
    conversations = {}
    nonces = []

    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(CollectNonces(nonces))
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["aes-128-gcm cipher"] = conversation

    nonces256 = []

    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(CollectNonces(nonces256))
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["aes-256-gcm cipher"] = conversation


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
            good += 1
            print("OK\n")
        else:
            bad += 1

    print("aes-128-gcm Nonce monotonicity...")
    if len(nonces) < 2:
        print("Not enough nonces collected, FAIL")
        bad += 1
    else:
        if bytesToNumber(nonces[0]) == bytesToNumber(nonces[1]):
            print("reused nonce! Security vulnerability!")
            bad += 1
        elif bytesToNumber(nonces[0]) + 1 != bytesToNumber(nonces[1]):
            print("nonce not monotonically increasing, FAIL")
            bad += 1
        else:
            print("OK\n")
            good += 1

    print("aes-256-gcm Nonce monotonicity...")
    if len(nonces256) < 2:
        print("Not enough nonces collected, FAIL")
        bad += 1
    else:
        if bytesToNumber(nonces256[0]) == bytesToNumber(nonces256[1]):
            print("reused nonce! Security vulnerability!")
            bad += 1
        elif bytesToNumber(nonces256[0]) + 1 != bytesToNumber(nonces256[1]):
            print("nonce not monotonically increasing, FAIL")
            bad += 1
        else:
            print("OK\n")
            good += 1


    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
