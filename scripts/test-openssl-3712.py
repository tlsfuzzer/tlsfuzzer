# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ResetHandshakeHashes
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType

def main():

    #
    # Test interleaving of Application Data with handshake messages,
    # requires server to support client initiated renegotiation
    #

    conversation = Connect("localhost", 4433)
    node = conversation
    #ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
    #           CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ClientHelloGenerator([CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
                                               session_id=bytearray(0),
                                               extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"hello server!\n")))
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"hello server!\n")))
    #node = node.add_child(ExpectApplicationData(bytearray(b"hello client!\n")))
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node.next_sibling.next_sibling = ExpectApplicationData()

    # run the conversation
    good = 0
    bad = 0

    runner = Runner(conversation)

    res = True
    try:
        runner.run()
    except:
        print("Error while processing")
        print(traceback.format_exc())
        res = False

    if res:
        good+=1
    else:
        bad+=1

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
