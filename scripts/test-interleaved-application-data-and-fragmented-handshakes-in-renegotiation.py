# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ResetHandshakeHashes, split_message, FlushMessageList
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType

def main():

    #
    # Test interleaving of Application Data with handshake messages,
    # requires an HTTP-like server with support for client initiated
    # renegotiation
    #

    conversations = {}

    conver = Connect("localhost", 4433)
    node = conver
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
    fragment_list = []
    node = node.add_child(split_message(ClientHelloGenerator([CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA],
                                                             extensions={ExtensionType.renegotiation_info:None}),
                                        fragment_list, 30))
    # interleaved AppData
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0")))
    node = node.add_child(FlushMessageList(fragment_list))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["Application data inside Client Hello"] = conver

    conver = Connect("localhost", 4433)
    node = conver
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
                                                             extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    fragment_list = []
    node = node.add_child(split_message(ClientKeyExchangeGenerator(), fragment_list, 30))
    # interleaved AppData
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0")))
    node = node.add_child(FlushMessageList(fragment_list))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["Application data inside Client Key Exchange"] = conver

    # CCS is one byte, can't split it
    #conversations["Application data inside Change Cipher Spec"] = conver

    conver = Connect("localhost", 4433)
    node = conver
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
                                               extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    fragments = []
    node = node.add_child(split_message(FinishedGenerator(), fragments, 10))
    # interleaved AppData
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0")))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["Application data inside Finished"] = conver
    # run the conversation
    good = 0
    bad = 0

    for conver_name in conversations:
        conversation = conversations[conver_name]
        runner = Runner(conversation)
        print(conver_name + "...")

        res = True
        try:
            runner.run()
        except:
            print("\n")
            print("Error while processing")
            print(traceback.format_exc())
            res = False

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
