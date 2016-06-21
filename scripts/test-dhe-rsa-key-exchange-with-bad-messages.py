# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Test for DHE_RSA key exchange error handling"""

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        truncate_handshake, TCPBufferingEnable, TCPBufferingDisable, \
        TCPBufferingFlush, pad_handshake
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectServerKeyExchange, \
        ExpectApplicationData

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType

def main():
    """Test if server correctly handles malformed DHE_RSA CKE messages"""
    conversations = {}

    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={ExtensionType.
                                                   renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                     renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
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
    node = node.add_child(ExpectClose())

    conversations["sanity check DHE_RSA_AES_128"] = conversation

    # invalid dh_Yc value
    #for i in [2*1024, 4*1024, 8*1024, 16*1024]:
    for i in [8*1024]:
        conversation = Connect("localhost", 4433)
        node = conversation
        ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.
                                                       renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                         renegotiation_info:None}))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(dh_Yc=2**(i)))
        node = node.add_child(ChangeCipherSpecGenerator())
        #node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert())
        #node.next_sibling = ExpectClose()
        node.add_child(ExpectClose())

        conversations["invalid dh_Yc value - " + str(i) + "b"] = conversation

    # truncated dh_Yc value
    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={ExtensionType.
                                                   renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                     renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(truncate_handshake(ClientKeyExchangeGenerator(),
                                             1))
#    node = node.add_child(ExpectAlert(
#        description=AlertDescription.handshake_failure))
#    node = node.add_child(ExpectAlert(
#        description=AlertDescription.record_overflow))
    node = node.add_child(ExpectAlert())
#    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["truncated dh_Yc value"] = conversation

    # padded Client Key Exchange
    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={ExtensionType.
                                                   renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                     renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(pad_handshake(ClientKeyExchangeGenerator(),
                                             1))
    node = node.add_child(ExpectAlert())
#    node = node.add_child(
#            ExpectAlert(description=AlertDescription.record_overflow))
    # node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["padded Client Key Exchange"] = conversation

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

    print("Test version 1")
    print("Check if server properly verifies received Client Key Exchange")
    print("message. That the extra data (pad) at the end is noticed, that")
    print("too short message is rejected and a message with \"obviously\"")
    print("wrong client key share is rejected")

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
