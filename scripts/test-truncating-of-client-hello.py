# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ResetHandshakeHashes, SetMaxRecordSize, pad_handshake
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType
from tlslite.extensions import TLSExtension

def main():

    #
    # Test if client hello with garbage at the end gets rejected
    #

    conversations = {}

    # test if server doesn't interpret extensions past extensions length
    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(pad_handshake(ClientHelloGenerator(ciphers,
                                               extensions={}),
                                        # empty renegotiation info
                                        pad=bytearray(b'\xff\x01\x00\x01\x00')))
    # responding to a malformed client hello is not correct, but tested below
    node = node.add_child(ExpectServerHello(extensions={}))
    node.next_sibling = ExpectAlert()
    node.next_sibling.next_sibling = ExpectClose()

    conversations["extension past extensions"] = conversation


    for name, pad_len, pad_byte in [
                                ("small pad", 1, 0),
                                ("small pad", 2, 0),
                                ("small pad", 3, 0),
                                ("small pad", 1, 0xff),
                                ("small pad", 2, 0xff),
                                ("small pad", 3, 0xff),
                                ("medium pad", 256, 0),
                                ("big pad", 4096, 0),
                                ("huge pad", 2**16, 0),
                                ("small truncate", -1, 0),
                                ("small truncate", -2, 0),
                                ("small truncate", -3, 0),
                                ("small truncate", -4, 0),
                                ("small truncate", -5, 0),
                                ("small truncate", -6, 0),
                                # 7 bytes truncates whole 'extensions' creating
                                # a valid message
                                #("small truncate", -7, 0),
                                ("hello truncate", -8, 0),
                                ("hello truncate", -9, 0),
                                ("hello truncate", -10, 0),
                                ("hello truncate", -11, 0),
                                ("hello truncate", -12, 0),
                                ("hello truncate", -13, 0),
                                ]:

        conversation = Connect("localhost", 4433)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        node = node.add_child(pad_handshake(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info: None}),
                                            pad_len, pad_byte))
        # we expect Alert and Close or just Close
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node.add_child(ExpectClose())

        if "pad" in name:
            conversations[name + ": " + str(pad_len) + " of \"" + str(pad_byte) +
                          "\" byte padding"] = conversation
        else:
            conversations[name + ": " + str(-pad_len) +
                          " of bytes truncated"] = conversation

    # run the conversation
    good = 0
    bad = 0

    for conversation_name in conversations:
        conversation = conversations[conversation_name]

        print(str(conversation_name) + "...\n")

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
