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
    # Test if client hello with no valid cipher gets rejected
    #

    conversations = {}

    for name, ciphers in [
                          ("NULL_NULL cipher", [0x00]),
                          ("FORTEZZA", range(0x1c,0x1e)),
                          ("Unknown 0x0047", range(0x47, 0x60)),
                          ("EXPORT1024", range(0x60, 0x66)),
                          ("TLS_DHE_DSS_WITH_RC4_128_SHA", [0x66]),
                          ("Unknown 0x006e", range(0x6e, 0x80)),
                          ("GOST", range(0x80, 0x84)),
                          ("Unknown 0x00c6", range(0xc6, 0xff)),
                          ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", [0xff]),
                          ("Unknown 0x0100", range(0x0100, 0x1001)),
                          ("Unknown 0x2000", range(0x2000, 0x3001)),
                          ("Unknown 0x3000", range(0x3000, 0x4001)),
                          ("Unknown 0x4000", range(0x4000, 0x5001)),
                          ("Unknown 0x5000", range(0x5000, 0x6001)),
                          ("Unknown 0x6000", range(0x6000, 0x7001)),
                          ("Unknown 0x7000", range(0x7000, 0x8001)),
                          ("Unknown 0x8000", range(0x8000, 0x9001)),
                          ("Unknwon 0x9000", range(0x9000, 0xa001)),
                          ("Unknown 0xa000", range(0xa000, 0xb001)),
                          ("Unknown 0xb000", range(0xb000, 0xc001)),
                          ("Unknown 0xc0b0", range(0xc0b0, 0xd001)),
                          ("Unknown 0xd000", range(0xd000, 0xe001)),
                          ("Unknown 0xe000", range(0xe000, 0xf001)),
                          ("Unknown 0xf000", range(0xf000, 0xffff)),
                          ]:

        conversation = Connect("localhost", 4433)
        node = conversation

        node = node.add_child(ClientHelloGenerator(ciphers))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()

        conversations[name] = conversation

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
