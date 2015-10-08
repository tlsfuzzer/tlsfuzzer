# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        fuzz_message
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription

def main():

    #
    # check if incorrect Finished hash is rejected by server
    #

    conversations = {}

    for pos, val in [
                     (-1, 0x01),
                     (-1, 0xff),
                     (-2, 0x01),
                     (-2, 0xff),
                     (-6, 0x01),
                     (-6, 0xff),
                     (-12, 0x01),
                     (-12, 0xff),
                     # Finished messages have just 12 octets of data so
                     # by going to -13 we would be modifying the length
                     # of the message
                     ]:
        conversation = Connect("localhost", 4433)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(fuzz_message(FinishedGenerator(), xors={pos:val}))
        #node = node.add_child(ExpectChangeCipherSpec())
        #node = node.add_child(ExpectFinished())
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())

        conversations["XOR position " + str(pos) + " with " + str(hex(val))] = \
                conversation

    # run the conversation
    good = 0
    bad = 0

    for conversation_name in conversations:
        conversation = conversations[conversation_name]

        print(conversation_name + "...")

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
