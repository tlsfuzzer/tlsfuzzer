# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData

from tlslite.constants import CipherSuite

def main():

    conversation = Connect("localhost", 4433)
    node = conversation
    node = node.add_child(ClientHelloGenerator([CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectAlert())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(b"hello server!"))
    node = node.add_child(ExpectApplicationData(b"hello client!"))

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
