# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Example MAC value fuzzer"""

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        fuzz_padding, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectApplicationData

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription

def main():
    """check if zero-filled padding is accepted by server in SSLv3"""
    conversations = {}

    # zero-fill SSLv3 padding
    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 0)))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    text = b"GET / HTTP/1.0\nX-bad: aaaa\n\n"
    hmac_tag_length = 20
    block_size = 16
    # make sure that padding has full block to work with
    assert (len(text) + hmac_tag_length) % block_size == 0
    node = node.add_child(fuzz_padding(ApplicationDataGenerator(text),
                                       # set all bytes of pad to b'\x00'
                                       substitutions={x:0 for x
                                                      in range(0, 15)}))
    node = node.add_child(ExpectApplicationData())
    # BEAST 1/n-1 splitting
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())

    conversations["zero-filled padding in SSLv3"] = \
            conversation

    # run the conversation
    good = 0
    bad = 0

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
