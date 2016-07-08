# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Check handling of malformed ECDHE_RSA client key exchange messages"""

from __future__ import print_function
import traceback
import sys

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        fuzz_message, truncate_handshake, pad_handshake
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectServerKeyExchange, \
        ExpectApplicationData

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName, ECPointFormat
from tlslite.extensions import SupportedGroupsExtension, \
        ECPointFormatsExtension


def main():
    """Check handling of malformed ECDHE_RSA client key exchange messages"""
    conversations = {}

    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.supported_groups: SupportedGroupsExtension().
           create([GroupName.secp256r1, GroupName.secp384r1]),
           ExtensionType.ec_point_formats: ECPointFormatsExtension().
           create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.ec_point_formats: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
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

    conversations["sanity check ECDHE_RSA_AES_128"] = conversation

    # invalid ecdh_Yc value
    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.supported_groups: SupportedGroupsExtension().
           create([GroupName.secp256r1, GroupName.secp384r1]),
           ExtensionType.ec_point_formats: ECPointFormatsExtension().
           create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.ec_point_formats: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    # uncompressed EC points need to be self consistent, by changing
    # one coordinate without changing the other we create an invalid point
    node = node.add_child(fuzz_message(ClientKeyExchangeGenerator(),
                                       xors={-1:0xff}))
    node = node.add_child(ChangeCipherSpecGenerator())
    # node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectAlert())
    node = node.add_child(ExpectClose())

    conversations["invalid point (self-inconsistent)"] = conversation

    # truncated Client Key Exchange
    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.supported_groups: SupportedGroupsExtension().
           create([GroupName.secp256r1, GroupName.secp384r1]),
           ExtensionType.ec_point_formats: ECPointFormatsExtension().
           create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.ec_point_formats: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    # uncompressed EC points need to be self consistent, by changing
    # one coordinate without changing the other we create an invalid point
    node = node.add_child(truncate_handshake(ClientKeyExchangeGenerator(),
                                             1))
    # node = node.add_child(ChangeCipherSpecGenerator())
    # node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectAlert())
    node = node.add_child(ExpectClose())

    conversations["truncated ecdh_Yc value"] = conversation

    # padded Client Key Exchange
    conversation = Connect("localhost", 4433)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.supported_groups: SupportedGroupsExtension().
           create([GroupName.secp256r1, GroupName.secp384r1]),
           ExtensionType.ec_point_formats: ECPointFormatsExtension().
           create([ECPointFormat.uncompressed])}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.ec_point_formats: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    # uncompressed EC points need to be self consistent, by changing
    # one coordinate without changing the other we create an invalid point
    node = node.add_child(pad_handshake(ClientKeyExchangeGenerator(),
                                        1))
    # node = node.add_child(ChangeCipherSpecGenerator())
    # node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectAlert())
    node = node.add_child(ExpectClose())

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
            good += 1
            print("OK\n")
        else:
            bad += 1

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
