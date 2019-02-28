# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test if client hello with garbage at the end gets rejected"""

from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        pad_handshake
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType
from tlsfuzzer.common import handle_user_input, Conversation, run_all

def main():
    """Test if client hello with garbage at the end gets rejected"""
    host, port, run_only, run_exlude = handle_user_input()

    conversations = []

    # Sanity
    conversation_sanity = Conversation("sanity")
    conversation_sanity.root_node = Connect(host, port)
    ext = {ExtensionType.renegotiation_info: None}
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = conversation_sanity.root_node.add_child(ClientHelloGenerator(
        ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
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

    # test if server doesn't interpret extensions past extensions length
    conversation = Conversation("extension past extension")
    conversation.root_node = Connect(host, port)
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = conversation.root_node.add_child(pad_handshake(
        ClientHelloGenerator(ciphers, extensions={}),
        # empty renegotiation info
        pad=bytearray(b'\xff\x01\x00\x01\x00')))
    # responding to a malformed client hello is not correct, but tested below
    node = node.add_child(ExpectServerHello(extensions={}))
    node.next_sibling = ExpectAlert()
    conversations.append(conversation)

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
            # 7 bytes truncates whole 'extensions' creating a valid message
            #("small truncate", -7, 0),
            ("hello truncate", -8, 0),
            ("hello truncate", -9, 0),
            ("hello truncate", -10, 0),
            ("hello truncate", -11, 0),
            ("hello truncate", -12, 0),
            ("hello truncate", -13, 0)]:

        conversation_name = None
        if "pad" in name:
            conversation_name = "{0}: {1} of \"{2}\" byte padding".format(
                name, pad_len, pad_byte)
        else:
            conversation_name = "{0}: {1} of bytes truncated".format(
                name, -pad_len)
        conversation = Conversation(conversation_name)

        conversation.root_node = Connect(host, port)
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        node = conversation.root_node.add_child(pad_handshake(
            ClientHelloGenerator(
                ciphers, extensions={ExtensionType.renegotiation_info: None}),
            pad_len,
            pad_byte))
        # we expect Alert and Close or just Close
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node.add_child(ExpectClose())
        conversations.append(conversation)

    # first and last test is sanity
    conversations.insert(0, conversation_sanity)
    conversations.append(conversation_sanity)

    # TBD: move it to separate function
    #      conversations.filter_by(options)
    #      conversations.run_all()
    for conversation in conversations:
        if run_only and conversation.name not in run_only \
                or conversation.name in run_exlude:
            conversations.remove(conversation)

    run_all(conversations)

if __name__ == "__main__":
    main()
