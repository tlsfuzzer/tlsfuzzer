# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from .generators import Conversation
from .messages import Connect, Close, ClientHelloGenerator,\
        ClientKeyExchangeGenerator, FinishedGenerator,\
        ChangeCipherSpecGenerator, AlertGenerator

from tlslite.constants import ContentType, CipherSuite

class FakeMessage(object):
    def __init__(self, contentType, data):
        self.contentType = contentType
        self.data = data

    def write(self):
        return self.data

class FuzzedMessage(object):
    def __init__(self, version, protocol, generator):
        self.version = version
        self.protocol = protocol
        self.generator = generator

    def generate(self):
        return self.generator.generate()

    def serialise(self, message):
        messages = [FakeMessage(message.contentType, message.write())]
        # for fuzzer in self.postWriteFuzzers:
        #    messages = fuzzer.fuzz(messages)
        return messages

class Fuzzer(object):
    def __init__(self, conversation=None, fingerprint=None):
        self.conversation = conversation
        self.fingerprint = fingerprint

    def __iter__(self):
        conv = Conversation()
        for side, message in self.conversation.messages:
            if side == 'srv':
                conv.messages.append((side, message))
            elif side == 'clnt':
                if isinstance(message, (Connect, Close)):
                    conv.messages.append((side, message))
                elif isinstance(message, \
                        (ClientHelloGenerator, ClientKeyExchangeGenerator,
                            FinishedGenerator)):
                    # XXX should check if the settings was set
                    # and if not, copy from server_hello
                    message.cipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
                    message.protocol = (3, 1)
                    msg = FuzzedMessage((3, 1), ContentType.handshake, \
                            message)
                    conv.messages.append((side, msg))
                elif isinstance(message, ChangeCipherSpecGenerator):
                    msg = FuzzedMessage((3, 1),
                            ContentType.change_cipher_spec,
                            message)
                    conv.messages.append((side, msg))
                elif isinstance(message, AlertGenerator):
                    msg = FuzzedMessage((3, 1), ContentType.alert, \
                            message)
                    conv.messages.append((side, msg))
                else:
                    assert False
            else:
                assert False
        yield conv

