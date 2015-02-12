# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from tlslite.messages import ClientHello, ClientKeyExchange, ChangeCipherSpec,\
        Finished, Alert
from tlslite.constants import AlertLevel, AlertDescription

# control messages
class Connect(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

class Close(object):
    pass

# TLS messages
class MessageGenerator(object):
    def write(self):
        return bytearray(0)

class ClientHelloGenerator(MessageGenerator):
    def __init__(self, ciphers=None):
        if ciphers is None:
            ciphers = []
        self.ciphers = ciphers

    def generate(self):
        ch = ClientHello().create((3, 3), bytearray(32), bytearray(0), \
                self.ciphers, None, None, False, False, None)
        return ch

class ClientKeyExchangeGenerator(MessageGenerator):
    def __init__(self, cipher=None, protocol=None):
        self.cipher = cipher
        self.protocol = protocol

    def generate(self):
        cke = ClientKeyExchange(self.cipher, self.protocol)
        return cke

class ChangeCipherSpecGenerator(MessageGenerator):
    def __init__(self):
        pass

    def generate(self):
        ccs = ChangeCipherSpec()
        return ccs

class FinishedGenerator(MessageGenerator):
    def __init__(self, protocol=None):
        self.protocol = protocol

    def generate(self):
        f = Finished(self.protocol)
        return f

class AlertGenerator(MessageGenerator):
    def __init__(self, level=AlertLevel.warning,
            description=AlertDescription.close_notify):
        self.level = level
        self.description = description

    def generate(self):
        a = Alert().create(self.description, self.level)
        return a

