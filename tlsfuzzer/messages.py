# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Set of object for generating TLS messages to send"""

from tlslite.messages import ClientHello, ClientKeyExchange, ChangeCipherSpec,\
        Finished, Alert, ApplicationData
from tlslite.constants import AlertLevel, AlertDescription, ContentType
from tlslite.messagesocket import MessageSocket
from tlslite.defragmenter import Defragmenter
from tlsfuzzer.runner import TreeNode
import socket

class Command(TreeNode):

    """Command objects"""

    def __init__(self):
        super(Command, self).__init__()

    def is_command(self):
        """Define object as a command node"""
        return True

    def is_expect(self):
        """Define object as a command node"""
        return False

    def is_generator(self):
        """Define object as a command node"""
        return False

    def process(self, state):
        """Change the state of the connection"""
        raise NotImplementedError("Subclasses need to implement this!")

class Connect(Command):

    """Object used to connect to a TCP server"""

    def __init__(self, ip, port):
        super(Connect, self).__init__()
        self.ip = ip
        self.port = port

    def process(self, state):
        """Connect to a server"""
        sock = socket.socket((self.ip, self.port))
        sock.set_timeout(5)
        sock.connect()

        defragmenter = Defragmenter()
        defragmenter.addStaticSize(ContentType.alert, 2)
        defragmenter.addStaticSize(ContentType.change_cipher_spec, 1)
        defragmenter.addDynamicSize(ContentType.handshake, 1, 2)

        state.msg_sock = MessageSocket(sock, defragmenter)

class Close(Command):

    """Object used to close a TCP connection"""

    def __init__(self):
        super(Close, self).__init__()

    def process(self, state):
        """Close currently open connection"""
        state.msg_sock.close()

class MessageGenerator(TreeNode):

    """Message generator objects"""

    def __init__(self):
        super(MessageGenerator, self).__init__()

    def is_command(self):
        """Define object as a command node"""
        return False

    def is_expect(self):
        """Define object as a command node"""
        return False

    def is_generator(self):
        """Define object as a command node"""
        return True

    def generate(self, state):
        """Return a message ready to write to socket"""
        raise NotImplementedError("Subclasses need to implement this!")

    def post_send(self, state):
        """Modify the state after sending the message"""
        # since most messages don't require any post-send modifications
        # create a no-op default action
        pass

class ClientHelloGenerator(MessageGenerator):

    """Generator for TLS handshake protocol Client Hello messages"""

    def __init__(self, ciphers=None):
        super(ClientHelloGenerator, self).__init__()
        if ciphers is None:
            ciphers = []
        self.ciphers = ciphers

    def generate(self, status):
        clnt_hello = ClientHello().create((3, 3),
                                          bytearray(32),
                                          bytearray(0),
                                          self.ciphers)
        return clnt_hello

class ClientKeyExchangeGenerator(MessageGenerator):

    """Generator for TLS handshake protocol Client Key Exchange messages"""

    def __init__(self, cipher=None, protocol=None):
        super(ClientKeyExchangeGenerator, self).__init__()
        self.cipher = cipher
        self.protocol = protocol

    def generate(self, status):
        cke = ClientKeyExchange(self.cipher, self.protocol)
        return cke

class ChangeCipherSpecGenerator(MessageGenerator):

    """Generator for TLS Change Cipher Spec messages"""

    def generate(self, status):
        ccs = ChangeCipherSpec()
        return ccs

class FinishedGenerator(MessageGenerator):

    """Generator for TLS handshake protocol Finished messages"""

    def __init__(self, protocol=None):
        super(FinishedGenerator, self).__init__()
        self.protocol = protocol

    def generate(self, status):
        finished = Finished(self.protocol)
        return finished

class AlertGenerator(MessageGenerator):

    """Generator for TLS Alert messages"""

    def __init__(self, level=AlertLevel.warning,
                 description=AlertDescription.close_notify):
        super(AlertGenerator, self).__init__()
        self.level = level
        self.description = description

    def generate(self, status):
        alert = Alert().create(self.description, self.level)
        return alert

class ApplicationDataGenerator(MessageGenerator):

    """Generator for TLS Application Data messages"""

    def __init__(self, payload):
        super(ApplicationDataGenerator, self).__init__()
        self.payload = payload

    def generate(self, status):
        app_data = ApplicationData().create(self.payload)
        return app_data
