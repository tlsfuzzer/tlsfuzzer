# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Parsing and processing of received TLS messages"""

from tlslite.constants import ContentType, HandshakeType, CertificateType
from tlslite.messages import ServerHello, Certificate, ServerHelloDone,\
        ChangeCipherSpec, Finished, Alert
from tlslite.utils.codec import Parser
from .tree import TreeNode

class Expect(TreeNode):

    """Base class for objects handling message readers"""

    def __init__(self, content_type):
        """Prepare the class for handling tree graph"""
        super(Expect, self).__init__()
        self.content_type = content_type

    def is_expect(self):
        """Flag to tell if the object is a message processor"""
        return True

    def is_command(self):
        """Flag to tell that the object is a message processor"""
        return False

    def is_generator(self):
        """Flag to tell that the object is not a message generator"""
        return False

    def is_match(self, msg):
        """
        Checks if the object can handle message

        Note that the msg is a raw, unparsed message of indicated type that
        requires calling write() to get a raw bytearray() representation of it

        @type msg: L{tlslite.messages.Message}
        @param msg: raw message to check
        """
        if msg.contentType == self.content_type:
            return True

        return False

    def process(self, state, msg):
        """
        Process the message and update the state accordingly.

        @type state: L{tlsfuzzer.runner.ConnectionState}
        @param state: current connection state, needs to be updated after
        parsing the message
        @type msg: L{tlslite.messages.Message}
        @param msg: raw message to parse
        """
        raise NotImplementedError("Subclasses need to implement this!")

class ExpectHandshake(Expect):

    """Common methods for handling TLS Handshake protocol messages"""

    def __init__(self, content_type, handshake_type):
        """
        Set the type of message
        @type content_type: int
        @type handshake_type: int
        """
        super(ExpectHandshake, self).__init__(content_type)
        self.handshake_type = handshake_type

    def is_match(self, msg):
        """Check if message is a given type of handshake protocol message"""
        if not super(ExpectHandshake, self).is_match(msg):
            return False

        hs_type = Parser(msg.write()).get(1)
        if hs_type != self.handshake_type:
            return False

        return True

    def process(self, state, msg):
        raise NotImplementedError("Subclass need to implement this!")

class ExpectServerHello(ExpectHandshake):

    """Parsing TLS Handshake protocol Server Hello messages"""

    def __init__(self):
        """Initialize the object"""
        super(ExpectServerHello, self).__init__(ContentType.handshake,
                                                HandshakeType.server_hello)

    def process(self, state, msg):
        """
        Process the message and update state accordingly

        @type state: ConnectionState
        @param state: overall state of TLS connection

        @type msg: Message
        @param msg: TLS Message read from socket
        """
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.server_hello

        srv_hello = ServerHello()
        srv_hello.parse(parser)

        # extract important info
        state.cipher = srv_hello.cipher_suite
        state.version = srv_hello.server_version
        state.server_random = srv_hello.random

        # update the state of connection
        state.msg_sock.version = srv_hello.server_version

        state.handshake_messages.append(srv_hello)
        state.handshake_hashes.update(msg.write())

class ExpectCertificate(ExpectHandshake):

    """Processing TLS Handshake protocol Certificate messages"""

    def __init__(self, cert_type=CertificateType.x509):
        super(ExpectCertificate, self).__init__(ContentType.handshake,
                                                HandshakeType.certificate)
        self.cert_type = cert_type

    def process(self, state, msg):
        """
        @type state: ConnectionState
        """
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.certificate

        cert = Certificate(self.cert_type)
        cert.parse(parser)

        state.handshake_messages.append(cert)
        state.handshake_hashes.update(msg.write())

class ExpectServerHelloDone(ExpectHandshake):

    """Processing TLS Handshake protocol ServerHelloDone messages"""

    def __init__(self):
        super(ExpectServerHelloDone,
              self).__init__(ContentType.handshake,
                             HandshakeType.server_hello_done)

    def process(self, state, msg):
        """
        @type state: ConnectionState
        @type msg: Message
        """
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.server_hello_done

        srv_hello_done = ServerHelloDone()
        srv_hello_done.parse(parser)

        state.handshake_messages.append(srv_hello_done)
        state.handshake_hashes.update(msg.write())

class ExpectChangeCipherSpec(Expect):

    """Processing TLS Change Cipher Spec messages"""

    def __init__(self):
        super(ExpectChangeCipherSpec,
              self).__init__(ContentType.change_cipher_spec)

    def process(self, state, msg):
        """
        @type state: ConnectionState
        @type msg: Message
        """
        assert msg.contentType == ContentType.change_cipher_spec
        parser = Parser(msg.write())
        ccs = ChangeCipherSpec().parse(parser)

    def post_write(self, satate):
        """Change encryption method"""
        #TODO
        pass

class ExpectFinished(ExpectHandshake):

    """Processing TLS handshake protocol Finished message"""

    def __init__(self, version=(3, 3)):
        super(ExpectFinished, self).__init__(ContentType.handshake,
                                             HandshakeType.finished)
        self.version = version

    def process(self, state, msg):
        """
        @type state: ConnectionState
        @type msg: Message
        """
        assert msg.contentType == ContentType.handshake
        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.finished

        finished = Finished(self.version)
        finished.parse(parser)

        state.handshake_messages.append(finished)

class ExpectAlert(Expect):

    """Processing TLS Alert message"""

    def __init__(self):
        super(ExpectAlert, self).__init__(ContentType.alert)

    def process(self, state, msg):
        assert msg.contentType == ContentType.alert
        parser = Parser(msg.write())

        alert = Alert()
        alert.parse(Parser(msg.write()))

class ExpectApplicationData(Expect):

    """Processing Application Data message"""

    def __init__(self, data=None):
        super(ExpectApplicationData, self).\
                __init__(ContentType.application_data)
        self.data = data

    def process(self, state, msg):
        assert msg.content_type == ContentType.application_data
        parser = Parser(msg.write())

class ExpectClose(Expect):

    """Virtual message signifying closing of TCP connection"""

    def __init__(self):
        super(ExpectClose, self).__init__(None)
