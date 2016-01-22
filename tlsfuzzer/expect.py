# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Parsing and processing of received TLS messages"""

from tlslite.constants import ContentType, HandshakeType, CertificateType, \
        ExtensionType
from tlslite.messages import ServerHello, Certificate, ServerHelloDone,\
        ChangeCipherSpec, Finished, Alert, CertificateRequest
from tlslite.utils.codec import Parser
from tlslite.mathtls import calcFinished
from .handshake_helpers import calc_pending_states
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

    def __init__(self, extensions=None, version=None, resume=False):
        """
        Initialize the object

        @type resume: boolean
        @param resume: whether the session id should match the one from
        current state - IOW, if the server hello should belong to a resumed
        session.
        """
        super(ExpectServerHello, self).__init__(ContentType.handshake,
                                                HandshakeType.server_hello)
        self.extensions = extensions
        self.version = version
        self.resume = resume

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
        state.server_random = srv_hello.random

        # check for session_id based session resumption
        if self.resume:
            assert state.session_id == srv_hello.session_id
        if (state.session_id == srv_hello.session_id and
                srv_hello.session_id != bytearray(0)):
            state.resuming = True
            assert state.cipher == srv_hello.cipher_suite
            assert state.version == srv_hello.server_version
        state.session_id = srv_hello.session_id

        if self.version is not None:
            assert self.version == srv_hello.server_version

        state.cipher = srv_hello.cipher_suite
        state.version = srv_hello.server_version

        # update the state of connection
        state.msg_sock.version = srv_hello.server_version

        state.handshake_messages.append(srv_hello)
        state.handshake_hashes.update(msg.write())

        # Reset value of the session-wide settings
        state.extended_master_secret = False

        # check if the message has expected values
        if self.extensions is not None:
            for ext_id in self.extensions:
                ext = srv_hello.getExtension(ext_id)
                assert ext is not None
                # run extension-specific checker if present
                if self.extensions[ext_id] is not None:
                    self.extensions[ext_id](state, ext)
                if ext_id == ExtensionType.extended_master_secret:
                    state.extended_master_secret = True
            # not supporting any extensions is valid
            if srv_hello.extensions is not None:
                for ext_id in (ext.extType for ext in srv_hello.extensions):
                    assert ext_id in self.extensions

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

class ExpectCertificateRequest(ExpectHandshake):
    """Processing TLS Handshake protocol Certificate Request message"""

    def __init__(self):
        msg_type = HandshakeType.certificate_request
        super(ExpectCertificateRequest, self).__init__(ContentType.handshake,
                                                       msg_type)

    @staticmethod
    def process(state, msg):
        """
        Check received Certificate Request

        @type state: ConnectionState
        """
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.certificate_request

        cert_request = CertificateRequest(state.version)
        cert_request.parse(parser)

        state.handshake_messages.append(cert_request)
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

        # TOOD: check if it's correct

        if state.resuming:
            calc_pending_states(state)

        state.msg_sock.changeReadState()

class ExpectFinished(ExpectHandshake):

    """Processing TLS handshake protocol Finished message"""

    def __init__(self, version=None):
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
        if self.version is None:
            self.version = state.version

        finished = Finished(self.version)
        finished.parse(parser)

        verify_expected = calcFinished(state.version,
                                       state.master_secret,
                                       state.cipher,
                                       state.handshake_hashes,
                                       not state.client)

        assert finished.verify_data == verify_expected

        state.handshake_messages.append(finished)
        state.server_verify_data = finished.verify_data
        state.handshake_hashes.update(msg.write())

class ExpectAlert(Expect):

    """Processing TLS Alert message"""

    def __init__(self, level=None, description=None):
        super(ExpectAlert, self).__init__(ContentType.alert)
        self.level = level
        self.description = description

    def process(self, state, msg):
        assert msg.contentType == ContentType.alert
        parser = Parser(msg.write())

        alert = Alert()
        alert.parse(parser)

        problem_desc = ""
        if self.level is not None and alert.level != self.level:
            problem_desc += "Alert level {0} != {1}".format(alert.level,
                                                            self.level)
        if self.description is not None \
            and alert.description != self.description:
            if problem_desc:
                problem_desc += ", "
            problem_desc += "Alert description {0} != {1}".format(\
                                        alert.description, self.description)
        if problem_desc:
            raise AssertionError(problem_desc)

class ExpectApplicationData(Expect):

    """Processing Application Data message"""

    def __init__(self, data=None):
        super(ExpectApplicationData, self).\
                __init__(ContentType.application_data)
        self.data = data

    def process(self, state, msg):
        assert msg.contentType == ContentType.application_data
        data = msg.write()

        if self.data:
            assert self.data == data

class ExpectClose(Expect):

    """Virtual message signifying closing of TCP connection"""

    def __init__(self):
        super(ExpectClose, self).__init__(None)
