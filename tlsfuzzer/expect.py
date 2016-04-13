# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Parsing and processing of received TLS messages"""

from tlslite.constants import ContentType, HandshakeType, CertificateType,\
        HashAlgorithm, SignatureAlgorithm, ExtensionType
from tlslite.messages import ServerHello, Certificate, ServerHelloDone,\
        ChangeCipherSpec, Finished, Alert, CertificateRequest, \
        ServerKeyExchange, ClientHello
from tlslite.utils.codec import Parser
from tlslite.mathtls import calcFinished
from tlslite.keyexchange import KeyExchange, DHE_RSAKeyExchange
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

        # check if the message has expected values
        if self.extensions is not None:
            for ext_id in self.extensions:
                ext = srv_hello.getExtension(ext_id)
                assert ext is not None
                # run extension-specific checker if present
                if self.extensions[ext_id] is not None:
                    self.extensions[ext_id](state, ext)
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

class ExpectServerKeyExchange(ExpectHandshake):
    """Processing TLS Handshake protocol Server Key Exchange message"""

    def __init__(self, version=None, cipher_suite=None, valid_sig_algs=None):
        msg_type = HandshakeType.server_key_exchange
        super(ExpectServerKeyExchange, self).__init__(ContentType.handshake,
                                                      msg_type)
        self.version = version
        self.cipher_suite = cipher_suite
        self.valid_sig_algs = valid_sig_algs

    def process(self, state, msg):
        """Process the Server Key Exchange message"""
        assert msg.contentType == ContentType.handshake
        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.server_key_exchange

        if self.version is None:
            self.version = state.version
        if self.cipher_suite is None:
            self.cipher_suite = state.cipher
        valid_sig_algs = self.valid_sig_algs

        server_key_exchange = ServerKeyExchange(self.cipher_suite,
                                                self.version)
        server_key_exchange.parse(parser)

        client_random = state.client_random
        server_random = state.server_random
        public_key = state.get_server_public_key()
        server_hello = state.get_last_message_of_type(ServerHello)
        if server_hello is None:
            server_hello = ServerHello
            server_hello.server_version = state.version
        if valid_sig_algs is None:
            # if the value was unset in script, get the advertised value from
            # Client Hello
            client_hello = state.get_last_message_of_type(ClientHello)
            if client_hello is not None:
                sig_algs_ext = client_hello.getExtension(ExtensionType.
                                                         signature_algorithms)
                if sig_algs_ext is not None:
                    valid_sig_algs = sig_algs_ext.sigalgs
            if valid_sig_algs is None:
                # no advertised means support for sha1 only
                valid_sig_algs = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa)]

        KeyExchange.verifyServerKeyExchange(server_key_exchange,
                                            public_key,
                                            client_random,
                                            server_random,
                                            valid_sig_algs)

        state.key_exchange = DHE_RSAKeyExchange(self.cipher_suite,
                                                clientHello=None,
                                                serverHello=server_hello,
                                                privateKey=None)
        state.premaster_secret = state.key_exchange.\
                                 processServerKeyExchange(public_key,
                                                          server_key_exchange)

        state.handshake_messages.append(server_key_exchange)
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
            state.msg_sock.calcPendingStates(state.cipher,
                                             state.master_secret,
                                             state.client_random,
                                             state.server_random,
                                             None)

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
