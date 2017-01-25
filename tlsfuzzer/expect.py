# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Parsing and processing of received TLS messages"""

from tlslite.constants import ContentType, HandshakeType, CertificateType,\
        HashAlgorithm, SignatureAlgorithm, ExtensionType,\
        SSL2HandshakeType, CipherSuite, GroupName
from tlslite.messages import ServerHello, Certificate, ServerHelloDone,\
        ChangeCipherSpec, Finished, Alert, CertificateRequest, ServerHello2,\
        ServerKeyExchange, ClientHello, ServerFinished, CertificateStatus
from tlslite.utils.codec import Parser
from tlslite.mathtls import calcFinished
from .handshake_helpers import calc_pending_states
from tlslite.keyexchange import KeyExchange, DHE_RSAKeyExchange, \
        ECDHE_RSAKeyExchange
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
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

        if not msg.write():  # if message is empty
            return False

        hs_type = Parser(msg.write()).get(1)
        if hs_type != self.handshake_type:
            return False

        return True

    def process(self, state, msg):
        raise NotImplementedError("Subclass need to implement this!")


class ExpectServerHello(ExpectHandshake):
    """Parsing TLS Handshake protocol Server Hello messages"""

    def __init__(self, extensions=None, version=None, resume=False,
                 cipher=None):
        """
        Initialize the object

        @type resume: boolean
        @param resume: whether the session id should match the one from
        current state - IOW, if the server hello should belong to a resumed
        session.
        """
        super(ExpectServerHello, self).__init__(ContentType.handshake,
                                                HandshakeType.server_hello)
        self.cipher = cipher
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

        if self.cipher is not None:
            assert self.cipher == srv_hello.cipher_suite

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
                if ext is None:
                    raise AssertionError("Required extension {0} missing"
                                         .format(ExtensionType.toStr(ext_id)))
                # run extension-specific checker if present
                if self.extensions[ext_id] is not None:
                    self.extensions[ext_id](state, ext)
                if ext_id == ExtensionType.extended_master_secret:
                    state.extended_master_secret = True
            # not supporting any extensions is valid
            if srv_hello.extensions is not None:
                for ext_id in (ext.extType for ext in srv_hello.extensions):
                    if ext_id not in self.extensions:
                        raise AssertionError("unexpected extension: {0}"
                                             .format(ExtensionType
                                                     .toStr(ext_id)))


class ExpectServerHello2(ExpectHandshake):
    """Processing of SSLv2 Handshake Protocol SERVER-HELLO message"""

    def __init__(self, version=None):
        c_type = ContentType.handshake
        h_type = SSL2HandshakeType.server_hello
        super(ExpectServerHello2, self).__init__(c_type,
                                                 h_type)
        self.version = version

    def process(self, state, msg):
        """
        Process the message and update state accordingly

        @type state: ConnectionState
        @param state: overall state of TLS connection

        @type msg: Message
        @param msg: TLS Message read from socket
        """
        # the value is faked for SSLv2 protocol, but let's just check sanity
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == SSL2HandshakeType.server_hello

        server_hello = ServerHello2().parse(parser)

        state.handshake_messages.append(server_hello)
        state.handshake_hashes.update(msg.write())

        if self.version is not None:
            assert self.version == server_hello.server_version

        if server_hello.session_id_hit:
            state.resuming = True
        state.session_id = server_hello.session_id
        state.server_random = server_hello.session_id
        state.version = server_hello.server_version
        state.msg_sock.version = server_hello.server_version

        # fake a certificate message so finding the server public key works
        x509 = X509()
        x509.parseBinary(server_hello.certificate)
        cert_chain = X509CertChain([x509])
        certificate = Certificate(CertificateType.x509)
        certificate.create(cert_chain)
        state.handshake_messages.append(certificate)
        # fake message so don't update handshake hashes


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

    def __init__(self, version=None, cipher_suite=None, valid_sig_algs=None,
                 valid_groups=None):
        msg_type = HandshakeType.server_key_exchange
        super(ExpectServerKeyExchange, self).__init__(ContentType.handshake,
                                                      msg_type)
        self.version = version
        self.cipher_suite = cipher_suite
        self.valid_sig_algs = valid_sig_algs
        self.valid_groups = valid_groups

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
        valid_groups = self.valid_groups

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

        if self.cipher_suite in CipherSuite.dhAllSuites:
            state.key_exchange = DHE_RSAKeyExchange(self.cipher_suite,
                                                    clientHello=None,
                                                    serverHello=server_hello,
                                                    privateKey=None)
        elif self.cipher_suite in CipherSuite.ecdhAllSuites:
            # extract valid groups from Client Hello
            if valid_groups is None:
                client_hello = state.get_last_message_of_type(ClientHello)
                if client_hello is not None:
                    groups_ext = client_hello.getExtension(ExtensionType.
                                                           supported_groups)
                    if groups_ext is not None:
                        valid_groups = groups_ext.groups
                if valid_groups is None:
                    # no advertised means support for all
                    valid_groups = GroupName.allEC
            state.key_exchange = \
                ECDHE_RSAKeyExchange(self.cipher_suite,
                                     clientHello=None,
                                     serverHello=server_hello,
                                     privateKey=None,
                                     acceptedCurves=valid_groups)
        else:
            raise AssertionError("Unsupported cipher selected")
        state.premaster_secret = state.key_exchange.\
            processServerKeyExchange(public_key,
                                     server_key_exchange)

        state.handshake_messages.append(server_key_exchange)
        state.handshake_hashes.update(msg.write())


class ExpectCertificateRequest(ExpectHandshake):
    """Processing TLS Handshake protocol Certificate Request message"""

    def __init__(self, sig_algs=None):
        msg_type = HandshakeType.certificate_request
        super(ExpectCertificateRequest, self).__init__(ContentType.handshake,
                                                       msg_type)
        self.sig_algs = sig_algs

    def process(self, state, msg):
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
        if self.sig_algs is not None and \
                cert_request.supported_signature_algs != self.sig_algs:
            raise AssertionError("Unexpected algorithms found: {0}"
                                 .format(cert_request.supported_signature_algs)
                                )

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

        assert ccs.type == 1

        if state.resuming:
            calc_pending_states(state)

        state.msg_sock.changeReadState()


class ExpectVerify(ExpectHandshake):
    """Processing of SSLv2 SERVER-VERIFY message"""

    def __init__(self):
        super(ExpectVerify, self).__init__(ContentType.handshake,
                                           SSL2HandshakeType.server_verify)

    def process(self, state, msg):
        """Check if the VERIFY message has expected value"""
        assert msg.contentType == ContentType.handshake
        parser = Parser(msg.write())

        msg_type = parser.get(1)
        assert msg_type == SSL2HandshakeType.server_verify


class ExpectFinished(ExpectHandshake):
    """Processing TLS handshake protocol Finished message"""

    def __init__(self, version=None):
        if version in ((0, 2), (2, 0)):
            super(ExpectFinished, self).__init__(ContentType.handshake,
                                                 SSL2HandshakeType.
                                                 server_finished)
        else:
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
        assert hs_type == self.handshake_type
        if self.version is None:
            self.version = state.version

        if self.version in ((0, 2), (2, 0)):
            finished = ServerFinished()
        else:
            finished = Finished(self.version)

        finished.parse(parser)

        if self.version in ((0, 2), (2, 0)):
            state.session_id = finished.verify_data
        else:
            verify_expected = calcFinished(state.version,
                                           state.master_secret,
                                           state.cipher,
                                           state.handshake_hashes,
                                           not state.client)

            assert finished.verify_data == verify_expected

        state.handshake_messages.append(finished)
        state.server_verify_data = finished.verify_data
        state.handshake_hashes.update(msg.write())

        if self.version in ((0, 2), (2, 0)):
            state.msg_sock.handshake_finished = True


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
            problem_desc += ("Alert description {0} != {1}"
                             .format(alert.description, self.description))
        if problem_desc:
            raise AssertionError(problem_desc)


class ExpectSSL2Alert(ExpectHandshake):
    """Processing of SSLv2 Handshake protocol alert messages"""

    def __init__(self, error=None):
        super(ExpectSSL2Alert, self).__init__(ContentType.handshake,
                                              SSL2HandshakeType.error)
        self.error = error

    def process(self, state, msg):
        """Analyse the error message"""
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == SSL2HandshakeType.error

        if self.error is not None:
            assert self.error == parser.get(2)


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


class ExpectCertificateStatus(ExpectHandshake):
    """Processing of CertificateStatus message from RFC 6066."""

    def __init__(self):
        super(ExpectCertificateStatus,
              self).__init__(ContentType.handshake,
                             HandshakeType.certificate_status)

    def process(self, state, msg):
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.certificate_status

        cert_status = CertificateStatus().parse(parser)

        state.handshake_messages.append(cert_status)
        state.handshake_hashes.update(msg.write())
