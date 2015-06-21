# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Broken TLS server for testing error handling in clients"""

import logging
import threading

import hashlib

from tlslite.messagesocket import MessageSocket
from tlslite.defragmenter import Defragmenter
from tlslite.constants import ContentType, HandshakeType, AlertDescription, \
        CipherSuite, CertificateType, SignatureAlgorithm, HashAlgorithm
from tlslite.messages import ClientHello, ServerHello, Certificate, \
        ServerKeyExchange, ServerHelloDone, Alert
from tlslite.mathtls import goodGroupParameters
from tlslite.utils.cryptomath import bytesToNumber, getRandomBytes, powMod, MD5
from tlslite.utils.rsakey import RSAKey
from tlslite.utils.compat import compat26Str

#logging.basicConfig(level=logging.DEBUG,
#                    format='[%(levelname)s] (%(threadName)-21s) %(message)s')

def SHA224(b):
    return bytearray(hashlib.sha224(compat26Str(b)).digest())

def SHA256(b):
    return bytearray(hashlib.sha256(compat26Str(b)).digest())

def SHA384(b):
    return bytearray(hashlib.sha384(compat26Str(b)).digest())

def SHA512(b):
    return bytearray(hashlib.sha512(compat26Str(b)).digest())

class ServerStop(Exception):

    """Gracefully stop the server thread"""

    pass

class ServerSettings(object):

    """
    Behaviour configuration for the L{BadServer}

    @type record_layer_ver_intolerance: boolean
    @ivar record_layer_ver_intolerance: whether the implementation is
    record layer version intolerant. By default False, which will make it
    accept any record layer version. Use record_layer_ver_cb and
    record_layer_ver_ok to configure intolerance.
    @ivar record_layer_ver_cb: test intolerance callback. The
    method will get a single variable, the record layer version. It should
    return if the value is OK or raise an exception if it is invalid. Needs
    record_layer_ver_intolerance set to function.
    @ivar record_layer_ver_ok: list of versions which are to be considered
    ok. Needs record_layer_ver_intolerance set to function.

    @type tls_version_intolerance: boolean
    @ivar tls_version_intolerance: whether the implementation is supposed
    to simulate tls version intolerance. Checks for the version provided in
    client hello. False by default, meaning the any version will be accepted
    as long as it specifies version supported by server.
    @ivar tls_version_intolerance_cb: test tls version intolerance
    callback. Function that will get a single parameter to check if the
    version is ok. Should just return if the test passes, should raise an
    exception otherwise.
    @ivar tls_version_intolerance_ok: list of version tuples that are to
    be supported by server.

    @type extension_intolerance: boolean
    @ivar extension_intolerance: whether the implementation should simulate
    TLS extension intolerance, False by default.

    @type empty_ext_list_intolerance: boolean
    @ivar empty_ext_list_intolerance: whether implementation should
    simulate empty TLS client hello extension list intolerance, False by
    default

    @type error_handling: int
    @ivar error_handling: how to handle errors. ERROR_DISCONNECT - just end
    connection, default. ERROR_ALERT_GENERIC - send generic handshake failure
    TLS alert.

    @type message_splitting: int
    @ivar message_splitting: dictates if the handshake messages should be
    clumped together in records (SPLITTING_MINIMAL) or if the messages should
    be sent one per record (SPLITTING_FULL). SPLITTING_MINIMAL by default.

    @type supported_versions: list of tuples
    @ivar supported_versions: list of version tuples that server should
    simulate to support. By default SSL3 up to TLSv1.2, list MUST be in
    increasing order.

    @type cipher_ordering: int
    @ivar cipher_ordering: whether to use CLIENT_SIDE or SERVER_SIDE cipher
    ordering, CLIENT_SIDE by default

    @ivar cert_chain: list of certificates to send to client

    @ivar private_key: server private key

    @cvar ERROR_DISCONNECT: setting for error_handling
    @cvar ERROR_ALERT_GENERIC: setting for error_handling

    @cvar SPLITTING_FULL: setting for messsage_splitting
    @cvar SPLITTING_MINIMAL: setting for message_splitting

    @cvar CLIENT_SIDE: setting for cipher_ordering
    @cvar SERVER_SIDE: setting for cipher_ordering
    """

    ERROR_DISCONNECT = 0
    ERROR_ALERT_GENERIC = 1

    SPLITTING_FULL = 0
    SPLITTING_MINIMAL = 1

    CLIENT_SIDE = 0
    SERVER_SIDE = 1

    def __init__(self):
        """Set defaults"""
        self.error_handling = ServerSettings.ERROR_DISCONNECT
        self.message_splitting = ServerSettings.SPLITTING_MINIMAL

        self.record_layer_ver_intolerance = False
        self.record_layer_ver_cb = None
        self.record_layer_ver_ok = None

        self.tls_version_intolerance = False
        self.tls_version_intolerance_cb = None
        self.tls_version_intolerance_ok = None

        self.extension_intolerance = False

        self.empty_ext_list_intolerance = False

        self.supported_versions = [(3, 0), (3, 1), (3, 2), (3, 3)]

        self.cipher_ordering = ServerSettings.CLIENT_SIDE

        self.cert_chain = None
        self.private_key = None

    def test_record_layer_version(self, version):
        """Check if we're intolerant to given record layer version"""
        if not self.record_layer_ver_intolerance:
            return

        if self.record_layer_ver_cb is not None:
            self.record_layer_ver_cb(version)

        if self.record_layer_ver_ok is not None:
            if version not in self.record_layer_ver_ok:
                logging.info("Simulating record layer version intolerance, "
                             "got %s", version)
                raise ServerStop()

    def _test_tls_version(self, version):
        """Check for TLS version intolerance"""
        if not self.tls_version_intolerance:
            return

        if self.tls_version_intolerance_cb is not None:
            self.tls_version_intolerance_cb(version)

        if self.tls_version_intolerance_ok is not None:
            if version not in self.tls_version_intolerance_ok:
                logging.info("Simulating TLS version intolerance, got %s",
                             version)
                raise ServerStop()

    def _test_extension_intolerance(self, client_hello):
        """Check for client_hello intolerance"""
        if self.extension_intolerance and client_hello.extensions is not None:
            logging.info("Simulating TLS extension intolerance")
            raise ServerStop()

        if self.empty_ext_list_intolerance:
            if client_hello.extensions is not None and \
            len(client_hello.extensions) == 0:
                logging.info("Simulating empty TLS extension list "
                             "intolerance")
                raise ServerStop()

    def test_client_hello(self, client_hello):
        """Check if we're intolerant to given client hello"""
        self._test_tls_version(client_hello.client_version)

        self._test_extension_intolerance(client_hello)

    def select_version(self, client_version):
        """Pick the protocol version for server hello"""
        version = next((i for i in self.supported_versions[::-1] \
                        if client_version >= i), None)
        if version is not None:
            return version

        logging.info("Client version %s unsupported", client_version)
        raise ServerStop()

    def select_cipher(self, version, client_hello):
        """Pick the ciphersuite for server hello"""
        all_ciphers = []
        all_ciphers.extend(CipherSuite.tls12Suites)
        all_ciphers.extend(CipherSuite.ssl3Suites)

        if self.cipher_ordering == ServerSettings.CLIENT_SIDE:
            cipher_suite = next((i for i in client_hello.cipher_suites \
                                 if i in all_ciphers), None)
        elif self.cipher_ordering == ServerSettings.SERVER_SIDE:
            cipher_suite = next((i for i in all_ciphers \
                                 if i in client_hello.cipher_suites), None)
        else:
            raise AssertionError("Unknown cipher_ordering")

        if cipher_suite is None:
            logging.info("No shared cipher")
            raise ServerStop()

        return cipher_suite

    def select_extensions(self, version, cipher, client_hello):
        """Provide extension values for server hello"""
        return None

    def select_compression(self, version, cipher, client_hello):
        """Select compression method to advertise"""
        return 0

class BadServer(object):

    """TLS server which implements the protocol incorrectly"""

    def __init__(self, socket, settings):
        """Link server to socket"""
        self.socket = socket
        self.settings = settings

    @staticmethod
    def _setup_message_socket(socket):
        """Wrap the raw socket in TLS message level abstraction"""
        defragmenter = Defragmenter()
        defragmenter.addStaticSize(ContentType.change_cipher_spec, 1)
        defragmenter.addStaticSize(ContentType.alert, 2)
        defragmenter.addDynamicSize(ContentType.handshake, 1, 3)

        msg_sock = MessageSocket(socket, defragmenter)
        msg_sock.version = (3, 0)

        return msg_sock

    def _get_client_hello(self, msg_sock):
        """Get a client hello from socket"""
        header, parser = msg_sock.recvMessageBlocking()

        # in case of errors, use client protocol version
        msg_sock.version = header.version

        if header.type != ContentType.handshake:
            logging.error("Expected handshake protocol (%s), got %s",
                          ContentType.handshake, header.type)
            raise ServerStop()

        self.settings.test_record_layer_version(header.version)

        if parser.getRemainingLength() == 0:
            logging.error("Protocol violation, zero length message")
            raise ServerStop()

        msg_id = parser.get(1)
        if msg_id != HandshakeType.client_hello:
            logging.error("Expected client hello (%s), got %s",
                          HandshakeType.client_hello, msg_id)
            raise ServerStop()

        client_hello = ClientHello()
        try:
            client_hello.parse(parser)
        except SyntaxError: # XXX will be changed upstream
            logging.error("Parsing client hello failed")
            raise ServerStop()

        return client_hello

    def _send_message(self, msg_sock, message):
        """Send or queue a message in socket"""
        if self.settings.message_splitting == \
        ServerSettings.SPLITTING_MINIMAL:
            msg_sock.queueMessageBlocking(message)
        elif self.settings.message_splitting == \
        ServerSettings.SPLITTING_FULL:
            msg_sock.sendMessageBlocking(message)
        else:
            raise AssertionError("Unknown value for message_splitting")

    def _send_server_hello(self, msg_sock, client_hello):
        """Generate and queue a server hello message"""
        version = self.settings.select_version(client_hello.client_version)
        msg_sock.version = version

        cipher = self.settings.select_cipher(version,
                                             client_hello)

        extensions = self.settings.select_extensions(version,
                                                     cipher,
                                                     client_hello)

        server_hello = ServerHello()
        server_hello.create(version=version,
                            random=bytearray(32),
                            session_id=bytearray(0),
                            cipher_suite=cipher,
                            extensions=extensions)

        server_hello.compression_method = \
                self.settings.select_compression(version,
                                                 cipher,
                                                 client_hello)

        self._send_message(msg_sock, server_hello)

        return server_hello

    def _send_certificate(self, msg_sock, client_hello, server_hello):
        """Generate and queue a TLS certificate message"""
        certificate = Certificate(CertificateType.x509)
        certificate.create(self.settings.cert_chain)

        self._send_message(msg_sock, certificate)

        return certificate

    def _send_server_key_exchange(self, msg_sock, client_hello, server_hello):
        """Generate and queue a server key exchange message"""
        server_kex = ServerKeyExchange(server_hello.cipher_suite,
                                       server_hello.server_version)

        if server_hello.cipher_suite in CipherSuite.dhAllSuites:
            params = goodGroupParameters[3]

            srv_priv_value = bytesToNumber(getRandomBytes(32))

            srv_key_share = powMod(params[0], srv_priv_value, params[1])

            server_kex.createDH(params[1], params[0], srv_key_share)

        if server_hello.cipher_suite in CipherSuite.certAllSuites:
            if server_hello.server_version == (3, 3):
                hash_bytes = MD5(client_hello.random + server_hello.random +
                                    server_kex.writeParams())
            else:
                hash_bytes = server_kex.hash(client_hello.random,
                                             server_hello.random)


            if server_hello.server_version == (3, 3):
                server_kex.signAlg = SignatureAlgorithm.rsa
                server_kex.hashAlg = HashAlgorithm.md5
                #hash_bytes = RSAKey.addPKCS1SHA1Prefix(hash_bytes)
                md5_prefix = bytearray([0x30, 0x20, 0x30, 0x0c, 0x06, 0x08,
                                        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                                        0x02, 0x05, 0x05, 0x00, 0x04, 0x10])
                sha224_prefix = bytearray([0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09,
                                           0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                           0x04, 0x02, 0x04, 0x05, 0x00, 0x04,
                                           0x1c])
                sha256_prefix = bytearray([0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
                                           0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                           0x04, 0x02, 0x01, 0x05, 0x00, 0x04,
                                           0x20])
                sha384_prefix = bytearray([0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
                                           0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                           0x04, 0x02, 0x02, 0x05, 0x00, 0x04,
                                           0x30])
                sha512_prefix = bytearray([0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
                                           0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                           0x04, 0x02, 0x03, 0x05, 0x00, 0x04,
                                           0x40])
                hash_bytes = md5_prefix + hash_bytes

            server_kex.signature = \
                    self.settings.private_key.sign(hash_bytes)

        self._send_message(msg_sock, server_kex)

        return server_kex

    def handle_request(self, clnt_sock):
        """Handle a single connection on a socket"""
        try:
            logging.debug("Starting handling request")

            client_hello = None
            server_hello = None
            certificate = None
            server_key_exchange = None

            msg_sock = self._setup_message_socket(clnt_sock)

            client_hello = self._get_client_hello(msg_sock)
            logging.debug("Received client hello: %r", client_hello)
            self.settings.test_client_hello(client_hello)

            server_hello = self._send_server_hello(msg_sock, client_hello)

            if server_hello.cipher_suite in CipherSuite.certAllSuites:
                certificate = self._send_certificate(msg_sock,
                                                     client_hello,
                                                     server_hello)

            if server_hello.cipher_suite in CipherSuite.dhAllSuites or \
            server_hello.cipher_suite in CipherSuite.srpAllSuites:
                server_key_exchange = \
                    self._send_server_key_exchange(msg_sock,
                                                   client_hello,
                                                   server_hello)

            server_hello_done = ServerHelloDone().create()
            self._send_message(msg_sock, server_hello_done)

            msg_sock.flushBlocking()

        except ServerStop:
            if self.settings.error_handling == ServerSettings.ERROR_DISCONNECT:
                pass
            elif self.settings.error_handling == \
            ServerSettings.ERROR_ALERT_GENERIC:
                alert = Alert().create(AlertDescription.handshake_failure)
                msg_sock.sendMessageBlocking(alert)
            else:
                raise AssertionError("Unknown value for error_handling")
        finally:
            clnt_sock.close()
            logging.debug("Socket closed")

    def run(self):
        """Run the server"""
        while True:
            logging.debug("Listening...")
            conn, addr = self.socket.accept()

            thread = threading.Thread(target=self.handle_request,
                                      name=str(addr[0]) + ':' + str(addr[1]),
                                      args=tuple([conn]))

            thread.daemon = True
            thread.start()
