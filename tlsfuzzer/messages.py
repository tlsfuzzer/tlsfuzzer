# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Objects for generating TLS messages to send."""

from tlslite.messages import ClientHello, ClientKeyExchange, ChangeCipherSpec,\
        Finished, Alert, ApplicationData, Message, Certificate, \
        CertificateVerify, CertificateRequest, ClientMasterKey, \
        ClientFinished, ServerKeyExchange, ServerHello
from tlslite.constants import AlertLevel, AlertDescription, ContentType, \
        ExtensionType, CertificateType, ClientCertificateType, HashAlgorithm, \
        SignatureAlgorithm, CipherSuite, SignatureScheme, TLS_1_3_HRR
import tlslite.utils.tlshashlib as hashlib
from tlslite.extensions import TLSExtension, RenegotiationInfoExtension, \
        ClientKeyShareExtension
from tlslite.messagesocket import MessageSocket
from tlslite.defragmenter import Defragmenter
from tlslite.mathtls import calcMasterSecret, calcFinished, \
        calcExtendedMasterSecret
from tlslite.handshakehashes import HandshakeHashes
from tlslite.utils.codec import Writer
from tlslite.utils.cryptomath import getRandomBytes, numBytes, \
    numberToByteArray, bytesToNumber, HKDF_expand_label, secureHMAC, \
    derive_secret
from tlslite.keyexchange import KeyExchange
from tlslite.bufferedsocket import BufferedSocket
from .helpers import key_share_gen
from .handshake_helpers import calc_pending_states
from .tree import TreeNode
import socket
from functools import partial


class Command(TreeNode):
    """Command objects."""

    def __init__(self):
        """Create object."""
        super(Command, self).__init__()

    def is_command(self):
        """Define object as a command node."""
        return True

    def is_expect(self):
        """Define object as a command node."""
        return False

    def is_generator(self):
        """Define object as a command node."""
        return False

    def process(self, state):
        """Change the state of the connection."""
        raise NotImplementedError("Subclasses need to implement this!")


class Connect(Command):
    """Object used to connect to a TCP server."""

    def __init__(self, hostname, port, version=(3, 0)):
        """Provide minimal settings needed to connect to other peer."""
        super(Connect, self).__init__()
        self.hostname = hostname
        self.port = port
        self.version = version

    def process(self, state):
        """Connect to a server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((self.hostname, self.port))
        # disable Nagle - we handle buffering and flushing ourselves
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        # allow for later buffering of writes to the socket
        sock = BufferedSocket(sock)

        defragmenter = Defragmenter()
        defragmenter.add_static_size(ContentType.alert, 2)
        defragmenter.add_static_size(ContentType.change_cipher_spec, 1)
        defragmenter.add_dynamic_size(ContentType.handshake, 1, 3)

        state.msg_sock = MessageSocket(sock, defragmenter)

        state.msg_sock.version = self.version


class Close(Command):
    """Object used to close a TCP connection."""

    def __init__(self):
        """Close connection object."""
        super(Close, self).__init__()

    def process(self, state):
        """Close currently open connection."""
        state.msg_sock.sock.close()


class ResetHandshakeHashes(Command):
    """
    Object used to reset current state of handshake hashes to zero.

    Used for session renegotiation or resumption.
    """

    def __init__(self):
        """Object for resetting handshake hashes of session."""
        super(ResetHandshakeHashes, self).__init__()

    def process(self, state):
        """Reset current running handshake protocol hashes."""
        state.handshake_hashes = HandshakeHashes()


class ResetRenegotiationInfo(Command):
    """Object used to reset state of data needed for secure renegotiation."""

    def __init__(self, client=None, server=None):
        """Reset the stored rengotiation info to provided values."""
        super(ResetRenegotiationInfo, self).__init__()
        self.client_verify_data = client
        self.server_verify_data = server

    def process(self, state):
        """Reset current Finished message values."""
        if self.client_verify_data is None:
            self.client_verify_data = bytearray(0)
        if self.server_verify_data is None:
            self.server_verify_data = bytearray(0)
        state.key['client_verify_data'] = self.client_verify_data
        state.key['server_verify_data'] = self.server_verify_data


class SetMaxRecordSize(Command):
    """Change the Record Layer to send records of non standard size."""

    def __init__(self, max_size=None):
        """Set the maximum record layer message size, no option for default."""
        super(SetMaxRecordSize, self).__init__()
        self.max_size = max_size

    def process(self, state):
        """Change the size of messages in record layer."""
        if self.max_size is None:
            # the maximum for SSLv3, TLS1.0, TLS1.1 and TLS1.2
            state.msg_sock.recordSize = 2**14
        else:
            state.msg_sock.recordSize = self.max_size


class SetPaddingCallback(Command):
    """
    Set the padding callback which returns the length of the padding to be
    added to the message in the record layer.
    """

    def __init__(self, cb=None):
        """Set the padding callback"""
        super(SetPaddingCallback, self).__init__()
        self.padding_cb = cb

    @staticmethod
    def fixed_length_cb(size):
        """
        Returns a callback function which returns a fixed number as the
        padding size
        """
        def _fixed_len_cb(length, contenttype, max_padding, zeroes=size):
            """
            Simple callback which returns a fixed number as the padding size
            to be added to the message
            """
            if zeroes > (max_padding - length):
                raise ValueError("requested padding size is too large")

            return zeroes
        return _fixed_len_cb

    @staticmethod
    def fill_padding_cb(length, contenttype, max_padding):
        """
        Simple callback which returns the maximum padding size as
        the size of the padding to be added to the message
        """
        return max_padding - length

    def process(self, state):
        """
        Set the callback which returns the length of the padding in record
        layer.
        """
        state.msg_sock.padding_cb = self.padding_cb


class TCPBufferingEnable(Command):
    """
    Start buffering all writes on the TCP level of connection.

    You will need to call an explicit flush to send the messages.
    """

    def process(self, state):
        """Enable TCP buffering."""
        state.msg_sock.sock.buffer_writes = True


class TCPBufferingDisable(Command):
    """
    Stop buffering all writes on the TCP level.

    All messages will be now passed directly to the TCP socket
    """

    def process(self, state):
        """Disable TCP buffering."""
        state.msg_sock.sock.buffer_writes = False


class TCPBufferingFlush(Command):
    """
    Send all messages in the buffer.

    Does not change the state of buffering
    """

    def process(self, state):
        """Flush all messages to TCP socket."""
        state.msg_sock.sock.flush()


class CollectNonces(Command):
    """
    Start collecting nonces being sent by the server in the provided array.

    Works only for ciphers like AES-GCM which use explicit nonces. Ciphers
    like Chacha20 use implicit nonce constructed from PRF output and sequence
    number.

    Needs to be run after the cipher was negotiated and switched to (after
    CCS), will collect nonces only till next renegotiation.
    """

    def __init__(self, nonces):
        """Link the list for storing nonces with the object."""
        super(CollectNonces, self).__init__()
        self.nonces = nonces

    def process(self, state):
        """Monkey patch the seal() method."""
        seal_mthd = state.msg_sock._writeState.encContext.seal

        def collector(nonce, buf, authData, old_seal=seal_mthd,
                      nonces=self.nonces):
            """Collect used nonces for encryption."""
            nonces.append(nonce)
            return old_seal(nonce, buf, authData)

        state.msg_sock._writeState.encContext.seal = collector


class PlaintextMessageGenerator(Command):
    """
    Send a plaintext data record even if encryption is already negotiated.

    Do not update handshake hashes, record layer state, do not fragment, etc.
    """

    def __init__(self, content_type, data, description=None):
        """Set the record layer type and payload to send."""
        super(PlaintextMessageGenerator, self).__init__()
        self.content_type = content_type
        self.data = data
        self.description = description

    def __repr__(self):
        """Return human readable representation of the object."""
        vals = []
        vals.append(('content_type', self.content_type))
        vals.append(('data', repr(self.data)))
        if self.description:
            vals.append(('description', repr(self.description)))

        return "PlaintextMessageGenerator({0})".format(
                ", ".join("{0}={1}".format(i[0], i[1]) for i in vals))

    def process(self, state):
        """Send the message over the socket."""
        msg = Message(self.content_type, self.data)

        for _ in state.msg_sock._recordSocket.send(msg):
            pass


class MessageGenerator(TreeNode):
    """Message generator objects."""

    def __init__(self):
        """Initialize the object."""
        super(MessageGenerator, self).__init__()
        self.msg = None

    def is_command(self):
        """Define object as a generator node."""
        return False

    def is_expect(self):
        """Define object as a generator node."""
        return False

    def is_generator(self):
        """Define object as a generator node."""
        return True

    def generate(self, state):
        """Return a message ready to write to socket."""
        raise NotImplementedError("Subclasses need to implement this!")

    def post_send(self, state):
        """Modify the state after sending the message."""
        # since most messages don't require any post-send modifications
        # create a no-op default action
        pass


class RawMessageGenerator(MessageGenerator):
    """
    Generator for arbitrary record layer messages.

    Can generate message with any content_type and any payload. Will
    be encrypted if encryption is negotiated in the connection.
    """

    def __init__(self, content_type, data, description=None):
        """Set the record layer type and payload to send."""
        super(RawMessageGenerator, self).__init__()
        self.content_type = content_type
        self.data = data
        self.description = description

    def generate(self, state):
        """Create a tlslite-ng message that can be send."""
        message = Message(self.content_type, self.data)
        return message

    def __repr__(self):
        """Return human readable representation of the object."""
        if self.description is None:
            return "RawMessageGenerator(content_type={0!s}, data={1!r})".\
                   format(self.content_type, self.data)
        else:
            return "RawMessageGenerator(content_type={0!s}, data={1!r}, " \
                   "description={2!r})".format(self.content_type, self.data,
                                               self.description)


class HandshakeProtocolMessageGenerator(MessageGenerator):
    """Message generator for TLS Handshake protocol messages."""

    def post_send(self, state):
        """Update handshake hashes after sending."""
        super(HandshakeProtocolMessageGenerator, self).post_send(state)

        state.handshake_hashes.update(self.msg.write())
        state.handshake_messages.append(self.msg)


def ch_cookie_handler(state):
    """Client Hello cookie extension handler.

    Copies the cookie extension from last HRR message.
    """
    hrr = state.get_last_message_of_type(ServerHello)
    if not hrr or hrr.random != TLS_1_3_HRR:
        # as the second CH should never be used without ExpectHelloRetryRequest
        # before it, using this helper when there is no HRR in current
        # handshake messages in the state is a user error, not server error
        raise ValueError("No HRR received")
    cookie = hrr.getExtension(ExtensionType.cookie)
    return cookie


def ch_key_share_handler(state):
    """Client Hello key_share extension handler.

    Generates the key share for the group selected by server in the last
    HRR message.
    """
    hrr = state.get_last_message_of_type(ServerHello)
    if not hrr or hrr.random != TLS_1_3_HRR:
        # as the second CH should never be used without ExpectHelloRetryRequest
        # before it, using this helper when there is no HRR in current
        # handshake messages in the state is a user error, not server error
        raise ValueError("No HRR received")
    hrr_key_share = hrr.getExtension(ExtensionType.key_share)

    # the check if the group selected in HRR was advertised in the first
    # ClientHello happens in the hrr_ext_handler_key_share()

    group_id = hrr_key_share.selected_group
    key_shares = [key_share_gen(group_id)]
    key_share = ClientKeyShareExtension().create(key_shares)
    return key_share


class ClientHelloGenerator(HandshakeProtocolMessageGenerator):
    """Generator for TLS handshake protocol Client Hello messages."""

    def __init__(self, ciphers=None, extensions=None, version=None,
                 session_id=None, random=None, compression=None, ssl2=False):
        """Set up the object for generation of Client Hello messages."""
        super(ClientHelloGenerator, self).__init__()
        if ciphers is None:
            ciphers = []
        if compression is None:
            compression = [0]

        self.version = version
        self.ciphers = ciphers
        self.extensions = extensions
        self.version = version
        self.session_id = session_id
        self.random = random
        self.compression = compression
        self.ssl2 = ssl2

    def _generate_extensions(self, state):
        """Convert extension generators to extension objects."""
        extensions = []
        for ext_id in self.extensions:
            if self.extensions[ext_id] is not None:
                if callable(self.extensions[ext_id]):
                    extensions.append(self.extensions[ext_id](state))
                elif isinstance(self.extensions[ext_id], TLSExtension):
                    extensions.append(self.extensions[ext_id])
                else:
                    raise ValueError("Bad extension, id: {0}".format(ext_id))
                continue

            if ext_id == ExtensionType.renegotiation_info:
                ext = RenegotiationInfoExtension()\
                    .create(state.key['client_verify_data'])
                extensions.append(ext)
            else:
                extensions.append(TLSExtension().create(ext_id, bytearray(0)))

        return extensions

    def generate(self, state):
        """Create a Client Hello message."""
        if self.version is None:
            self.version = state.client_version
        if self.random:
            state.client_random = self.random
        if self.session_id is None and state.session_id:
            self.session_id = state.session_id
        if self.session_id is None and self.extensions \
                and ExtensionType.supported_versions in self.extensions:
            # in TLS 1.3, the server should reply with CCS (middlebox compat
            # mode) only when client sends a session_id
            self.session_id = getRandomBytes(32)
        # if still unset, set to default value
        if not self.session_id:
            self.session_id = bytearray(b'')

        if not state.client_random:
            state.client_random = bytearray(32)

        extensions = None
        if self.extensions is not None:
            extensions = self._generate_extensions(state)

        clnt_hello = ClientHello(self.ssl2).create(self.version,
                                                   state.client_random,
                                                   self.session_id,
                                                   self.ciphers,
                                                   extensions=extensions)
        clnt_hello.compression_methods = self.compression
        state.client_version = self.version

        self.msg = clnt_hello

        return clnt_hello


class ClientKeyExchangeGenerator(HandshakeProtocolMessageGenerator):
    """
    Generator for TLS handshake protocol Client Key Exchange messages.

    @type dh_Yc: int
    @ivar dh_Yc: Override the sent dh_Yc value to the specified one
    @type padding_subs: dict
    @ivar padding_subs: Substitutions for the encrypted premaster secret
       padding bytes (applicable only for the RSA key exchange)
    @type padding_xors: dict
    @ivar padding_xors: XORs for the encrypted premaster secret padding bytes
       (applicable only for the RSA key exchange)
    @type ecdh_Yc: bytearray
    @ivar ecdh_Yc: encoded ECC point being the client key share for the
       key exchange
    @type encrypted_premaster: bytearray
    @ivar encrypted_premaster: the premaster secret after it was encrypted,
       as it will be sent on the wire
    @type modulus_as_encrypted_premaster: boolean
    @ivar modulus_as_encrypted_premaster: if True, set the encrypted
       premaster (the value seen on the wire) to the server's certificate
       modulus (the server's public key)
    @type p_as_share: boolean
    @ivar p_as_share: set the key share to the value p provided by server
       in Server Key Exchange (applicable only to FFDHE key exchange)
    @type p_1_as_share: boolean
    @ivar p_1_as_share: set the key share to the value p-1, as provided by
       server in Server Key Exchange (applicable only to FFDHE key exchange
       with safe primes)
    """

    def __init__(self, cipher=None, version=None, client_version=None,
                 dh_Yc=None, padding_subs=None, padding_xors=None,
                 ecdh_Yc=None, encrypted_premaster=None,
                 modulus_as_encrypted_premaster=False, p_as_share=False,
                 p_1_as_share=False, premaster_secret=None):
        """Set settings of the Client Key Exchange to be sent."""
        super(ClientKeyExchangeGenerator, self).__init__()
        self.cipher = cipher
        self.version = version
        self.client_version = client_version
        if premaster_secret is None:
            self.premaster_secret = bytearray(48)
        else:
            self.premaster_secret = premaster_secret
        self.dh_Yc = dh_Yc
        self.padding_subs = padding_subs
        self.padding_xors = padding_xors
        self.ecdh_Yc = ecdh_Yc
        self.encrypted_premaster = encrypted_premaster
        self.modulus_as_encrypted_premaster = modulus_as_encrypted_premaster
        self.p_as_share = p_as_share
        self.p_1_as_share = p_1_as_share

        if p_as_share and p_1_as_share:
            raise ValueError("Can't set both p_as_share and p_1_as_share at "
                             "the same time")

    def generate(self, status):
        """Create a Client Key Exchange message."""
        if self.version is None:
            self.version = status.version

        if self.cipher is None:
            self.cipher = status.cipher

        if self.client_version is None:
            self.client_version = status.client_version

        cke = ClientKeyExchange(self.cipher, self.version)
        if self.cipher in CipherSuite.certSuites:
            if self.modulus_as_encrypted_premaster:
                public_key = status.get_server_public_key()
                self.encrypted_premaster = numberToByteArray(public_key.n)
            if self.encrypted_premaster:
                cke.createRSA(self.encrypted_premaster)
            else:
                assert len(self.premaster_secret) > 1
                self.premaster_secret[0] = self.client_version[0]
                self.premaster_secret[1] = self.client_version[1]

                status.key['premaster_secret'] = self.premaster_secret

                public_key = status.get_server_public_key()

                cke.createRSA(self._encrypt_with_fuzzing(public_key))
        elif self.cipher in CipherSuite.dheCertSuites:
            if self.dh_Yc is not None:
                cke = ClientKeyExchange(self.cipher,
                                        self.version).createDH(self.dh_Yc)
            elif self.p_as_share or self.p_1_as_share:
                ske = next((i for i in reversed(status.handshake_messages)
                            if isinstance(i, ServerKeyExchange)), None)
                assert ske, "No server key exchange in messages"
                if self.p_as_share:
                    cke = ClientKeyExchange(self.cipher,
                                            self.version).createDH(ske.dh_p)
                else:
                    cke = ClientKeyExchange(self.cipher,
                                            self.version).createDH(ske.dh_p-1)
            else:
                cke = status.key_exchange.makeClientKeyExchange()
        elif self.cipher in CipherSuite.ecdhAllSuites:
            if self.ecdh_Yc is not None:
                cke = ClientKeyExchange(self.cipher,
                                        self.version).createECDH(self.ecdh_Yc)
            else:
                cke = status.key_exchange.makeClientKeyExchange()
        else:
            raise AssertionError("Unknown cipher/key exchange type")

        self.msg = cke

        return cke

    def _encrypt_with_fuzzing(self, public_key):
        """Use public_key to encrypt premaster secret with fuzzed padding."""
        old_addPKCS1Padding = public_key._addPKCS1Padding
        public_key = fuzz_pkcs1_padding(public_key, self.padding_subs,
                                        self.padding_xors)
        ret = public_key.encrypt(self.premaster_secret)
        public_key._addPKCS1Padding = old_addPKCS1Padding
        return ret

    def post_send(self, state):
        """Save intermediate handshake hash value."""
        # for EMS all messages up to and including CKE are part of
        # "session_hash"
        super(ClientKeyExchangeGenerator, self).post_send(state)
        state.certificate_verify_handshake_hashes = \
            state.handshake_hashes.copy()


class ClientMasterKeyGenerator(HandshakeProtocolMessageGenerator):
    """Generator for SSLv2 Handshake Protocol CLIENT-MASTER-KEY message."""

    def __init__(self, cipher=None, master_key=None):
        """Set the cipher to send to server."""
        super(ClientMasterKeyGenerator, self).__init__()
        self.cipher = cipher
        self.master_key = master_key

    def generate(self, state):
        """Generate a new CLIENT-MASTER-KEY message."""
        if self.cipher is None:
            raise NotImplementedError("No cipher autonegotiation")
        if self.master_key is None:
            if state.key['master_secret'] == bytearray(0):
                if self.cipher in CipherSuite.ssl2_128Key:
                    key_size = 16
                elif self.cipher in CipherSuite.ssl2_192Key:
                    key_size = 24
                elif self.cipher in CipherSuite.ssl2_64Key:
                    key_size = 8
                else:
                    raise AssertionError("unknown cipher but no master_secret")
                self.master_key = getRandomBytes(key_size)
            else:
                self.master_key = state.key['master_secret']

        cipher = self.cipher
        if (cipher not in CipherSuite.ssl2rc4 and
                cipher not in CipherSuite.ssl2_3des):
            # tlslite-ng doesn't implement anything else, so we need to
            # workaround calculation of pending states failure for test
            # cases which don't really encrypt data
            cipher = CipherSuite.SSL_CK_RC4_128_WITH_MD5

        key_arg = state.msg_sock.calcSSL2PendingStates(cipher,
                                                       self.master_key,
                                                       state.client_random,
                                                       state.server_random,
                                                       None)

        if self.cipher in CipherSuite.ssl2export:
            clear_key = self.master_key[:-5]
            secret_key = self.master_key[-5:]
        else:
            clear_key = bytearray(0)
            secret_key = self.master_key

        pub_key = state.get_server_public_key()
        encrypted_master_key = pub_key.encrypt(secret_key)

        cmk = ClientMasterKey()
        cmk.create(self.cipher, clear_key, encrypted_master_key, key_arg)
        self.msg = cmk
        return cmk


class CertificateGenerator(HandshakeProtocolMessageGenerator):
    """Generator for TLS handshake protocol Certificate message."""

    def __init__(self, certs=None, cert_type=None):
        """Set the certificates to send to server."""
        super(CertificateGenerator, self).__init__()
        self.certs = certs
        self.cert_type = cert_type

    def generate(self, status):
        """Create a Certificate message."""
        del status  # unused
        # TODO: support client certs
        if self.cert_type is None:
            self.cert_type = CertificateType.x509
        cert = Certificate(self.cert_type)
        cert.create(self.certs)

        self.msg = cert
        return cert


class CertificateVerifyGenerator(HandshakeProtocolMessageGenerator):
    """
    Generator for TLS handshake protocol Certificate Verify message.

    @type msg_alg: touple of two integers
    @ivar msg_alg: signature and hash algorithm to be set on in the
      digitally-signed structure of TLSv1.2 Certificate Verify message.
      By default the first RSA hash advertised by server. SHA-1 if no RSA
      hashes advertised. The first value specifies hash type (from
      HashAlgorithm) and the second value specifies the signature algorithm
      (from SignatureAlgorithm).

    @type msg_version: touple of two integers
    @ivar msg_version: protocol version that the message is to use,
      default is taken from current connection state

    @type sig_version: touple of two integers
    @ivar sig_version: protocol version to use for calculating the verify bytes
      for the signature (overrides msg_version, but just for the signature).
      Equal to msg_version by default.

    @type sig_alg: touple of two integers
    @ivar sig_alg: hash and signature algorithm to be used for creating the
      signature in the message. Equal to msg_alg by default. Requires the
      protocol of the signature to be set to at least TLSv1.2 to be effective.

    @type signature: bytearray
    @ivar signature: bytes to sent as the signature of the message
    """

    def __init__(self, private_key=None, msg_version=None, msg_alg=None,
                 sig_version=None, sig_alg=None, signature=None,
                 rsa_pss_salt_len=None, padding_xors=None, padding_subs=None):
        """Create object for generating Certificate Verify messages."""
        super(CertificateVerifyGenerator, self).__init__()
        self.private_key = private_key
        self.msg_alg = msg_alg
        self.msg_version = msg_version
        self.sig_version = sig_version
        self.sig_alg = sig_alg
        self.signature = signature
        self.rsa_pss_salt_len = rsa_pss_salt_len
        self.padding_xors = padding_xors
        self.padding_subs = padding_subs

    def generate(self, status):
        """Create a CertificateVerify message."""
        if self.msg_version is None:
            self.msg_version = status.version
        if self.sig_version is None:
            self.sig_version = self.msg_version
        if self.msg_alg is None and self.msg_version >= (3, 3):
            cert_req = next((msg for msg in status.handshake_messages[::-1]
                             if isinstance(msg, CertificateRequest)), None)
            if cert_req is not None:
                self.msg_alg = next((sig for sig in
                                     cert_req.supported_signature_algs
                                     if sig[1] == SignatureAlgorithm.rsa or
                                     sig[0] == 8 and sig[1] in (4, 5, 6)),
                                    None)
            if self.msg_alg is None:
                self.msg_alg = (HashAlgorithm.sha1,
                                SignatureAlgorithm.rsa)
        if self.sig_alg is None:
            self.sig_alg = self.msg_alg

        # TODO: generate a random key if none provided
        if self.signature is not None:
            signature = self.signature
        else:
            if self.private_key is None:
                raise ValueError("Can't create a signature without "
                                 "private key!")

            verify_bytes = \
                KeyExchange.calcVerifyBytes(self.sig_version,
                                            status.handshake_hashes,
                                            self.sig_alg,
                                            status.key['premaster_secret'],
                                            status.client_random,
                                            status.server_random)

            # we don't have to handle non pkcs1 padding because the
            # calcVerifyBytes does everything
            scheme = SignatureScheme.toRepr(self.sig_alg)
            hashName = None
            saltLen = 0
            if scheme is None:
                padding = "pkcs1"
            else:
                padding = SignatureScheme.getPadding(scheme)
                if padding == 'pss':
                    hashName = SignatureScheme.getHash(scheme)
                    if self.rsa_pss_salt_len is None:
                        self.rsa_pss_salt_len = \
                                getattr(hashlib, hashName)().digest_size

            def _newRawPrivateKeyOp(self, m, original_rawPrivateKeyOp,
                                    subs=None, xors=None):
                signBytes = numberToByteArray(m, numBytes(self.n))
                signBytes = substitute_and_xor(signBytes, subs, xors)
                m = bytesToNumber(signBytes)
                # RSA operations are defined only on numbers that are smaller
                # than the modulus, so ensure the XORing or substitutions
                # didn't break it (especially necessary for pycrypto as
                # it raises exception in such case)
                if m > self.n:
                    m %= self.n
                return original_rawPrivateKeyOp(m)

            oldPrivateKeyOp = self.private_key._rawPrivateKeyOp
            self.private_key._rawPrivateKeyOp = \
                partial(_newRawPrivateKeyOp,
                        self.private_key,
                        original_rawPrivateKeyOp=oldPrivateKeyOp,
                        subs=self.padding_subs,
                        xors=self.padding_xors)
            try:
                signature = self.private_key.sign(verify_bytes,
                                                  padding,
                                                  hashName,
                                                  self.rsa_pss_salt_len)
            finally:
                # make sure the changes are undone even if the signing fails
                self.private_key._rawPrivateKeyOp = oldPrivateKeyOp

        cert_verify = CertificateVerify(self.msg_version)
        cert_verify.create(signature, self.msg_alg)

        self.msg = cert_verify
        return cert_verify


class ChangeCipherSpecGenerator(MessageGenerator):
    """Generator for TLS Change Cipher Spec messages."""

    def __init__(self, extended_master_secret=None):
        """Create an object for generating CCS messages."""
        super(ChangeCipherSpecGenerator, self).__init__()
        self.extended_master_secret = extended_master_secret

    def generate(self, status):
        """Create a message for sending to server."""
        ccs = ChangeCipherSpec()
        return ccs

    def post_send(self, status):
        """Generate new encryption keys for connection."""
        cipher_suite = status.cipher
        status.msg_sock.encryptThenMAC = status.encrypt_then_mac
        if self.extended_master_secret is None:
            self.extended_master_secret = status.extended_master_secret

        if not status.resuming:
            if self.extended_master_secret:
                # in case client certificates are used, we need to omit
                # certificate verify message
                hh = status.certificate_verify_handshake_hashes
                if not hh:
                    hh = status.handshake_hashes
                master_secret = \
                    calcExtendedMasterSecret(status.version,
                                             cipher_suite,
                                             status.key['premaster_secret'],
                                             hh)
            else:
                master_secret = calcMasterSecret(
                    status.version,
                    cipher_suite,
                    status.key['premaster_secret'],
                    status.client_random,
                    status.server_random)

            status.key['master_secret'] = master_secret

            # in case of resumption, the pending states are generated
            # during receive of server sent CCS
            calc_pending_states(status)

        status.msg_sock.changeWriteState()


class FinishedGenerator(HandshakeProtocolMessageGenerator):
    """Generator for TLS handshake protocol Finished messages."""

    def __init__(self, protocol=None):
        """Object to generate Finished messages."""
        super(FinishedGenerator, self).__init__()
        self.protocol = protocol
        self.server_finish_hh = None

    def generate(self, status):
        """Create a Finished message."""
        if self.protocol is None:
            self.protocol = status.version

        if self.protocol in ((0, 2), (2, 0)):
            finished = ClientFinished()
            verify_data = status.session_id

            # in SSLv2 we're using it as a CCS-of-sorts too
            status.msg_sock.changeWriteState()
            status.msg_sock.changeReadState()
        elif self.protocol <= (3, 3):
            finished = Finished(self.protocol)
            verify_data = calcFinished(status.version,
                                       status.key['master_secret'],
                                       status.cipher,
                                       status.handshake_hashes,
                                       status.client)
        else:  # TLS 1.3
            finished = Finished(self.protocol, status.prf_size)
            finished_key = HKDF_expand_label(
                status.key['client handshake traffic secret'],
                b'finished',
                b'',
                status.prf_size,
                status.prf_name)
            self.server_finish_hh = status.handshake_hashes.copy()
            verify_data = secureHMAC(
                finished_key,
                self.server_finish_hh.digest(status.prf_name),
                status.prf_name)

        status.key['client_verify_data'] = verify_data

        finished.create(verify_data)

        self.msg = finished

        return finished

    def post_send(self, status):
        """Perform post-transmit changes needed by generation of Finished."""
        super(FinishedGenerator, self).post_send(status)

        # resumption finished
        status.resuming = False

        if status.version <= (3, 3):
            return

        # derive the master secret
        secret = derive_secret(
            status.key['handshake secret'], b'derived', None, status.prf_name)
        secret = secureHMAC(
            secret, bytearray(status.prf_size), status.prf_name)
        status.key['master secret'] = secret

        # derive encryption keys
        c_traff_sec = derive_secret(
            secret, b'c ap traffic', self.server_finish_hh, status.prf_name)
        status.key['client application traffic secret'] = c_traff_sec
        s_traff_sec = derive_secret(
            secret, b's ap traffic', self.server_finish_hh, status.prf_name)
        status.key['server application traffic secret'] = s_traff_sec

        # derive TLS exporter key
        exp_ms = derive_secret(secret, b'exp master', self.server_finish_hh,
                               status.prf_name)
        status.key['exporter master secret'] = exp_ms

        # set up the encryption keys for application data
        status.msg_sock.calcTLS1_3PendingState(
            status.cipher, c_traff_sec, s_traff_sec, None)
        status.msg_sock.changeReadState()
        status.msg_sock.changeWriteState()

        # derive resumption master secret key
        res_ms = derive_secret(secret, b'res master', status.handshake_hashes,
                               status.prf_name)
        status.key['resumption master secret'] = res_ms


class AlertGenerator(MessageGenerator):
    """Generator for TLS Alert messages."""

    def __init__(self, level=AlertLevel.warning,
                 description=AlertDescription.close_notify):
        """Save the level and description of the Alert to send."""
        super(AlertGenerator, self).__init__()
        self.level = level
        self.description = description

    def generate(self, status):
        """Send the Alert to server."""
        alert = Alert().create(self.description, self.level)
        return alert


class ApplicationDataGenerator(MessageGenerator):
    """Generator for TLS Application Data messages."""

    def __init__(self, payload):
        """Save the data to send to server."""
        super(ApplicationDataGenerator, self).__init__()
        self.payload = payload

    def generate(self, status):
        """Send data to server in Application Data messages."""
        app_data = ApplicationData().create(self.payload)
        return app_data


def pad_handshake(generator, size=0, pad_byte=0, pad=None):
    """
    Pad or truncate handshake messages.

    Pad or truncate a handshake message by given amount of bytes, use negative
    to size to truncate.
    """
    def new_generate(state, old_generate=generator.generate):
        """Monkey patch for the generate method of the Handshake generators."""
        msg = old_generate(state)

        def post_write(writer, self=msg, size=size, pad_byte=pad_byte,
                       pad=pad):
            """Monkey patch for the postWrite of handshake messages."""
            if pad is not None:
                size = len(pad)
            header_writer = Writer()
            header_writer.add(self.handshakeType, 1)
            header_writer.add(len(writer.bytes) + size, 3)
            if pad is not None:
                return header_writer.bytes + writer.bytes + pad
            elif size < 0:
                return header_writer.bytes + writer.bytes[:size]
            else:
                return header_writer.bytes + writer.bytes + \
                       bytearray([pad_byte]*size)

        msg.postWrite = post_write
        return msg

    generator.generate = new_generate
    return generator


def truncate_handshake(generator, size=0, pad_byte=0):
    """Truncate a handshake message."""
    return pad_handshake(generator, -size, pad_byte)


def substitute_and_xor(data, substitutions, xors):
    """Apply changes from substitutions and xors to data for fuzzing."""
    if substitutions is not None:
        for pos in substitutions:
            data[pos] = substitutions[pos]

    if xors is not None:
        for pos in xors:
            data[pos] ^= xors[pos]

    return data


def fuzz_message(generator, substitutions=None, xors=None):
    """Change arbitrary bytes of the message after write."""
    def new_generate(state, old_generate=generator.generate):
        """Monkey patch for the generate method of the Handshake generators."""
        msg = old_generate(state)

        def new_write(old_write=msg.write, substitutions=substitutions,
                      xors=xors):
            """Monkey patch for the write method of messages."""
            data = old_write()

            data = substitute_and_xor(data, substitutions, xors)

            return data

        msg.write = new_write
        return msg

    generator.generate = new_generate
    return generator


def post_send_msg_sock_restore(obj, method_name, old_method_name):
    """Un-Monkey patch a method of msg_sock."""
    def new_post_send(state, obj=obj,
                      method_name=method_name,
                      old_method_name=old_method_name,
                      old_post_send=obj.post_send):
        """Reverse the patching of a method in msg_sock."""
        setattr(state.msg_sock, method_name, getattr(obj, old_method_name))
        old_post_send(state)
    obj.post_send = new_post_send
    return obj


def fuzz_mac(generator, substitutions=None, xors=None):
    """Change arbitrary bytes of the MAC value."""
    def new_generate(state, self=generator,
                     old_generate=generator.generate,
                     substitutions=substitutions,
                     xors=xors):
        """Monkey patch to modify MAC calculation of created MAC."""
        msg = old_generate(state)

        old_calculate_mac = state.msg_sock.calculateMAC

        self.old_calculate_mac = old_calculate_mac

        def new_calculate_mac(mac, seqnumBytes, contentType, data,
                              old_calculate_mac=old_calculate_mac,
                              substitutions=substitutions,
                              xors=xors):
            """Monkey patch for the MAC calculation method of msg socket."""
            mac_bytes = old_calculate_mac(mac, seqnumBytes, contentType, data)

            mac_bytes = substitute_and_xor(mac_bytes, substitutions, xors)

            return mac_bytes

        state.msg_sock.calculateMAC = new_calculate_mac

        return msg

    generator.generate = new_generate

    post_send_msg_sock_restore(generator, 'calculateMAC', 'old_calculate_mac')

    return generator


def fuzz_encrypted_message(generator, substitutions=None, xors=None):
    """Change arbitrary bytes of the authenticated ciphertext block."""
    def new_generate(state, self=generator,
                     old_generate=generator.generate,
                     substitutions=substitutions,
                     xors=xors):
        """Monkey patch to modify authenticated ciphertext block."""
        msg = old_generate(state)

        old_send = state.msg_sock._recordSocket.send

        self.old_send = old_send

        def new_send(message, padding, old_send=old_send,
                     substitutions=substitutions, xors=xors):
            """
            Monkey patch for the send method of msg socket.

            message.data is the encrypted tls record, e.g.

            message.data = aead_encrypt(plain); defined by aead suite
            message.data = encrypt(plain + padding) + mac; etm
            message.data = encrypt(plain + mac + padding); mte
            """
            data = message.write()

            data = substitute_and_xor(data, substitutions, xors)

            new_message = Message(message.contentType, data)

            return old_send(new_message, padding)

        state.msg_sock._recordSocket.send = new_send

        return msg

    generator.generate = new_generate
    post_send_msg_sock_restore(generator, '._recordSocket.send', 'old_send')
    return generator


def div_ceil(divident, divisor):
    """Perform integer division of divident by divisor, round up."""
    quotient, reminder = divmod(divident, divisor)
    return quotient + int(bool(reminder))


def fuzz_padding(generator, min_length=None, substitutions=None, xors=None):
    """
    Change the padding of the message.

    the min_length specifies the minimum length of the padding created,
    including the byte specifying length of padding

    substitutions and xors are dicionaries the specify the values to which
    the padding should be set, note that the "-1" position is the byte with
    length of padding while "-2" is the last byte of padding (if padding
    has non-zero length)
    """
    if min_length is not None and min_length >= 256:
        raise ValueError("Padding cannot be longer than 255 bytes")

    def new_generate(state, self=generator,
                     old_generate=generator.generate,
                     substitutions=substitutions,
                     xors=xors):
        """Monkey patch to modify padding behaviour."""
        msg = old_generate(state)

        self.old_add_padding = state.msg_sock.addPadding

        def new_add_padding(data, self=state.msg_sock,
                            old_add_padding=self.old_add_padding,
                            substitutions=substitutions,
                            xors=xors):
            """Monkey patch the padding creating method."""
            if min_length is None:
                # make a copy of data as we need it unmodified later
                padded_data = old_add_padding(bytearray(data))
                padding_length = padded_data[-1]
                padding = padded_data[-(padding_length+1):]
            else:
                block_size = self.blockSize
                padding_length = div_ceil(len(data) + min_length,
                                          block_size) * block_size - len(data)
                if padding_length > 256:
                    raise ValueError("min_length set too "
                                     "high for message: {0}"
                                     .format(padding_length))
                padding = bytearray([padding_length - 1] * (padding_length))

            padding = substitute_and_xor(padding, substitutions, xors)

            return data + padding

        state.msg_sock.addPadding = new_add_padding

        return msg

    generator.generate = new_generate

    post_send_msg_sock_restore(generator, 'addPadding', 'old_add_padding')

    return generator


def replace_plaintext(generator, new_plaintext):
    """
    Change the plaintext of the message right before encryption.

    Will replace all data before encryption, including the IV, MAC and
    padding.

    Note: works only with CBC ciphers. in EtM mode will NOT modify MAC.

    Length of new_plaintext must be multiple of negotiated cipher block size
    (8 bytes for 3DES, 16 bytes for AES)
    """
    def new_generate(state, self=generator,
                     old_generate=generator.generate,
                     new_plaintext=new_plaintext):
        """Monkey patch to modify padding behaviour."""
        msg = old_generate(state)

        self.old_add_padding = state.msg_sock.addPadding

        def new_add_padding(data,
                            old_add_padding=self.old_add_padding,
                            self=state.msg_sock,
                            new_plaintext=new_plaintext):
            """Monkey patch the padding creating method."""
            del data
            del old_add_padding
            block_size = self.blockSize
            if len(new_plaintext) % block_size:
                raise ValueError("new_plaintext length not a multiple of "
                                 "cipher block size")
            return new_plaintext

        state.msg_sock.addPadding = new_add_padding

        return msg

    generator.generate = new_generate

    post_send_msg_sock_restore(generator, 'addPadding', 'old_add_padding')

    return generator


def fuzz_plaintext(generator, substitutions=None, xors=None):
    """
    Change arbitrary bytes of the plaintext right before encryption.

    Get access to all data before encryption, including the IV, MAC and
    padding.

    Note: works only with CBC ciphers. in EtM mode will not include MAC.

    substitutions and xors are dictionaries that specify the values to which
    the plaintext should be set, note that the "-1" position is the byte with
    length of padding while "-2" is the last byte of padding (if padding
    has non-zero length)
    """
    def new_generate(state, self=generator,
                     old_generate=generator.generate,
                     substitutions=substitutions,
                     xors=xors):
        """Monkey patch to modify padding behaviour."""
        msg = old_generate(state)

        self.old_add_padding = state.msg_sock.addPadding

        def new_add_padding(data,
                            old_add_padding=self.old_add_padding,
                            substitutions=substitutions,
                            xors=xors):
            """Monkey patch the padding creating method."""
            data = old_add_padding(data)

            data = substitute_and_xor(data, substitutions, xors)

            return data

        state.msg_sock.addPadding = new_add_padding

        return msg

    generator.generate = new_generate

    post_send_msg_sock_restore(generator, 'addPadding', 'old_add_padding')

    return generator


def split_message(generator, fragment_list, size):
    """
    Split a given message type to multiple messages.

    Allows for splicing message into the middle of a different message type
    """
    def new_generate(state, old_generate=generator.generate,
                     fragment_list=fragment_list, size=size):
        """Monkey patch for the generate method of the message generator."""
        msg = old_generate(state)
        content_type = msg.contentType
        data = msg.write()
        # since empty messages can be created much more easily with
        # RawMessageGenerator, we don't handle 0 length messages here
        while len(data) > 0:
            # move the data to fragment_list (outside the method)
            fragment_list.append(Message(content_type, data[:size]))
            data = data[size:]

        return fragment_list.pop(0)

    generator.generate = new_generate
    return generator


class PopMessageFromList(MessageGenerator):
    """Takes a reference to list, pops a message from it to generate one."""

    def __init__(self, fragment_list):
        """Link a list to store messages with the object."""
        super(PopMessageFromList, self).__init__()
        self.fragment_list = fragment_list

    def generate(self, state):
        """Create a message using the reference to list from init."""
        msg = self.fragment_list.pop(0)
        return msg


class FlushMessageList(MessageGenerator):
    """Takes a reference to list, empties it to generate a message."""

    def __init__(self, fragment_list):
        """Link a list to pull the messages from to the object."""
        super(FlushMessageList, self).__init__()
        self.fragment_list = fragment_list

    def generate(self, state):
        """Creata a single message to empty the list."""
        msg = self.fragment_list.pop(0)
        content_type = msg.contentType
        data = msg.write()
        while len(self.fragment_list) > 0:
            msg_frag = self.fragment_list.pop(0)
            assert msg_frag.contentType == content_type
            data += msg_frag.write()
        msg_ret = Message(content_type, data)
        return msg_ret


def fuzz_pkcs1_padding(key, substitutions=None, xors=None):
    """
    Fuzz the PKCS#1 padding used in signatures or encryption.

    Use to modify Client Key Exchange padding of encrypted value.
    """
    if not xors and not substitutions:
        return key

    def new_addPKCS1Padding(bytes, blockType, self=key,
                            old_add_padding=key._addPKCS1Padding,
                            substitutions=substitutions, xors=xors):
        """Monkey patch for the _addPKCS1Padding() method of RSA key."""
        ret = old_add_padding(bytes, blockType)
        pad_length = numBytes(self.n) - len(bytes)
        pad = ret[:pad_length]
        value = ret[pad_length:]
        pad = substitute_and_xor(pad, substitutions, xors)
        return pad + value

    key._addPKCS1Padding = new_addPKCS1Padding
    return key
