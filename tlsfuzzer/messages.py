# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Set of object for generating TLS messages to send"""

from tlslite.messages import ClientHello, ClientKeyExchange, ChangeCipherSpec,\
        Finished, Alert, ApplicationData, Message, Certificate, \
        CertificateVerify, CertificateRequest, ClientMasterKey, \
        ClientFinished
from tlslite.constants import AlertLevel, AlertDescription, ContentType, \
        ExtensionType, CertificateType, ClientCertificateType, HashAlgorithm, \
        SignatureAlgorithm, CipherSuite
from tlslite.extensions import TLSExtension
from tlslite.messagesocket import MessageSocket
from tlslite.defragmenter import Defragmenter
from tlslite.mathtls import calcMasterSecret, calcFinished, \
        calcExtendedMasterSecret
from tlslite.handshakehashes import HandshakeHashes
from tlslite.utils.codec import Writer
from tlslite.utils.cryptomath import getRandomBytes
from tlslite.keyexchange import KeyExchange
from .handshake_helpers import calc_pending_states
from .tree import TreeNode
import socket

# TODO move the following to tlslite proper
class RenegotiationInfoExtension(TLSExtension):

    """Implementation of the Renegotiation Info extension

    Handling of the Secure Renegotiation extension from RFC 5746
    """

    def __init__(self):
        self.renegotiated_connection = None
        self.serverType = False

    @property
    def extType(self):
        """Return the extension type, 0xff01"""
        return ExtensionType.renegotiation_info

    @property
    def extData(self):
        """Return the extension payload"""
        if self.renegotiated_connection is None:
            return bytearray(0)

        writer = Writer()
        writer.addVarSeq(self.renegotiated_connection, 1, 1)

        return writer.bytes

    def create(self, renegotiated_connection=None):
        """Set the payload of the extension"""
        self.renegotiated_connection = renegotiated_connection
        return self

    def parse(self, parser):
        """Parse the extension from on the wire data"""
        self.renegotiated_connection = parser.getVarBytes(1)
        return self

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

    def __init__(self, hostname, port, version=(3, 0)):
        """Provide minimal settings needed to connect to other peer"""
        super(Connect, self).__init__()
        self.hostname = hostname
        self.port = port
        self.version = version

    def process(self, state):
        """Connect to a server"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((self.hostname, self.port))

        defragmenter = Defragmenter()
        defragmenter.addStaticSize(ContentType.alert, 2)
        defragmenter.addStaticSize(ContentType.change_cipher_spec, 1)
        defragmenter.addDynamicSize(ContentType.handshake, 1, 3)

        state.msg_sock = MessageSocket(sock, defragmenter)

        state.msg_sock.version = self.version

class Close(Command):

    """Object used to close a TCP connection"""

    def __init__(self):
        super(Close, self).__init__()

    def process(self, state):
        """Close currently open connection"""
        state.msg_sock.sock.close()

class ResetHandshakeHashes(Command):

    """Object used to reset current state of handshake hashes to zero"""

    def __init__(self):
        super(ResetHandshakeHashes, self).__init__()

    def process(self, state):
        """Reset current running handshake protocol hashes"""
        state.handshake_hashes = HandshakeHashes()

class ResetRenegotiationInfo(Command):
    """Object used to reset state of data needed for secure renegotiation"""

    def __init__(self, client=None, server=None):
        super(ResetRenegotiationInfo, self).__init__()
        self.client_verify_data = client
        self.server_verify_data = server

    def process(self, state):
        """Reset current Finished message values"""
        if self.client_verify_data is None:
            self.client_verify_data = bytearray(0)
        if self.server_verify_data is None:
            self.server_verify_data = bytearray(0)
        state.client_verify_data = self.client_verify_data
        state.server_verify_data = self.server_verify_data

class SetMaxRecordSize(Command):

    """Change the Record Layer to send records of non standard size"""

    def __init__(self, max_size=None):
        """Set the maximum record layer message size, no option for default"""
        super(SetMaxRecordSize, self).__init__()
        self.max_size = max_size

    def process(self, state):
        """Change the size of messages in record layer"""
        if self.max_size is None:
            # the maximum for SSLv3, TLS1.0, TLS1.1 and TLS1.2
            state.msg_sock.recordSize = 2**14
        else:
            state.msg_sock.recordSize = self.max_size

class MessageGenerator(TreeNode):

    """Message generator objects"""

    def __init__(self):
        super(MessageGenerator, self).__init__()
        self.msg = None

    def is_command(self):
        """Define object as a generator node"""
        return False

    def is_expect(self):
        """Define object as a generator node"""
        return False

    def is_generator(self):
        """Define object as a generator node"""
        return True

    def generate(self, state):
        """Return a message ready to write to socket"""
        raise NotImplementedError("Subclasses need to implement this!")

    def post_send(self, state):
        """Modify the state after sending the message"""
        # since most messages don't require any post-send modifications
        # create a no-op default action
        pass

class RawMessageGenerator(MessageGenerator):

    """Generator for arbitrary record layer messages"""

    def __init__(self, content_type, data, description=None):
        """Set the record layer type and payload to send"""
        super(RawMessageGenerator, self).__init__()
        self.content_type = content_type
        self.data = data
        self.description = description

    def generate(self, state):
        """Create a tlslite-ng message that can be send"""
        message = Message(self.content_type, self.data)
        return message

    def __repr__(self):
        if self.description is None:
            return "RawMessageGenerator(content_type={0!s}, data={1!r})".\
                   format(self.content_type, self.data)
        else:
            return "RawMessageGenerator(content_type={0!s}, data={1!r}, " \
                   "description={2!r})".format(self.content_type, self.data,
                                               self.description)

class HandshakeProtocolMessageGenerator(MessageGenerator):

    """Message generator for TLS Handshake protocol messages"""

    def post_send(self, state):
        """Update handshake hashes after sending"""
        super(HandshakeProtocolMessageGenerator, self).post_send(state)

        state.handshake_hashes.update(self.msg.write())
        state.handshake_messages.append(self.msg)

class ClientHelloGenerator(HandshakeProtocolMessageGenerator):

    """Generator for TLS handshake protocol Client Hello messages"""

    def __init__(self, ciphers=None, extensions=None, version=None,
                 session_id=None, random=None, compression=None, ssl2=False):
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
        """Convert extension generators to extension objects"""
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
                ext = RenegotiationInfoExtension().create(state.client_verify_data)
                extensions.append(ext)
            else:
                extensions.append(TLSExtension().create(ext_id, bytearray(0)))

        return extensions

    def generate(self, state):
        if self.version is None:
            self.version = state.client_version
        if self.random:
            state.client_random = self.random
        if self.session_id is None:
            self.session_id = state.session_id
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
    Generator for TLS handshake protocol Client Key Exchange messages

    @type dh_Yc: int
    @ivar dh_Yc: Override the sent dh_Yc value to the specified one
    """

    def __init__(self, cipher=None, version=None, client_version=None,
                 dh_Yc=None):
        super(ClientKeyExchangeGenerator, self).__init__()
        self.cipher = cipher
        self.version = version
        self.client_version = client_version
        self.premaster_secret = bytearray(48)
        self.dh_Yc = dh_Yc

    def generate(self, status):
        if self.version is None:
            self.version = status.version

        if self.cipher is None:
            self.cipher = status.cipher

        if self.client_version is None:
            self.client_version = status.client_version

        cke = ClientKeyExchange(self.cipher, self.version)
        if self.cipher in CipherSuite.certSuites:
            assert len(self.premaster_secret) > 1

            self.premaster_secret[0] = self.client_version[0]
            self.premaster_secret[1] = self.client_version[1]

            status.premaster_secret = self.premaster_secret

            public_key = status.get_server_public_key()

            cke.createRSA(public_key.encrypt(self.premaster_secret))
        elif self.cipher in CipherSuite.dheCertSuites:
            if self.dh_Yc is not None:
                cke = ClientKeyExchange(self.cipher,
                                        self.version).createDH(self.dh_Yc)
            else:
                cke = status.key_exchange.makeClientKeyExchange()
        else:
            raise AssertionError("Unknown cipher/key exchange type")

        self.msg = cke

        return cke

class ClientMasterKeyGenerator(HandshakeProtocolMessageGenerator):
    """Generator for SSLv2 Handshake Protocol CLIENT-MASTER-KEY message"""

    def __init__(self, cipher=None, master_key=None):
        super(ClientMasterKeyGenerator, self).__init__()
        self.cipher = cipher
        self.master_key = master_key

    def generate(self, state):
        """Generate a new CLIENT-MASTER-KEY message"""
        if self.cipher is None:
            raise NotImplementedError("No cipher autonegotiation")
        if self.master_key is None:
            if state.master_secret == bytearray(0):
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
                self.master_key = state.master_secret

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
    """Generator for TLS handshake protocol Certificate message"""

    def __init__(self, certs=None, cert_type=None):
        super(CertificateGenerator, self).__init__()
        self.certs = certs
        self.cert_type = cert_type

    def generate(self, status):
        """Create a Certificate message"""
        del status # unused
        # TODO: support client certs
        if self.cert_type is None:
            self.cert_type = CertificateType.x509
        cert = Certificate(self.cert_type)
        cert.create(self.certs)

        self.msg = cert
        return cert

class CertificateVerifyGenerator(HandshakeProtocolMessageGenerator):
    """Generator for TLS handshake protocol Certificate Verify message"""

    def __init__(self, private_key=None, sig_type=None, version=None):
        super(CertificateVerifyGenerator, self).__init__()
        self.private_key = private_key
        self.sig_type = sig_type
        self.version = version

    def generate(self, status):
        """Create a CertificateVerify message"""
        if self.version is None:
            self.version = status.version
        if self.sig_type is None and self.version >= (3, 3):
            cert_req = next((msg for msg in status.handshake_messages[::-1]
                             if isinstance(msg, CertificateRequest)), None)
            if cert_req is not None:
                self.sig_type = next((sig for sig in
                                      cert_req.supported_signature_algs
                                      if sig[1] == SignatureAlgorithm.rsa),
                                     None)
            if self.sig_type is None:
                self.sig_type = (HashAlgorithm.sha1,
                                 SignatureAlgorithm.rsa)
        # TODO: generate a random key if none provided
        if self.private_key is None:
            raise ValueError("Can't create a signature without private key!")

        verify_bytes = KeyExchange.calcVerifyBytes(status.version,
                                                   status.handshake_hashes,
                                                   self.sig_type,
                                                   status.premaster_secret,
                                                   status.client_random,
                                                   status.server_random)
        signature = self.private_key.sign(verify_bytes)

        cert_verify = CertificateVerify(status.version)
        cert_verify.create(signature, self.sig_type)

        self.msg = cert_verify
        return cert_verify

class ChangeCipherSpecGenerator(MessageGenerator):
    """Generator for TLS Change Cipher Spec messages"""

    def __init__(self, extended_master_secret=None):
        super(ChangeCipherSpecGenerator, self).__init__()
        self.extended_master_secret = extended_master_secret

    def generate(self, status):
        ccs = ChangeCipherSpec()
        return ccs

    def post_send(self, status):
        cipher_suite = status.cipher
        if self.extended_master_secret is None:
            self.extended_master_secret = status.extended_master_secret

        if not status.resuming:
            if self.extended_master_secret:
                master_secret = \
                    calcExtendedMasterSecret(status.version,
                                             cipher_suite,
                                             status.premaster_secret,
                                             status.handshake_hashes)
            else:
                master_secret = calcMasterSecret(status.version,
                                                 cipher_suite,
                                                 status.premaster_secret,
                                                 status.client_random,
                                                 status.server_random)

            status.master_secret = master_secret

            # in case of resumption, the pending states are generated
            # during receive of server sent CCS
            calc_pending_states(status)

        status.msg_sock.changeWriteState()

class FinishedGenerator(HandshakeProtocolMessageGenerator):

    """Generator for TLS handshake protocol Finished messages"""

    def __init__(self, protocol=None):
        super(FinishedGenerator, self).__init__()
        self.protocol = protocol

    def generate(self, status):
        """Create a Finished message"""
        if self.protocol is None:
            self.protocol = status.version

        if self.protocol in ((0, 2), (2, 0)):
            finished = ClientFinished()
            verify_data = status.session_id

            # in SSLv2 we're using it as a CCS-of-sorts too
            status.msg_sock.changeWriteState()
            status.msg_sock.changeReadState()
        else:
            finished = Finished(self.protocol)
            verify_data = calcFinished(status.version,
                                       status.master_secret,
                                       status.cipher,
                                       status.handshake_hashes,
                                       status.client)

            status.client_verify_data = verify_data

        finished.create(verify_data)

        self.msg = finished

        return finished

    def post_send(self, status):
        """Perform post-transmit changes needed by generation of Finished"""
        super(FinishedGenerator, self).post_send(status)

        # resumption finished
        if status.resuming:
            status.resuming = False

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

def pad_handshake(generator, size=0, pad_byte=0, pad=None):
    """Pad or truncate handshake messages

    Pad or truncate a handshake message by given amount of bytes, use negative
    to size to truncate"""

    def new_generate(state, old_generate=generator.generate):
        """Monkey patch for the generate method of the Handshake generators"""
        msg = old_generate(state)

        def post_write(writer, self=msg, size=size, pad_byte=pad_byte, pad=pad):
            """Monkey patch for the postWrite of handshake messages"""
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
    """Truncate a handshake message"""
    return pad_handshake(generator, -size, pad_byte)

def substitute_and_xor(data, substitutions, xors):
    """Apply changes from substitutions and xors to data for fuzzing"""
    if substitutions is not None:
        for pos in substitutions:
            data[pos] = substitutions[pos]

    if xors is not None:
        for pos in xors:
            data[pos] ^= xors[pos]

    return data

def fuzz_message(generator, substitutions=None, xors=None):
    """Change arbitrary bytes of the message after write"""
    def new_generate(state, old_generate=generator.generate):
        """Monkey patch for the generate method of the Handshake generators"""
        msg = old_generate(state)

        def new_write(old_write=msg.write, substitutions=substitutions,
                      xors=xors):
            """Monkey patch for the write method of messages"""
            data = old_write()

            data = substitute_and_xor(data, substitutions, xors)

            return data

        msg.write = new_write
        return msg

    generator.generate = new_generate
    return generator

def post_send_msg_sock_restore(obj, method_name, old_method_name):
    """Un-Monkey patch a method of msg_sock"""
    def new_post_send(state, obj=obj,
                      method_name=method_name,
                      old_method_name=old_method_name,
                      old_post_send=obj.post_send):
        """Reverse the patching of a method in msg_sock"""
        setattr(state.msg_sock, method_name, getattr(obj, old_method_name))
        old_post_send(state)
    obj.post_send = new_post_send
    return obj

def fuzz_mac(generator, substitutions=None, xors=None):
    """Change arbitrary bytes of the MAC value"""
    def new_generate(state, self=generator,
                     old_generate=generator.generate,
                     substitutions=substitutions,
                     xors=xors):
        """Monkey patch to modify MAC calculation of created MAC"""
        msg = old_generate(state)

        old_calculate_mac = state.msg_sock.calculateMAC

        self.old_calculate_mac = old_calculate_mac

        def new_calculate_mac(mac, seqnumBytes, contentType, data,
                              old_calculate_mac=old_calculate_mac,
                              substitutions=substitutions,
                              xors=xors):
            """Monkey patch for the MAC calculation method of msg socket"""
            mac_bytes = old_calculate_mac(mac, seqnumBytes, contentType, data)

            mac_bytes = substitute_and_xor(mac_bytes, substitutions, xors)

            return mac_bytes

        state.msg_sock.calculateMAC = new_calculate_mac

        return msg

    generator.generate = new_generate

    post_send_msg_sock_restore(generator, 'calculateMAC', 'old_calculate_mac')

    return generator

def div_ceil(divident, divisor):
    """Perform integer division of divident by divisor, round up"""
    quotient, reminder = divmod(divident, divisor)
    return quotient + int(bool(reminder))

def fuzz_padding(generator, min_length=None, substitutions=None, xors=None):
    """Change the padding of the message

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
        """Monkey patch to modify padding behaviour"""
        msg = old_generate(state)

        self.old_add_padding = state.msg_sock.addPadding

        def new_add_padding(data, self=state.msg_sock,
                            old_add_padding=self.old_add_padding,
                            substitutions=substitutions,
                            xors=xors):
            """Monkey patch the padding creating method"""
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
                    raise ValueError("min_length set too high for message: {0}"\
                            .format(padding_length))
                padding = bytearray([padding_length - 1] * (padding_length))

            padding = substitute_and_xor(padding, substitutions, xors)

            return data + padding

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
        """Monkey patch to modify padding behaviour"""
        msg = old_generate(state)

        self.old_add_padding = state.msg_sock.addPadding

        def new_add_padding(data,
                            old_add_padding=self.old_add_padding,
                            substitutions=substitutions,
                            xors=xors):
            """Monkey patch the padding creating method"""
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
    Split a given message type to multiple messages

    Allows for splicing message into the middle of a different message type
    """
    def new_generate(state, old_generate=generator.generate,
                     fragment_list=fragment_list, size=size):
        """Monkey patch for the generate method of the message generator"""
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

    """Takes a reference to list, pops a message from it to generate one"""

    def __init__(self, fragment_list):
        super(PopMessageFromList, self).__init__()
        self.fragment_list = fragment_list

    def generate(self, state):
        """Create a message using the reference to list from init"""
        msg = self.fragment_list.pop(0)
        return msg

class FlushMessageList(MessageGenerator):

    """Takes a reference to list, empties it to generate a message"""

    def __init__(self, fragment_list):
        super(FlushMessageList, self).__init__()
        self.fragment_list = fragment_list

    def generate(self, state):
        """Creata a single message to empty the list"""
        msg = self.fragment_list.pop(0)
        content_type = msg.contentType
        data = msg.write()
        while len(self.fragment_list) > 0:
            msg_frag = self.fragment_list.pop(0)
            assert msg_frag.contentType == content_type
            data += msg_frag.write()
        msg_ret = Message(content_type, data)
        return msg_ret
