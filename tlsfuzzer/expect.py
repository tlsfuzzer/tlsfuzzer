# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Parsing and processing of received TLS messages"""
from __future__ import print_function

import collections
import itertools
from functools import partial
import sys
import time

import tlslite.utils.tlshashlib as hashlib
from tlslite.constants import ContentType, HandshakeType, CertificateType,\
        HashAlgorithm, SignatureAlgorithm, ExtensionType,\
        SSL2HandshakeType, CipherSuite, GroupName, AlertDescription, \
        SignatureScheme, TLS_1_3_HRR, HeartbeatMode, \
        TLS_1_1_DOWNGRADE_SENTINEL, TLS_1_2_DOWNGRADE_SENTINEL
from tlslite.messages import ServerHello, Certificate, ServerHelloDone,\
        ChangeCipherSpec, Finished, Alert, CertificateRequest, ServerHello2,\
        ServerKeyExchange, ClientHello, ServerFinished, CertificateStatus, \
        CertificateVerify, EncryptedExtensions, NewSessionTicket
from tlslite.extensions import TLSExtension, ALPNExtension
from tlslite.utils.codec import Parser, Writer
from tlslite.utils.compat import b2a_hex
from tlslite.utils.cryptomath import secureHMAC, derive_secret, \
        HKDF_expand_label
from tlslite.mathtls import calcFinished, RFC7919_GROUPS
from tlslite.keyexchange import KeyExchange, DHE_RSAKeyExchange, \
        ECDHE_RSAKeyExchange
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.errors import TLSDecryptionFailed
from tlslite.handshakehashes import HandshakeHashes
from tlslite.handshakehelpers import HandshakeHelpers
from .handshake_helpers import calc_pending_states, kex_for_group
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
        parsing the message by inheriting classes
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


def srv_ext_handler_ems(state, extension):
    """Process Extended Master Secret extension from server."""
    if extension.extData:
        raise AssertionError("Malformed EMS extension, data in payload")

    state.extended_master_secret = True


def srv_ext_handler_etm(state, extension):
    """Process Encrypt then MAC extension from server."""
    if extension.extData:
        raise AssertionError("Malformed EtM extension, data in payload")

    state.encrypt_then_mac = True


def srv_ext_handler_sni(state, extension):
    """Process the server_name extension from server."""
    del state  # kept for comatibility
    if extension.extData:
        raise AssertionError("Malformed SNI extenion, data in payload")


def srv_ext_handler_renego(state, extension):
    """Process the renegotiation_info from server."""
    if extension.renegotiated_connection != \
            state.key['client_verify_data'] + state.key['server_verify_data']:
        raise AssertionError("Invalid data in renegotiation_info")


def srv_ext_handler_alpn(state, extension):
    """Process the ALPN extension from server."""
    cln_hello = state.get_last_message_of_type(ClientHello)
    cln_ext = cln_hello.getExtension(ExtensionType.alpn)
    # the sent extension might have been provided with explicit encoding
    cln_ext = ALPNExtension().parse(Parser(cln_ext.extData))

    if not extension.protocol_names or len(extension.protocol_names) != 1:
        raise AssertionError("Malformed ALPN extension")
    if extension.protocol_names[0] not in cln_ext.protocol_names:
        raise AssertionError("Server selected ALPN protocol we did not "
                             "advertise")


def srv_ext_handler_ec_point(state, extension):
    """Process the ec_point_formats extension from server."""
    del state
    if extension.formats is None or not extension.formats:
        raise AssertionError("Malformed ec_point_formats extension")


def srv_ext_handler_npn(state, extension):
    """Process the NPN extension from server."""
    del state
    if extension.protocols is None or not extension.protocols:
        raise AssertionError("Malformed NPN extension")


def srv_ext_handler_key_share(state, extension):
    """Process the key_share extension from server."""
    cln_hello = state.get_last_message_of_type(ClientHello)
    cln_ext = cln_hello.getExtension(ExtensionType.key_share)

    group_id = extension.server_share.group

    cl_ext = next((i for i in cln_ext.client_shares if i.group == group_id),
                  None)
    if cl_ext is None:
        raise AssertionError("Server selected group we didn't advertise: {0}"
                             .format(GroupName.toStr(group_id)))

    kex = kex_for_group(group_id, state.version)

    state.key['ServerHello.extensions.key_share.key_exchange'] = \
        extension.server_share.key_exchange

    if not cl_ext.private:
        raise ValueError("private value for key share of group {0} missing"
                         .format(GroupName.toStr(group_id)))
    z = kex.calc_shared_key(cl_ext.private,
                            extension.server_share.key_exchange)

    state.key['DH shared secret'] = z


def hrr_ext_handler_key_share(state, extension):
    """Process the key_share extension in HRR message."""
    cln_hello = state.get_last_message_of_type(ClientHello)
    cln_ext = cln_hello.getExtension(ExtensionType.supported_groups)

    group_id = extension.selected_group

    if group_id not in cln_ext.groups:
        raise AssertionError("Server selected group we didn't advertise: {0}"
                             .format(GroupName.toStr(group_id)))


def hrr_ext_handler_cookie(state, extension):
    """Process the cookie extension in HRR message."""
    del state
    if not extension.cookie:
        raise AssertionError("Server sent empty cookie extension")


def srv_ext_handler_supp_vers(state, extension):
    """Process the supported_versions from server."""
    cln_hello = state.get_last_message_of_type(ClientHello)
    cln_ext = cln_hello.getExtension(ExtensionType.supported_versions)

    vers = extension.version

    if vers not in cln_ext.versions:
        raise AssertionError("Server selected version we didn't advertise: {0}"
                             .format(vers))

    state.version = vers


def srv_ext_handler_supp_groups(state, extension):
    """Process the supported_groups from server."""
    del state
    if not extension.groups:
        raise AssertionError("Server did not send any supported_groups")


def srv_ext_handler_status_request(state, extension):
    """
    Process the status_request extension from server.

    TLS 1.2 ServerHello specific, in TLS 1.3 the extension resides in
    Certificate message.
    """
    del state
    if extension.status_type is not None or \
            extension.responder_id_list != [] or \
            extension.request_extensions != bytearray():
        raise AssertionError("Server did send non empty status_request "
                             "extension")


def srv_ext_handler_heartbeat(state, extension):
    """Process the heartbeat extension from server."""
    del state
    if not extension.mode:
        raise AssertionError("Empty mode in heartbeat extension.")
    if extension.mode != HeartbeatMode.PEER_ALLOWED_TO_SEND and \
       extension.mode != HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND:
        raise AssertionError("Invalid mode in heartbeat extension.")


def _srv_ext_handler_psk(state, extension, psk_configs):
    """Process the pre_shared_key extension from server.

    Since it needs the psk_configurations, it can't do it automatically
    so it shouldn't be part of _srv_ext_handler.
    """
    cln_hello = state.get_last_message_of_type(ClientHello)
    cln_ext = cln_hello.getExtension(ExtensionType.pre_shared_key)

    # the selection is 0-based
    if extension.selected >= len(cln_ext.identities):
        raise AssertionError("Server selected PSK we didn't send")

    ident = cln_ext.identities[extension.selected].identity
    if state.session_tickets:
        nst = state.session_tickets[-1]
        if nst.ticket == ident:
            state.key['PSK secret'] = HandshakeHelpers.calc_res_binder_psk(
                cln_ext.identities[extension.selected],
                state.key['resumption master secret'],
                [nst])
            return
    secret = next((i[1] for i in psk_configs if i[0] == ident), None)
    if not secret:
        raise ValueError("psk_configs are missing identity")

    state.key['PSK secret'] = secret


def gen_srv_ext_handler_psk(psk_configs=tuple()):
    """Creates a handler for pre_shared_key extension from the server."""
    return partial(_srv_ext_handler_psk, psk_configs=psk_configs)


def _srv_ext_handler_record_limit(state, extension, size=None):
    """Process record_size_limit extension from server."""
    cln_hello = state.get_last_message_of_type(ClientHello)
    cln_ext = cln_hello.getExtension(ExtensionType.record_size_limit)

    assert extension.record_size_limit is not None
    assert 64 <= extension.record_size_limit <= 2**14 + \
        int(state.version > (3, 3))

    if size and extension.record_size_limit != size:
        raise AssertionError("Server sent unexpected size in extension, "
                             "expected size: {0}, received size: {1}"
                             .format(size, extension.record_size_limit))

    if state.version <= (3, 3):
        # in TLS 1.2 and earlier we need to delay that to processing of
        # server CCS
        state._peer_record_size_limit = extension.record_size_limit
        state._our_record_size_limit = min(2**14, cln_ext.record_size_limit)
    else:
        # in TLS 1.3 we need to implement it right away (as the extension
        # applies only to encrypted messages)
        # the RecordLayer expects value that excludes content type
        state.msg_sock.recv_record_limit = min(
            2**14,
            cln_ext.record_size_limit-1)
        # this is just hint for padding callback
        state.msg_sock.send_record_limit = min(
            2**14,
            extension.record_size_limit-1)
        # this guides fragmentation
        state.msg_sock.recordSize = state.msg_sock.send_record_limit


def gen_srv_ext_handler_record_limit(size=None):
    """
    Create a handler for record_size_limit_extension from the server.

    Note that if the extension is actually negotiated, it will override
    any SetMaxRecordSize() before EncryptedExtensions in TLS 1.3 and
    before ChangeCipherSpec in TLS 1.2 and earlier.

    :param int size: expected value from server, None for any valid
    """
    return partial(_srv_ext_handler_record_limit, size=size)


_srv_ext_handler = \
        {ExtensionType.extended_master_secret: srv_ext_handler_ems,
         ExtensionType.encrypt_then_mac: srv_ext_handler_etm,
         ExtensionType.server_name: srv_ext_handler_sni,
         ExtensionType.renegotiation_info: srv_ext_handler_renego,
         ExtensionType.alpn: srv_ext_handler_alpn,
         ExtensionType.ec_point_formats: srv_ext_handler_ec_point,
         ExtensionType.supports_npn: srv_ext_handler_npn,
         ExtensionType.key_share: srv_ext_handler_key_share,
         ExtensionType.supported_versions: srv_ext_handler_supp_vers,
         ExtensionType.heartbeat: srv_ext_handler_heartbeat,
         ExtensionType.record_size_limit: _srv_ext_handler_record_limit,
         ExtensionType.status_request: srv_ext_handler_status_request}


_HRR_EXT_HANDLER = \
        {ExtensionType.key_share: hrr_ext_handler_key_share,
         ExtensionType.cookie: hrr_ext_handler_cookie}


_EE_EXT_HANDLER = \
        {ExtensionType.server_name: srv_ext_handler_sni,
         ExtensionType.alpn: srv_ext_handler_alpn,
         ExtensionType.supported_groups: srv_ext_handler_supp_groups,
         ExtensionType.heartbeat: srv_ext_handler_heartbeat,
         ExtensionType.record_size_limit: _srv_ext_handler_record_limit}


class ExpectServerHello(ExpectHandshake):
    """
    Parsing TLS Handshake protocol Server Hello messages.

    @note: Receiving of the ServerHello in TLS 1.3 influences record layer
    encryption. After the message is received, the
    C{client_handshake_traffic_secret} and C{server_handshake_traffic_secret}
    is derived and record layer is configured to expect encrypted records
    on the I{receiving} side.
    """

    def __init__(self, extensions=None, version=None, resume=False,
                 cipher=None, server_max_protocol=None):
        """
        Initialize the object

        @param dict extensions: extension objects to match the server sent
        extensions or callbacks to process and verify them. None means use
        automatic handlers that will verify the response against the extensions
        sent in ClientHello. Empty dict means that the server is expected to
        send no extensions. Order does not matter, but all extensions present
        and only extensions present in the list must be sent by server. None
        as the value of the relevant extension type can be used to select
        autohandler for a given extension type.

        @param tuple version: the literal version in the Server Hello message
        (needs to be (3, 3) for TLS 1.3, use extensions to expect TLS 1.3
        negotiation)

        @param tuple server_max_protocol: the higher protocol version supported
        by server. Used for testing downgrade signaling of servers.

        @param int cipher: the id of the cipher that is expected to be
        negotiated by server. None (the default) means any valid cipher
        (i.e. not SCSV or GREASE) sent in ClientHello can be selected by
        server.

        @type resume: boolean
        @param resume: whether the session id should match the one from
        current state - IOW, if the server hello should belong to a resumed
        session. TLS 1.2 and earlier only. In TLS 1.3 resumption is handled
        by providing handler for pre_shared_key extension.
        """
        super(ExpectServerHello, self).__init__(ContentType.handshake,
                                                HandshakeType.server_hello)
        self.cipher = cipher
        self.extensions = extensions
        self.version = version
        self.resume = resume
        self.srv_max_prot = server_max_protocol

    def _compare_extensions(self, srv_hello):
        """
        Verify that server provided extensions match exactly expected list.
        """
        # if the list of extensions is present, make sure it matches exactly
        # with what the server sent
        if self.extensions and not srv_hello.extensions:
            raise AssertionError("Server did not send any extensions")
        elif self.extensions is not None and srv_hello.extensions:
            expected = set(self.extensions.keys())
            got = set(i.extType for i in srv_hello.extensions)
            if got != expected:
                diff = expected.difference(got)
                if diff:
                    raise AssertionError("Server did not send extension(s): "
                                         "{0}".format(
                                             ", ".join((ExtensionType.toStr(i)
                                                        for i in diff))))
                diff = got.difference(expected)
                # we already checked if got != expected so diff here
                # must be non-empty if the one checked above is
                assert diff
                raise AssertionError("Server sent unexpected extension(s):"
                                     " {0}".format(
                                         ", ".join(ExtensionType.toStr(i)
                                                   for i in diff)))

    @staticmethod
    def _get_autohandler(ext_id):
        try:
            return _srv_ext_handler[ext_id]
        except KeyError:
            raise AssertionError("No autohandler for "
                                 "{0}"
                                 .format(ExtensionType
                                         .toStr(ext_id)))

    def _process_extensions(self, state, cln_hello, srv_hello):
        """Check if extensions are correct."""
        # extensions allowed in TLS 1.3 ServerHello and HelloRetryRequest
        # messages (as some need to be echoed by server in EncryptedExtensions
        # and some in Certificate)
        sh_supported = [ExtensionType.pre_shared_key,
                        ExtensionType.supported_versions,
                        ExtensionType.key_share]
        hrr_supported = [ExtensionType.cookie,
                         ExtensionType.supported_versions,
                         ExtensionType.key_share]
        for ext in srv_hello.extensions:
            ext_id = ext.extType
            if state.version > (3, 3) and \
                    ((srv_hello.random != TLS_1_3_HRR and
                      ext_id not in sh_supported) or
                     (srv_hello.random == TLS_1_3_HRR and
                      ext_id not in hrr_supported)):
                raise AssertionError("Server sent unallowed "
                                     "extension of type {0}"
                                     .format(ExtensionType
                                             .toStr(ext_id)))
            # in TLS 1.2 generally the server can reply to any client sent
            # extension, and all of them end in ClientHello
            cl_ext = cln_hello.getExtension(ext_id)
            if ext_id == ExtensionType.renegotiation_info and \
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV \
                    in cln_hello.cipher_suites:
                cl_ext = True
            if isinstance(self, ExpectHelloRetryRequest) and \
                    ext_id == ExtensionType.cookie:
                cl_ext = True
            if cl_ext is None:
                raise AssertionError("Server sent unadvertised "
                                     "extension of type {0}"
                                     .format(ExtensionType
                                             .toStr(ext_id)))
            handler = None
            if self.extensions:
                handler = self.extensions[ext_id]

            # use automatic handlers for some extensions
            if handler is None:
                handler = self._get_autohandler(ext_id)

            if callable(handler):
                handler(state, ext)
            elif isinstance(handler, TLSExtension):
                if not handler == ext:
                    raise AssertionError("Expected extension not "
                                         "matched for type {0}, "
                                         "received: {1}"
                                         .format(ExtensionType
                                                 .toStr(ext_id),
                                                 ext))
            else:
                raise ValueError("Bad extension handler for id {0}"
                                 .format(ExtensionType.toStr(ext_id)))

    @staticmethod
    def _extract_version(msg):
        """Extract the real version from the message if TLS 1.3 is in use."""
        ext = msg.getExtension(ExtensionType.supported_versions)

        # RFC 8446 "legacy_version field MUST be set to 0x0303"
        if msg.server_version > (3, 3):
            raise ValueError("Server sent invalid version in legacy_version "
                             "field")

        if ext and msg.server_version == (3, 3):
            return ext.version

        return msg.server_version

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
                srv_hello.session_id != bytearray(0) and
                self._extract_version(srv_hello) < (3, 4)):
            # TLS 1.2 resumption, TLS 1.3 is based on PSKs
            state.resuming = True
            assert state.cipher == srv_hello.cipher_suite
            assert state.version == self._extract_version(srv_hello)
        state.session_id = srv_hello.session_id

        if self.version is not None:
            assert self.version == srv_hello.server_version

        if self.cipher is not None:
            assert self.cipher == srv_hello.cipher_suite

        # check if server sent cipher matches what we advertised in CH
        cln_hello = state.get_last_message_of_type(ClientHello)
        if srv_hello.cipher_suite not in cln_hello.cipher_suites:
            cipher = srv_hello.cipher_suite
            if cipher in CipherSuite.ietfNames:
                name = "{0} ({1:#06x})".format(CipherSuite.ietfNames[cipher],
                                               cipher)
            else:
                name = "{0:#06x}".format(cipher)
            raise AssertionError("Server responded with cipher we did"
                                 " not advertise: {0}".format(name))

        state.cipher = srv_hello.cipher_suite
        state.version = self._extract_version(srv_hello)

        # update the state of connection
        state.msg_sock.version = state.version
        state.msg_sock.tls13record = state.version > (3, 3)

        self._check_against_hrr(state, srv_hello)

        state.handshake_messages.append(srv_hello)
        state.handshake_hashes.update(msg.write())

        # Reset value of the session-wide settings
        state.extended_master_secret = False
        state.encrypt_then_mac = False

        self._check_downgrade_protection(srv_hello)

        self._compare_extensions(srv_hello)

        if srv_hello.extensions:
            self._process_extensions(state, cln_hello, srv_hello)

        if state.version > (3, 3):
            self._setup_tls13_handshake_keys(state)
        return srv_hello

    @staticmethod
    def _check_against_hrr(state, srv_hello):
        if state.version < (3, 4):
            return

        hrr = state.get_last_message_of_type(ServerHello)
        if not hrr or hrr.random != TLS_1_3_HRR:
            # not an HRR, so HRR tests don't apply to it
            return

        if hrr.cipher_suite != srv_hello.cipher_suite:
            raise AssertionError("Server picked different cipher suite than "
                                 "it advertised in HelloRetryRequest")

        hrr_version = hrr.getExtension(ExtensionType.supported_versions)
        sh_version = srv_hello.getExtension(ExtensionType.supported_versions)

        if hrr_version.version != sh_version.version:
            raise AssertionError("Server picked different protocol version "
                                 "than it advertised in HelloRetryRequest")

    def _setup_tls13_handshake_keys(self, state):
        """Set up the encryption keys for the TLS 1.3 handshake."""
        del self
        prf_name = state.prf_name
        prf_size = state.prf_size

        # Derive PSK secret
        psk = state.key.setdefault('PSK secret', bytearray(prf_size))

        # Derive TLS 1.3 early secret
        secret = bytearray(prf_size)
        secret = secureHMAC(secret, psk, prf_name)
        state.key['early secret'] = secret

        # Derive TLS 1.3 handshake secret
        secret = derive_secret(secret, b'derived', None, prf_name)
        dh_secret = state.key.setdefault('DH shared secret',
                                         bytearray(prf_size))
        secret = secureHMAC(secret, dh_secret, prf_name)
        state.key['handshake secret'] = secret

        # Derive TLS 1.3 traffic secrets
        s_traffic_secret = derive_secret(secret, b's hs traffic',
                                         state.handshake_hashes,
                                         prf_name)
        state.key['server handshake traffic secret'] = s_traffic_secret
        c_traffic_secret = derive_secret(secret, b'c hs traffic',
                                         state.handshake_hashes,
                                         prf_name)
        state.key['client handshake traffic secret'] = c_traffic_secret

        state.msg_sock.calcTLS1_3PendingState(
            state.cipher, c_traffic_secret, s_traffic_secret, None)

        state.msg_sock.changeReadState()

    def _check_downgrade_protection(self, srv_hello):
        """
        Verify that server provided downgrade protection as specified in
        RFC 8446, Section 4.1.3
        """
        # even if we don't know which version server supports, some values
        # are obviously incorrect:
        if (self._extract_version(srv_hello) > (3, 3) and
                srv_hello.random[24:] == TLS_1_2_DOWNGRADE_SENTINEL) or \
                (self._extract_version(srv_hello) > (3, 2) and
                 srv_hello.random[24:] == TLS_1_1_DOWNGRADE_SENTINEL):
            raise AssertionError(
                "Server set downgrade protection sentinel but shouldn't "
                "have done that")
        # as we're doing both TLS 1.2 tests and TLS 1.3 tests with `scripts/`
        # we don't know when setting the sentinel is expected and when
        # it is not as the negotiation might have ended up with TLS 1.2
        # because that was the highest version we advertised
        if self.srv_max_prot is None:
            return

        downgrade_value = None
        if self.srv_max_prot > (3, 3) \
                and self._extract_version(srv_hello) == (3, 3):
            downgrade_value = TLS_1_2_DOWNGRADE_SENTINEL
        elif self.srv_max_prot > (3, 2) \
                and self._extract_version(srv_hello) < (3, 3):
            downgrade_value = TLS_1_1_DOWNGRADE_SENTINEL
        else:
            if srv_hello.random[24:] == TLS_1_1_DOWNGRADE_SENTINEL or \
                srv_hello.random[24:] == TLS_1_2_DOWNGRADE_SENTINEL:
                raise AssertionError(
                    "Server set downgrade protection sentinel but shouldn't "
                    "have done that")

        if downgrade_value is not None:
            if srv_hello.random[24:] != downgrade_value:
                raise AssertionError(
                    "Server failed to set downgrade protection sentinel in "
                    "ServerHello.random value")


class ExpectHelloRetryRequest(ExpectServerHello):
    """Processing of the TLS 1.3 HelloRetryRequest message."""

    def __init__(self, extensions=None, version=None, cipher=None):
        super(ExpectHelloRetryRequest, self).__init__(
            extensions, version, cipher)
        self._ch_hh = None
        self._msg = None

    def process(self, state, msg):
        self._ch_hh = state.handshake_hashes.copy()
        self._msg = msg
        hrr = super(ExpectHelloRetryRequest, self).process(state, msg)
        assert hrr.random == TLS_1_3_HRR

    @staticmethod
    def _get_autohandler(ext_id):
        try:
            return _HRR_EXT_HANDLER[ext_id]
        except KeyError:
            try:
                return _srv_ext_handler[ext_id]
            except KeyError:
                raise AssertionError("No autohandler for {0}".format(
                    ExtensionType.toStr(ext_id)))

    def _setup_tls13_handshake_keys(self, state):
        """Prepare handshake ciphers for the HRR handling"""
        prf_name = state.prf_name

        ch_hash = self._ch_hh.digest(prf_name)
        new_hh = HandshakeHashes()
        writer = Writer()
        writer.add(HandshakeType.message_hash, 1)
        writer.addVarSeq(ch_hash, 1, 3)
        new_hh.update(writer.bytes)

        new_hh.update(self._msg.write())

        state.handshake_hashes = new_hh


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

        cert = Certificate(self.cert_type, state.version)
        cert.parse(parser)

        state.handshake_messages.append(cert)
        state.handshake_hashes.update(msg.write())


class ExpectCertificateVerify(ExpectHandshake):
    """Processing TLS Handshake protocol Certificate Verify messages."""
    def __init__(self, version=None, sig_alg=None):
        super(ExpectCertificateVerify, self).__init__(
            ContentType.handshake,
            HandshakeType.certificate_verify)
        self.version = version
        self.sig_alg = sig_alg

    def process(self, state, msg):
        """
        @type state: ConnectionState
        """
        assert msg.contentType == ContentType.handshake
        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.certificate_verify

        if self.version is None:
            self.version = state.version

        cert_v = CertificateVerify(self.version)
        cert_v.parse(parser)

        if self.sig_alg:
            assert self.sig_alg == cert_v.signatureAlgorithm
        else:
            c_hello = state.get_last_message_of_type(ClientHello)
            ext = c_hello.getExtension(ExtensionType.signature_algorithms)
            assert cert_v.signatureAlgorithm in ext.sigalgs
            if state.get_server_public_key().key_type == "rsa-pss":
                # in TLS 1.3 only RSA-PSS signatures are allowed
                assert cert_v.signatureAlgorithm in (
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.rsa_pss_pss_sha384,
                    SignatureScheme.rsa_pss_pss_sha512)
            elif state.get_server_public_key().key_type == "rsa":
                # in TLS 1.3 only RSA-PSS signatures are allowed
                assert cert_v.signatureAlgorithm in (
                    SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_rsae_sha384,
                    SignatureScheme.rsa_pss_rsae_sha512)

        salg = cert_v.signatureAlgorithm

        scheme = SignatureScheme.toRepr(salg)
        hash_name = SignatureScheme.getHash(scheme)

        transcript_hash = state.handshake_hashes.digest(state.prf_name)
        sig_context = bytearray(b'\x20' * 64 +
                                b'TLS 1.3, server CertificateVerify' +
                                b'\x00') + transcript_hash

        if not state.get_server_public_key().hashAndVerify(
                cert_v.signature,
                sig_context,
                SignatureScheme.getPadding(scheme),
                hash_name,
                getattr(hashlib, hash_name)().digest_size):
            raise AssertionError("Signature verification failed")

        state.handshake_messages.append(cert_v)
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

    def _checkParams(self, server_key_exchange):
        groups = [RFC7919_GROUPS[i - 256] for i in self.valid_groups
                  if i in range(256, 512)]
        if (server_key_exchange.dh_g, server_key_exchange.dh_p) not in groups:
            raise AssertionError("DH parameters not from RFC 7919")

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

        try:
            KeyExchange.verifyServerKeyExchange(server_key_exchange,
                                                public_key,
                                                client_random,
                                                server_random,
                                                valid_sig_algs)
        except TLSDecryptionFailed:
            # very rarely validation of signature fails, print it so that
            # we have a chance in debugging it
            print("Bad signature: {0}"
                  .format(b2a_hex(server_key_exchange.signature)),
                  file=sys.stderr)
            raise

        if self.cipher_suite in CipherSuite.dhAllSuites:
            if valid_groups and any(i in range(256, 512)
                                    for i in valid_groups):
                self._checkParams(server_key_exchange)
            state.key_exchange = DHE_RSAKeyExchange(self.cipher_suite,
                                                    clientHello=None,
                                                    serverHello=server_hello,
                                                    privateKey=None)
            state.key['ServerKeyExchange.key_share'] = \
                server_key_exchange.dh_Ys
            state.key['ServerKeyExchange.dh_p'] = server_key_exchange.dh_p
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
            state.key['ServerKeyExchange.key_share'] = \
                server_key_exchange.ecdh_Ys
        else:
            raise AssertionError("Unsupported cipher selected")
        state.key['premaster_secret'] = state.key_exchange.\
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
            raise AssertionError("Unexpected sig algs. Got: {0}, "
                                 "expected: {1}"
                                 .format(cert_request.supported_signature_algs,
                                         self.sig_algs)
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
    """
    Processing TLS Change Cipher Spec messages.

    @note:
    In SSLv3 up to TLS 1.2, the message modifies the state of record layer
    to expect encrypted records I{after} receiving this message.
    In case of renegotiation, record layer will expect records encrypted
    with the newly negotiated keys. In TLS 1.3 it has no effect record layer
    encryption.
    """

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

        if state.version < (3, 4):
            # in TLS 1.3 the CCS does not have any affect on encryption
            if state.resuming:
                state.msg_sock.encryptThenMAC = state.encrypt_then_mac
                calc_pending_states(state)

            state.msg_sock.changeReadState()

            if state._our_record_size_limit:
                state.msg_sock.recv_record_limit = state._our_record_size_limit


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
    """
    Processing TLS handshake protocol Finished message.

    @note: In TLS 1.3 the message will modify record layer to start I{sending}
    records with encryption using the C{client_handshake_traffic_secret} keys.
    It will also modify the record layer to start expecting the records
    to be encrypted with C{server_application_traffic_secret} keys.
    """

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
            finished = Finished(self.version, state.prf_size)

        finished.parse(parser)

        if self.version in ((0, 2), (2, 0)):
            state.session_id = finished.verify_data
        elif self.version <= (3, 3):
            verify_expected = calcFinished(state.version,
                                           state.key['master_secret'],
                                           state.cipher,
                                           state.handshake_hashes,
                                           not state.client)

            assert finished.verify_data == verify_expected
        else:  # TLS 1.3
            finished_key = HKDF_expand_label(
                state.key['server handshake traffic secret'],
                b'finished',
                b'',
                state.prf_size,
                state.prf_name)
            transcript_hash = state.handshake_hashes.digest(state.prf_name)
            verify_expected = secureHMAC(finished_key,
                                         transcript_hash,
                                         state.prf_name)
            assert finished.verify_data == verify_expected

        state.handshake_messages.append(finished)
        state.key['server_verify_data'] = finished.verify_data
        state.handshake_hashes.update(msg.write())

        if self.version in ((0, 2), (2, 0)):
            state.msg_sock.handshake_finished = True

        if self.version > (3, 3):
            # in TLS 1.3 ChangeCipherSpec is a no-op, so we need to attach
            # the change for reading to some message that is always sent
            state.msg_sock.changeWriteState()

            # we now need to calculate application traffic keys to allow
            # correct interpretation of the alerts regarding Certificate,
            # CertificateVerify and Finished

            # derive the master secret
            secret = derive_secret(
                state.key['handshake secret'], b'derived', None,
                state.prf_name)
            secret = secureHMAC(
                secret, bytearray(state.prf_size), state.prf_name)
            state.key['master secret'] = secret

            # derive encryption keys
            c_traff_sec = derive_secret(
                secret, b'c ap traffic', state.handshake_hashes,
                state.prf_name)
            state.key['client application traffic secret'] = c_traff_sec
            s_traff_sec = derive_secret(
                secret, b's ap traffic', state.handshake_hashes,
                state.prf_name)
            state.key['server application traffic secret'] = s_traff_sec

            # derive TLS exporter key
            exp_ms = derive_secret(secret, b'exp master',
                                   state.handshake_hashes,
                                   state.prf_name)
            state.key['exporter master secret'] = exp_ms

            # set up the encryption keys for application data
            state.msg_sock.calcTLS1_3PendingState(
                state.cipher, c_traff_sec, s_traff_sec, None)
            state.msg_sock.changeReadState()


class ExpectEncryptedExtensions(ExpectHandshake):
    """Processing of the TLS handshake protocol Encrypted Extensions message"""

    def __init__(self, extensions=None):
        super(ExpectEncryptedExtensions, self).__init__(
            ContentType.handshake,
            HandshakeType.encrypted_extensions)
        self.extensions = extensions

    def _compare_extensions(self, srv_exts, cln_hello):
        """
        Verify that server provided extensions match exactly expected list.
        """
        # check if received extensions match the set extensions
        if self.extensions and not srv_exts.extensions:
            raise AssertionError("Server did not send any extensions")
        elif self.extensions is not None and srv_exts.extensions:
            expected = set(self.extensions.keys())
            got = set(i.extType for i in srv_exts.extensions)
            if got != expected:
                diff = expected.difference(got)
                if diff:
                    raise AssertionError("Server did not send extension(s): "
                                         "{0}".format(
                                             ", ".join(ExtensionType.toStr(i)
                                                       for i in diff)))
                diff = got.difference(expected)
                if diff:
                    raise AssertionError("Server sent unexpected extension(s):"
                                         " {0}".format(
                                             ", ".join(ExtensionType.toStr(i)
                                                       for i in diff)))
        elif self.extensions is None and srv_exts.extensions:
            cln_exts = set(i.extType for i in cln_hello.extensions)
            got = set(i.extType for i in srv_exts.extensions)
            diff = got.difference(cln_exts)
            if not got.issubset(cln_exts):
                raise AssertionError("Server sent unexpected extension(s):"
                                     " {0}".format(
                                         ", ".join(ExtensionType.toStr(i)
                                                   for i in diff)))

    @staticmethod
    def _get_autohandler(ext_id):
        try:
            return _EE_EXT_HANDLER[ext_id]
        except KeyError:
            raise ValueError("No autohandler for "
                             "{0}"
                             .format(ExtensionType
                                     .toStr(ext_id)))

    def _process_extensions(self, state, srv_exts):
        """Check if extensions are correct."""
        # fix these constants, when the extensions are implemented
        ee_supported = [ExtensionType.server_name,
                        1,  # max_fragment_length - RFC 6066
                        ExtensionType.supported_groups,
                        14,  # use_srtp - RFC 5764
                        ExtensionType.heartbeat,  # RFC 6520
                        ExtensionType.alpn,
                        19,  # client_certificate_type
                             # draft-ietf-tls-tls13-28 / RFC 7250
                        20,  # server_certificate_type
                             # draft-ietf-tls-tls13-28 / RFC 7250
                        ExtensionType.record_size_limit,  # RFC 8449
                        ExtensionType.early_data]

        for ext in srv_exts.extensions:
            ext_id = ext.extType
            if ext_id not in ee_supported:
                raise AssertionError("Server sent unsupported "
                                     "extension of type {0}"
                                     .format(ExtensionType
                                             .toStr(ext_id)))
            handler = None
            if self.extensions:
                handler = self.extensions[ext_id]

            # use automatic handlers for some extensions
            if handler is None:
                handler = self._get_autohandler(ext_id)

            if callable(handler):
                handler(state, ext)
            elif isinstance(handler, TLSExtension):
                if not handler == ext:
                    raise AssertionError("Expected extension not "
                                         "matched for type {0}, "
                                         "received: {1}"
                                         .format(ExtensionType
                                                 .toStr(ext_id),
                                                 ext))
            else:
                raise ValueError("Bad extension handler for id {0}"
                                 .format(ExtensionType.toStr(ext_id)))

    def process(self, state, msg):
        assert msg.contentType == ContentType.handshake
        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == self.handshake_type

        srv_exts = EncryptedExtensions().parse(parser)

        # get client_hello message with CH extensions
        cln_hello = state.get_last_message_of_type(ClientHello)

        self._compare_extensions(srv_exts, cln_hello)

        if srv_exts.extensions:
            self._process_extensions(state, srv_exts)

        state.handshake_messages.append(srv_exts)
        state.handshake_hashes.update(msg.write())


class ExpectNewSessionTicket(ExpectHandshake):
    """Processing TLS handshake protocol new session ticket message."""

    def __init__(self, note=None):
        """
        Initialise object.

        @note: the C{note} parameter MUST be specified as a keyword argument,
        i.e. read the definition as C{(self, *, note=None)} (see PEP 3102).
        Otherwise the behaviour of this node is not guaranteed if new
        arguments are added to it (as they will be added I{before} the C{note}
        argument).

        @type note: str
        @param note: name or comment attached to the node, will be printed
           when str() or repr() is called on the node
        """
        super(ExpectNewSessionTicket, self).__init__(
            ContentType.handshake,
            HandshakeType.new_session_ticket)
        self.note = note

    def process(self, state, msg):
        """Parse, verify and process the message."""
        assert msg.contentType == ContentType.handshake
        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.new_session_ticket

        ticket = NewSessionTicket().parse(parser)
        ticket.time = time.time()

        state.session_tickets.append(ticket)

    def __repr__(self):
        """Return human readable representation of object."""
        return "ExpectNewSessionTicket({0})".format(
            ", ".join("{0}={1!r}".format(name, getattr(self, name)) for name in
                      ['note'] if getattr(self, name) is not None))


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
        if self.description is not None:
            # allow for multiple choice for description
            if not isinstance(self.description, collections.Iterable):
                self.description = tuple([self.description])

            if alert.description not in self.description:
                if problem_desc:
                    problem_desc += ", "
                descriptions = ["\"{0}\"".format(AlertDescription.toStr(i))
                                for i in self.description]
                expected = ", ".join(
                    itertools.chain((i for i in descriptions[:-2]),
                                    [" or ".join(i for i in descriptions[-2:])]
                                   ))
                received = AlertDescription.toStr(alert.description)
                problem_desc += ("Expected alert description {0} does not "
                                 "match received \"{1}\""
                                 .format(expected, received))
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

    def __init__(self, data=None, size=None):
        super(ExpectApplicationData, self).\
                __init__(ContentType.application_data)
        self.data = data
        self.size = size

    def process(self, state, msg):
        assert msg.contentType == ContentType.application_data
        data = msg.write()

        if self.data:
            assert self.data == data
        if self.size and len(data) != self.size:
            raise AssertionError("ApplicationData of unexpected size: {0}, "
                                 "expected: {1}".format(len(data), self.size))


class ExpectNoMessage(Expect):
    """
    Virtual message signifying timeout on message listen.

    :ivar timeout: how long to wait for message before giving up, in seconds,
    can be float
    """

    def __init__(self, timeout=0.1):
        super(ExpectNoMessage, self).__init__(None)
        self.timeout = timeout

    def process(self, state, msg):
        """Do nothing."""
        pass


class ExpectClose(Expect):

    """Virtual message signifying closing of TCP connection"""

    def __init__(self):
        super(ExpectClose, self).__init__(None)

    def process(self, state, msg):
        """Close our side"""
        state.msg_sock.sock.close()


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
