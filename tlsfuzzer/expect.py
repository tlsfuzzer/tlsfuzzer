# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Parsing and processing of received TLS messages"""
from __future__ import print_function

import itertools
from functools import partial
import sys
import time

import tlslite.utils.tlshashlib as hashlib
from tlslite.constants import ContentType, HandshakeType, CertificateType,\
        HashAlgorithm, SignatureAlgorithm, ExtensionType,\
        SSL2HandshakeType, CipherSuite, GroupName, AlertDescription, \
        SignatureScheme, TLS_1_3_HRR, HeartbeatMode, \
        TLS_1_1_DOWNGRADE_SENTINEL, TLS_1_2_DOWNGRADE_SENTINEL, \
        HeartbeatMessageType, ClientCertificateType, CertificateStatusType
from tlslite.messages import ServerHello, Certificate, ServerHelloDone,\
        ChangeCipherSpec, Finished, Alert, CertificateRequest, ServerHello2,\
        ServerKeyExchange, ClientHello, ServerFinished, CertificateStatus, \
        CertificateVerify, EncryptedExtensions, NewSessionTicket, Heartbeat,\
        KeyUpdate, HelloRequest
from tlslite.extensions import TLSExtension, ALPNExtension
from tlslite.utils.codec import Parser, Writer
from tlslite.utils.compat import b2a_hex
from tlslite.utils.cryptomath import secureHMAC, derive_secret, \
        HKDF_expand_label
from tlslite.mathtls import RFC7919_GROUPS, FFDHE_PARAMETERS, calc_key
from tlslite.keyexchange import KeyExchange, DHE_RSAKeyExchange, \
        ECDHE_RSAKeyExchange
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlslite.errors import TLSDecryptionFailed
from tlslite.handshakehashes import HandshakeHashes
from tlslite.handshakehelpers import HandshakeHelpers
from .handshake_helpers import calc_pending_states, kex_for_group, \
        curve_name_to_hash_tls13
from .helpers import ECDSA_SIG_TLS1_3_ALL
from .tree import TreeNode

# pylint: disable=import-error,no-name-in-module
# pylint: disable=bad-option-value,deprecated-class
if sys.version_info >= (3, 3):
    from collections.abc import Iterable
else:
    from collections import Iterable
# pylint: enable=bad-option-value,deprecated-class
# pylint: enable=import-error,no-name-in-module


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

        :type msg: tlslite.messages.Message
        :param msg: raw message to check
        """
        if msg.contentType == self.content_type:
            return True

        return False

    def process(self, state, msg):
        """
        Process the message and update the state accordingly.

        :type state: tlsfuzzer.runner.ConnectionState
        :param state: current connection state, needs to be updated after
            parsing the message by inheriting classes
        :type msg: tlslite.messages.Message
        :param msg: raw message to parse
        """
        raise NotImplementedError("Subclasses need to implement this!")


class ExpectMessage(Expect):
    """Common methods for handling TLS messages."""

    @staticmethod
    def _cmp_eq(our, recv, field_type=None, f_str=None):
        """
        Check if expected value matched received, if defined.

        If our is not None, compare with recv. If they don't match, try
        translating them with field_type.toStr() method and rise
        AssertionError with message formatted with f_str. First parameter
        to .format() will be expected value and the second one will be the
        received one
        """
        if our is None or our == recv:
            return

        if field_type:
            expected = field_type.toStr(our)
            received = field_type.toStr(recv)
        else:
            expected = our
            received = recv

        if not f_str:
            f_str = "Expected: {0}, received: {1}"
        raise AssertionError(f_str.format(expected, received))

    @classmethod
    def _cmp_eq_or_in(cls, our, recv, field_type=None, f_str=None):
        """
        Check if received value equals expected or is in expected list.

        If our is a list or set, check if recv is in it.
        If our is not None, check if it's equal to recv.
        If they don't match or are not part of a set, try translating
        them with field_type.toStr() method and raise AssertionError
        formatted with f_str. First parameter to .format() will be
        the expected value and the second one witll be the
        received one.
        """
        if our is None:
            return
        try:
            if recv in our:
                return
        except TypeError:
            return cls._cmp_eq(our, recv, field_type, f_str)

        # doesn't match, so prepare the error message
        if field_type:
            expected = "({0})".format(", ".join(
                field_type.toStr(i) for i in our))
            received = field_type.toStr(recv)
        else:
            expected = our
            received = recv

        if not f_str:
            f_str = "Received value ({1}) not in expected list: {0}"
        raise AssertionError(f_str.format(expected, received))

    @staticmethod
    def _cmp_eq_list(our, recv, field_type=None, f_str=None):
        """
        Check if expected list of values matched received, if defined.

        If our is not None, compare with recv. If they don't match, try
        translating items in the lists with field_type.toStr() method and rise
        AssertionError with message formatted with f_str. First parameter
        to .format() will be list of expected values and the second one will be
        the received one
        """
        if our is None or our == recv:
            return

        if field_type:
            expected = ", ".join(field_type.toStr(i) for i in our)
            expected = "({0})".format(expected)
            received = ", ".join(field_type.toStr(i) for i in recv)
            received = "({0})".format(received)
        else:
            expected = repr(our)
            received = repr(recv)

        if not f_str:
            f_str = "Expected: {0}, received: {1}"
        raise AssertionError(f_str.format(expected, received))


class ExpectHandshake(ExpectMessage):
    """Common methods for handling TLS Handshake protocol messages"""

    def __init__(self, content_type, handshake_type):
        """
        Set the type of message

        :type content_type: int
        :type handshake_type: int
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
    any `~SetMaxRecordSize()` before EncryptedExtensions in TLS 1.3 and
    before ChangeCipherSpec in TLS 1.2 and earlier.

    :param int size: expected value from server, None for any valid
    """
    return partial(_srv_ext_handler_record_limit, size=size)


def clnt_ext_handler_status_request(state, extension):
    """
    Check status_request extension from initiating side.

    To be used in ClientHello and CertificateRequest
    """
    del state  # kept for compatibility
    if extension.status_type != CertificateStatusType.ocsp:
        raise AssertionError(
            "Unexpected status_type in status_request extension: {0}"
            .format(CertificateStatusType.toStr(extension.status_type)))
    if extension.responder_id_list is None \
            or extension.request_extensions is None:
        raise AssertionError(
            "Malformed status_request extension")


def clnt_ext_handler_sig_algs(state, extension):
    """
    Check signature_algorithms or signature_algorithms_cert extension.

    To be used in ClientHello and CertificateRequest.
    """
    del state  # kept for API compatibility
    if not extension.sigalgs:
        raise AssertionError(
            "Empty or malformed {0} extension"
            .format(ExtensionType.toStr(extension.extType)))


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


_CR_EXT_HANDLER = \
        {ExtensionType.status_request: clnt_ext_handler_status_request,
         ExtensionType.signature_algorithms: clnt_ext_handler_sig_algs,
         ExtensionType.signature_algorithms_cert: clnt_ext_handler_sig_algs}


class _ExpectExtensionsMessage(ExpectHandshake):
    """
    Common methods of messages that have a list of extensions.

    Used in ServerHello, EncryptedExtensions and CertificateRequest (in
    TLS 1.3)
    """
    def __init__(self, content_type, msg_type, extensions):
        super(_ExpectExtensionsMessage, self).__init__(
            content_type, msg_type)
        self.extensions = extensions

    def _compare_extensions(self, message):
        """
        Verify that server provided extensions match exactly expected list.
        """
        # if the list of extensions is present, make sure it matches exactly
        # with what the server sent
        if self.extensions and not message.extensions:
            raise AssertionError("Server did not send any extensions")
        if self.extensions is not None and message.extensions:
            expected = set(self.extensions.keys())
            got = set(i.extType for i in message.extensions)
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


class ExpectServerHello(_ExpectExtensionsMessage):
    """
    Parsing TLS Handshake protocol Server Hello messages.

    Processing of the ServerHello message updates the record layer
    to the version advertisied by the server.
    Use :py:class:`~tlsfuzzer.messages.SetRecordVersion` to change it earlier
    to send records with different versions.

    .. note::
      Receiving of the ServerHello in TLS 1.3 influences record layer
      encryption. After the message is received, the
      ``client_handshake_traffic_secret`` and
      ``server_handshake_traffic_secret``
      is derived and record layer is configured to expect encrypted records
      on the *receiving* side.

    :ivar str ~.description: identifier to print when processing of the
        node fails
    """

    def __init__(self, extensions=None, version=None, resume=False,
                 cipher=None, server_max_protocol=None,
                 description=None):
        """
        Initialize the object

        :param dict extensions: extension objects to match the server sent
        extensions or callbacks to process and verify them. None means use
        automatic handlers that will verify the response against the extensions
        sent in ClientHello. Empty dict means that the server is expected to
        send no extensions. Order does not matter, but all extensions present
        and only extensions present in the list must be sent by server. None
        as the value of the relevant extension type can be used to select
        autohandler for a given extension type.

        :param tuple version: the literal version in the Server Hello message
        (needs to be (3, 3) for TLS 1.3, use extensions to expect TLS 1.3
        negotiation)

        :param tuple server_max_protocol: the higher protocol version supported
        by server. Used for testing downgrade signaling of servers.

        :type cipher: int or set-like
        :param int cipher: the id of the cipher that is expected to be
        negotiated by server. Can also be a list or set (needs to support
        ``in``) for a set of allowed ciphers.
        None (the default) means any valid cipher
        (i.e. not SCSV or GREASE) sent in ClientHello can be selected by
        server.

        :type resume: boolean
        :param resume: whether the session id should match the one from
        current state - IOW, if the server hello should belong to a resumed
        session. TLS 1.2 and earlier only. In TLS 1.3 resumption is handled
        by providing handler for ``pre_shared_key`` extension.
        """
        super(ExpectServerHello, self).__init__(ContentType.handshake,
                                                HandshakeType.server_hello,
                                                extensions)
        self.cipher = cipher
        self.version = version
        self.resume = resume
        self.srv_max_prot = server_max_protocol
        self.description = description

    def __str__(self):
        """Return human redable representation of the object."""
        if self.description:
            return "ExpectServerHello(description={0!r})"\
                   .format(self.description)
        return "ExpectServerHello()"

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

        :type state: ConnectionState
        :param state: overall state of TLS connection

        :type msg: Message
        :param msg: TLS Message read from socket
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

        self._cmp_eq(self.version, srv_hello.server_version,
                     f_str="Server selected unexpected protocol version. "
                           "Expected: {0}, received: {1}.")

        self._cmp_eq_or_in(
            self.cipher, srv_hello.cipher_suite,
            f_str="Server selected unexpected ciphersuite. "
                  "Expected: {0}, received: {1}.")

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

        :type state: `~ConnectionState`
        :param state: overall state of TLS connection

        :type msg: Message
        :param msg: TLS Message read from socket
        """
        # the value is faked for SSLv2 protocol, but let's just check sanity
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == SSL2HandshakeType.server_hello

        server_hello = ServerHello2().parse(parser)

        state.handshake_messages.append(server_hello)
        state.handshake_hashes.update(msg.write())

        self._cmp_eq(self.version, server_hello.server_version,
                     f_str="Server picked unexpected protocol version."
                           "Expected: {0}, received: {1}.")

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
        self._old_cert = None
        self._old_cert_bytes = None

    def process(self, state, msg):
        """
        :type state: `~ConnectionState`
        """
        assert msg.contentType == ContentType.handshake

        msg_bytes = msg.write()
        if self._old_cert_bytes is not None and \
                msg_bytes == self._old_cert_bytes:
            cert = self._old_cert
        else:
            parser = Parser(msg_bytes)
            hs_type = parser.get(1)
            assert hs_type == HandshakeType.certificate

            cert = Certificate(self.cert_type, state.version)
            cert.parse(parser)
            self._old_cert_bytes = msg_bytes
            self._old_cert = cert

        state.handshake_messages.append(cert)
        state.handshake_hashes.update(msg_bytes)


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
        :type state: `~ConnectionState`
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
            key_type = state.get_server_public_key().key_type
            if key_type == "rsa-pss":
                # in TLS 1.3 only RSA-PSS signatures are allowed
                assert cert_v.signatureAlgorithm in (
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.rsa_pss_pss_sha384,
                    SignatureScheme.rsa_pss_pss_sha512)
            elif key_type == "rsa":
                # in TLS 1.3 only RSA-PSS signatures are allowed
                assert cert_v.signatureAlgorithm in (
                    SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_rsae_sha384,
                    SignatureScheme.rsa_pss_rsae_sha512)
            elif key_type in ("Ed25519", "Ed448"):
                assert cert_v.signatureAlgorithm in (
                    SignatureScheme.ed25519,
                    SignatureScheme.ed448)
                if getattr(SignatureScheme, key_type.lower()) != \
                        cert_v.signatureAlgorithm:
                    raise AssertionError(
                        "Mismatched signature ({0}) for used key ({1})"
                        .format(
                            SignatureScheme.toStr(cert_v.signatureAlgorithm),
                            key_type))
            else:
                assert key_type == "ecdsa"
                curve_name = state.get_server_public_key().curve_name
                assert curve_name in ("NIST256p", "NIST384p", "NIST521p")
                sigalg = cert_v.signatureAlgorithm
                assert sigalg in ECDSA_SIG_TLS1_3_ALL
                hash_name = curve_name_to_hash_tls13(curve_name)
                # in TLS 1.3 the hash is bound to key curve
                if sigalg != (getattr(HashAlgorithm, hash_name),
                              SignatureAlgorithm.ecdsa):
                    raise AssertionError(
                        "Invalid signature type for {1} key, "
                        "received: {0}"
                        .format(SignatureScheme.toStr(sigalg), curve_name))

        salg = cert_v.signatureAlgorithm

        if salg in (SignatureScheme.ed25519, SignatureScheme.ed448):
            hash_name = "intrinsic"
            padding = None
            salt_len = None
        elif salg[1] == SignatureAlgorithm.ecdsa:
            hash_name = HashAlgorithm.toStr(salg[0])
            padding = None
            salt_len = None
        else:
            scheme = SignatureScheme.toRepr(salg)
            hash_name = SignatureScheme.getHash(scheme)
            padding = SignatureScheme.getPadding(scheme)
            salt_len = getattr(hashlib, hash_name)().digest_size

        transcript_hash = state.handshake_hashes.digest(state.prf_name)
        sig_context = bytearray(b'\x20' * 64 +
                                b'TLS 1.3, server CertificateVerify' +
                                b'\x00') + transcript_hash

        if not state.get_server_public_key().hashAndVerify(
                cert_v.signature,
                sig_context,
                padding,
                hash_name,
                salt_len):
            raise AssertionError("Signature verification failed")

        state.handshake_messages.append(cert_v)
        state.handshake_hashes.update(msg.write())


class ExpectServerKeyExchange(ExpectHandshake):
    """Processing TLS Handshake protocol Server Key Exchange message"""

    def __init__(self, version=None, cipher_suite=None, valid_sig_algs=None,
                 valid_groups=None, valid_params=None):
        """
        Expect ServerKeyExchange message from server.

        :param list(int) valid_groups: TLS group identifiers for groups that
            server can use. In case the groups include identifiers between 256
            and 512 (see RFC 7919), the node will also check that the server
            selected FFDH parameters match the parameters specified in the RFC.

        :param set(tuple(int,int)) valid_params: set of explicit expected
            parameters used by the server, the first element of the tuple
            is the expected generator and the second is the prime used for the
            DH calculation. Applicable only to ciphersuites that use FFDHE
            key exchange.
        """
        msg_type = HandshakeType.server_key_exchange
        super(ExpectServerKeyExchange, self).__init__(ContentType.handshake,
                                                      msg_type)
        self.version = version
        self.cipher_suite = cipher_suite
        self.valid_sig_algs = valid_sig_algs
        self.valid_groups = valid_groups
        self.valid_params = valid_params
        if self.valid_groups and self.valid_params:
            raise ValueError("valid_groups and valid_params are exclusive")

    def _checkParams(self, server_key_exchange):
        groups = []
        if self.valid_groups and any(i in range(256, 512)
                                     for i in self.valid_groups):
            groups = [RFC7919_GROUPS[i - 256] for i in self.valid_groups
                      if i in range(256, 512)]
        if self.valid_params:
            groups = self.valid_params
        server_params = (server_key_exchange.dh_g, server_key_exchange.dh_p)
        if groups and server_params not in groups:
            for name, params in FFDHE_PARAMETERS.items():
                if server_params == params:
                    raise AssertionError(
                        "DH parameters not from valid set, "
                        "received: {0}".format(name))
            raise AssertionError(
                "DH parameters not from valid set, "
                "received: g:{0}, p:{1}".format(
                    hex(server_params[0]),
                    hex(server_params[1])))

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
                if self.cipher_suite in CipherSuite.ecdheEcdsaSuites:
                    valid_sig_algs = [(HashAlgorithm.sha1,
                                       SignatureAlgorithm.ecdsa)]

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


# RFC8446 Section 4.2 says that implementation MUST reject extensions
# it recognises but which are not allowed in CertificateRequest
# check it against all defined in RFC8446
TLS_1_3_CR_FORBIDDEN = set((
    ExtensionType.server_name,
    1,  # ExtensionType.max_fragment_length
    ExtensionType.supported_groups,
    14,  # ExtensionType.use_srtp
    ExtensionType.heartbeat,
    ExtensionType.alpn,
    19,  # ExtensionType.client_certificate_type
    20,  # ExtensionType.server_certificate_type
    21,  # ExtensionType.padding,
    ExtensionType.key_share,
    ExtensionType.pre_shared_key,
    ExtensionType.psk_key_exchange_modes,
    ExtensionType.early_data,
    ExtensionType.cookie,
    ExtensionType.supported_versions,
    49  # ExtensionType.post_handshake_auth
    ))


class ExpectCertificateRequest(_ExpectExtensionsMessage):
    """Processing TLS Handshake protocol Certificate Request message."""

    def __init__(self, sig_algs=None, cert_types=None,
                 sanity_check_cert_types=True, extensions=None, context=None):
        """
        Set expected parameters for the CertificateRequest message.

        :param sig_algs: a list of signature algorithms that we are expecting
            from server. Needs to be in-order and complete. ``None`` to accept
            any list from server. Applicable to TLS 1.2 and later only.
            Do not use together with non-default ``extensions``.
        :param cert_types: a list of client certificate types that we are
            expecting from server. Needs to be in-order and complete.
            ``None`` to accept any list from server. Applicable to TLS 1.2 and
            earlier only.
        :param sanity_check_cert_types: set to ``False`` to disable
            verification checking if every signature algorithm has a
            corresponding client certificate type.
        :param extensions: dictionary with extensions that need to be included
            in the message. Set to ``None`` to accept any, set to empty dict to
            expect no extensions. Usable in TLS 1.3 only.
        """
        msg_type = HandshakeType.certificate_request
        super(ExpectCertificateRequest, self).__init__(ContentType.handshake,
                                                       msg_type,
                                                       extensions)
        self.sig_algs = sig_algs
        self.cert_types = cert_types
        self.context = context
        self.sanity_check_cert_types = sanity_check_cert_types
        if sig_algs is not None and extensions is not None:
            raise ValueError("Can't set sig_algs and extensions at the same "
                             "time")

    @staticmethod
    def _sanity_check_cert_types(cert_request):
        """Verify that the CertificateRequest is self-consistent."""
        for sig_alg in cert_request.supported_signature_algs:
            if sig_alg[1] in (SignatureAlgorithm.ecdsa,
                              SignatureAlgorithm.ed25519,
                              SignatureAlgorithm.ed448):
                key_type = "ECDSA"
                cert_type = "ecdsa_sign"
            elif sig_alg[1] == SignatureAlgorithm.rsa:
                key_type = "RSA"
                cert_type = "rsa_sign"
            elif sig_alg[1] == SignatureAlgorithm.dsa:
                key_type = "DSA"
                cert_type = "dss_sign"
            else:
                sig_scheme = SignatureScheme.toRepr(sig_alg)
                key_type = SignatureScheme.getKeyType(sig_scheme)
                assert key_type == "rsa", \
                    "Unsupported signature algorithm: {0}".format(sig_alg)
                cert_type = "rsa_sign"

            if getattr(ClientCertificateType, cert_type) \
                    not in cert_request.certificate_types:
                raise AssertionError(
                    "CertificateRequest includes {1} signature algorithms "
                    "({0}) but does not include {2} client "
                    "certificate type".format(sig_alg, key_type, cert_type))

    @staticmethod
    def _get_autohandler(ext_id):
        try:
            return _CR_EXT_HANDLER[ext_id]
        except KeyError:
            # handle future/GREASE extensions
            return None

    def _process_extensions(self, state, msg):
        for ext in msg.extensions:
            ext_id = ext.extType
            handler = None
            if ext_id in TLS_1_3_CR_FORBIDDEN:
                raise AssertionError(
                    "Server sent extension that is explicitly forbidden in "
                    "CertificateRequest messages: {0}".format(
                        ExtensionType.toStr(ext_id)))
            if self.extensions:
                handler = self.extensions[ext_id]
            if handler is None:
                handler = self._get_autohandler(ext_id)

            if callable(handler):
                handler(state, ext)
            elif isinstance(handler, TLSExtension):
                if not handler == ext:
                    raise AssertionError(
                        "Expected extension not matched for type {0}, "
                        "received: {1}".format(ExtensionType.toStr(ext_id),
                                               ext))
            elif handler is None:
                # since server can send arbitrary extensions, we need to
                # be able to process them, so if the self.extensions is unset
                # we can just do nothing
                pass
            else:
                raise ValueError("Bad extension handler for id {0}".format(
                    ExtensionType.toStr(ext_id)))

    def process(self, state, msg):
        """
        Check received Certificate Request

        :type state: ConnectionState
        """
        assert msg.contentType == ContentType.handshake

        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.certificate_request

        cert_request = CertificateRequest(state.version)
        cert_request.parse(parser)

        self._cmp_eq_list(self.sig_algs, cert_request.supported_signature_algs,
                          SignatureScheme,
                          f_str="Unexpected signature algorithms. Got: {1}, "
                                "expected: {0}")

        self._cmp_eq_list(self.cert_types, cert_request.certificate_types,
                          ClientCertificateType,
                          f_str="Unexpected client certificate types. Got: "
                                "{1}, expected: {0}")

        if state.version == (3, 3) and self.sanity_check_cert_types:
            # only in TLS 1.2 do the sig algs coexist with cert types
            self._sanity_check_cert_types(cert_request)

        if state.version >= (3, 4):
            self._compare_extensions(cert_request)
            self._process_extensions(state, cert_request)
            if self.context is not None:
                self.context.append(cert_request)

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
        :type state: ConnectionState
        :type msg: Message
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

    .. note::
      In SSLv3 up to TLS 1.2, the message modifies the state of record layer
      to expect encrypted records *after* receiving this message.
      In case of renegotiation, record layer will expect records encrypted
      with the newly negotiated keys. In TLS 1.3 it has no effect on record
      layer encryption.
    """

    def __init__(self):
        super(ExpectChangeCipherSpec,
              self).__init__(ContentType.change_cipher_spec)

    def process(self, state, msg):
        """
        :type state: ConnectionState
        :type msg: Message
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

    .. note::
      In TLS 1.3 the message will modify record layer to start *sending*
      records with encryption using the ``client_handshake_traffic_secret``
      keys.
      It will also modify the record layer to start expecting the records
      to be encrypted with ``server_application_traffic_secret`` keys.
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
        :type state: ConnectionState
        :type msg: Message
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
            verify_expected = calc_key(state.version,
                                       state.key['master_secret'],
                                       state.cipher,
                                       b'client finished' if not state.client
                                       else b'server finished',
                                       state.handshake_hashes,
                                       output_length=12)

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


class ExpectEncryptedExtensions(_ExpectExtensionsMessage):
    """Processing of the TLS handshake protocol Encrypted Extensions message"""

    def __init__(self, extensions=None):
        super(ExpectEncryptedExtensions, self).__init__(
            ContentType.handshake,
            HandshakeType.encrypted_extensions,
            extensions)

    def _compare_extensions_in_ee(self, srv_exts, cln_hello):
        """
        Verify that server provided extensions match exactly expected list.
        """
        # check if received extensions match the set extensions
        self._compare_extensions(srv_exts)
        if self.extensions is None and srv_exts.extensions:
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

        self._compare_extensions_in_ee(srv_exts, cln_hello)

        if srv_exts.extensions:
            self._process_extensions(state, srv_exts)

        state.handshake_messages.append(srv_exts)
        state.handshake_hashes.update(msg.write())


class ExpectNewSessionTicket(ExpectHandshake):
    """Processing TLS handshake protocol new session ticket message."""

    def __init__(self, description=None):
        """
        Initialise object.

        .. note::
            The ``description`` parameter MUST be specified
            as a keyword argument, i.e. read the definition as
            ``(self, *, description=None)`` (see PEP 3102).
            Otherwise the behaviour of this node is not guaranteed if new
            arguments are added to it (as they will be added *before*
            the ``description`` argument).

        :param str description: name or comment attached to the node,
            it will be printed when :py:func:`str` or :py:func:`repr` is
            called on the node.
        """
        super(ExpectNewSessionTicket, self).__init__(
            ContentType.handshake,
            HandshakeType.new_session_ticket)
        self.description = description

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
        return self._repr(['description'])


class ExpectHelloRequest(ExpectHandshake):
    """Processing of TLS handshake protocol hello request message."""

    def __init__(self, description=None):
        """
        Initialise object.

        .. note::
            The ``description`` parameter MUST be specified
            as a keyword argument, i.e. read the definition as
            ``(self, *, description=None)`` (see PEP 3102).
            Otherwise the behaviour of this node is not guaranteed if new
            arguments are added to it (as they will be added *before*
            the ``description`` argument).

        :param str description: name or comment attached to the node,
            it will be printed when :py:func:`str` or :py:func:`repr` is
            called on the node.
        """
        super(ExpectHelloRequest, self).__init__(
            ContentType.handshake,
            HandshakeType.hello_request)
        self.description = description

    def process(self, state, msg):
        """Parse, verify and process the message."""
        assert msg.contentType == ContentType.handshake
        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == HandshakeType.hello_request

        # check if it is well-formed
        HelloRequest().parse(parser)

    def __repr__(self):
        """Return human readable representation of object."""
        return self._repr(['description'])


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
            if not isinstance(self.description, Iterable):
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

    def __repr__(self):
        """Return human readable representation of object."""
        return self._repr(["level", "description"])


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

    def __init__(self, data=None, size=None, output=None):
        super(ExpectApplicationData, self).\
                __init__(ContentType.application_data)
        self.data = data
        self.size = size
        self.output = output

    def process(self, state, msg):
        assert msg.contentType == ContentType.application_data
        data = msg.write()

        if self.data:
            assert self.data == data
        if self.size and len(data) != self.size:
            raise AssertionError("ApplicationData of unexpected size: {0}, "
                                 "expected: {1}".format(len(data), self.size))
        if self.output:
            self.output.write("ExpectApplicationData received payload:\n")
            self.output.write(data)
            self.output.write("ExpectApplicationData end of payload.\n")


class ExpectHeartbeat(ExpectMessage):
    """Processing of heartbeat messages."""

    def __init__(self, message_type=HeartbeatMessageType.heartbeat_response,
                 payload=None, padding_size=None):
        """
        Set up waiting for a heartbeat message.

        :type message_type: int
        :param message_type: Type of heartbeat messages to wait for, see
            `~tlslite.constants.HeartbeatMessageType` for defined types
        :type payload: bytes-like
        :param payload: literal value of padding to expect, if set to ``None``,
            any payload will be accepted
        :type padding_size: int
        :param padding_size: exact length of padding that will be expected,
            if set to ``None``, any padding length will be accepted
        """
        super(ExpectHeartbeat, self).\
            __init__(ContentType.heartbeat)
        self.message_type = message_type
        self.payload = payload
        self.padding_size = padding_size

    def process(self, state, msg):
        """Check if the ``msg`` meets the requirements for the message."""
        assert msg.contentType == ContentType.heartbeat

        parser = Parser(msg.write())
        heartbeat = Heartbeat().parse(parser)

        self._cmp_eq(self.message_type, heartbeat.message_type,
                     HeartbeatMessageType,
                     "Unexpected heartbeat message type. Expected: {0}, "
                     "received: {1}.")

        self._cmp_eq(self.payload, heartbeat.payload,
                     f_str="Unexpected payload in Heartbeat message "
                           "received. Expected: {0!r}, received: {1!r}")

        if self.padding_size is None:
            assert len(heartbeat.padding) >= 16
        else:
            if len(heartbeat.padding) != self.padding_size:
                raise AssertionError(
                        "Server sent unexpected size of padding "
                        "in heartbeat message. Expected: {0}, "
                        "received: {1}".format(self.padding_size,
                                               len(heartbeat.padding)))


class ExpectNoMessage(Expect):
    """
    Virtual message signifying timeout on message listen.

    :ivar timeout: how long to wait for message before giving up, in seconds,
        can be float
    :vartype timeout: int or float
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


class ExpectKeyUpdate(ExpectHandshake):
    """Processing of post-handshake KeyUpdate message from RFC 8446"""

    def __init__(self, message_type=None):
        """
        Initialize object.

        :type message_type: int
        :param message_type: type of KeyUpdate msg, either
            update_not_requested or update_requested
        """
        super(ExpectKeyUpdate, self).__init__(
            ContentType.handshake,
            HandshakeType.key_update)
        self.message_type = message_type

    def process(self, state, msg):
        """
        Parse, verify and process the message.

        :type state: ConnectionState
        :type msg: Message
        """
        assert msg.contentType == self.content_type
        parser = Parser(msg.write())
        hs_type = parser.get(1)
        assert hs_type == self.handshake_type

        keyupdate = KeyUpdate().parse(parser)
        assert keyupdate.message_type == self.message_type

        _, sr_app_secret = state.msg_sock.\
            calcTLS1_3KeyUpdate_sender(
                state.cipher,
                state.key['client application traffic secret'],
                state.key['server application traffic secret'])
        state.key['server application traffic secret'] = sr_app_secret
