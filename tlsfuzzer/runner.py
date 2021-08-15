# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Main event loop for running test cases"""

from __future__ import print_function

import socket
from tlslite.messages import Message, Certificate, RecordHeader2
from tlslite.handshakehashes import HandshakeHashes
from tlslite.errors import TLSAbruptCloseError
from tlslite.constants import ContentType, HandshakeType, AlertLevel, \
        AlertDescription, SSL2HandshakeType, CipherSuite
from .expect import ExpectClose, ExpectNoMessage, ExpectAlert

class ConnectionState(object):

    """
    Keeps the TLS connection state for sending of messages

    :ivar ~tlslite.messagesocket.MessageSocket msg_sock: message level
        abstraction for TLS Record Socket

    :ivar handshake_hashes: all handshake messages hashed

    :ivar handshake_messages: all hadshake messages exchanged between peers

    :ivar key: various computed cryptographic keys, hashes and secrets related
        to handshake and record layer

        ``premaster_secret`` - premaster secret from TLS 1.2 and earlier

        ``client finished handshake hashes`` -
        :py:class:`~tlslite.handshakehashes.HandshakeHashes` object that has
        the handshake hashes of last handshake (the only Handshake in TLS 1.3)
        up to and including the client Finished; used for post-handshake
        authentication
    """

    def __init__(self):
        """Prepare object for keeping connection state"""
        self.msg_sock = None

        # cipher negotiated in connection
        self.cipher = 0

        # version proposed in client hello
        self.client_version = (3, 3)

        # version negotiated in connection
        self.version = (3, 3)

        # hashes of all handshake messages exchanged so far
        self.handshake_hashes = HandshakeHashes()

        # hash of all messages exchanged up to Certificate Verify, if CV was
        # used on connection
        self.certificate_verify_handshake_hashes = None

        # all handshake messages exchanged so far
        self.handshake_messages = []

        # are we a client or server side of connection (influences just the
        # way encryption and MAC keys are calculated)
        self.client = True

        # calculated value for premaster secret
        self.key = {}
        self.key['premaster_secret'] = bytearray(0)

        self.key['client handshake traffic secret'] = bytearray(0)

        # negotiated value for master secret
        self.key['master_secret'] = bytearray(0)

        # random values shared by peers
        self.server_random = bytearray(0)
        self.client_random = bytearray(0)

        # session ID set by server
        self.session_id = bytearray(0)

        # Finished message data for secure renegotiation
        self.key['client_verify_data'] = bytearray(0)
        self.key['server_verify_data'] = bytearray(0)

        # Whether we are currently resuming a previously negotiated session
        self.resuming = False

        # variable holding the intermediate state for DHE (and similar) key
        # exchanges
        self.key_exchange = None

        # Whether the session we're currently using is using extended master
        # secret calculation defined in RFC 7627
        self.extended_master_secret = False

        # Whether the session we're currently using is using
        # EncryptThenMAC extension defined in RFC 7366
        self.encrypt_then_mac = False

        # list of tickets received from the server
        self.session_tickets = []

        # used to enforce record_size_limit in TLS 1.2 and earlier
        self._peer_record_size_limit = None
        self._our_record_size_limit = None

    @property
    def prf_name(self):
        """Return the name of the PRF used for session.

        TLS 1.3 specific function
        """
        if self.cipher in CipherSuite.sha384PrfSuites:
            return 'sha384'
        return 'sha256'

    @property
    def prf_size(self):
        """Return the size of the PRF output used for session.

        TLS 1.3 specific function
        """
        if self.cipher in CipherSuite.sha384PrfSuites:
            return 48
        return 32

    def get_server_public_key(self):
        """Extract server public key from server Certificate message"""
        certificates = (msg for msg in self.handshake_messages if\
                        isinstance(msg, Certificate))
        cert_message = next(certificates)
        return cert_message.cert_chain.getEndEntityPublicKey()

    def get_last_message_of_type(self, msg_type):
        """Returns last handshake message of provided type"""
        for msg in reversed(self.handshake_messages):
            if isinstance(msg, msg_type):
                return msg
        return None


def guess_response(content_type, data, ssl2=False):
    """Guess which kind of message is in the record layer payload"""
    if content_type == ContentType.change_cipher_spec:
        if len(data) != 1:
            return "ChangeCipherSpec(invalid size)"
        return "ChangeCipherSpec()"
    elif content_type == ContentType.alert:
        if len(data) < 2:
            return "Alert(invalid size)"
        return "Alert({0}, {1})".format(AlertLevel.toStr(data[0]),
                                        AlertDescription.toStr(data[1]))

    elif content_type == ContentType.handshake:
        if not data:
            return "Handshake(invalid size)"
        if ssl2:
            return "Handshake({0})".format(SSL2HandshakeType.toStr(data[0]))
        else:
            return "Handshake({0})".format(HandshakeType.toStr(data[0]))
    elif content_type == ContentType.application_data:
        return "ApplicationData(len={0})".format(len(data))
    else:
        return ("Message(content_type={0}, first_byte={1}, "
                "len={2})").format(ContentType.toStr(content_type),
                                   data[0],
                                   len(data))


class Runner(object):
    """Test if sending a set of commands returns expected values"""

    def __init__(self, conversation):
        """Link conversation with runner"""
        self.conversation = conversation
        self.state = ConnectionState()

    def run(self):
        """Execute conversation"""
        node = self.conversation
        try:
            while node is not None:
                old_node = None
                msg = None
                if node.is_command():
                    # update connection state
                    node.process(self.state)

                    node = node.child
                    continue
                elif node.is_expect():
                    if isinstance(node, ExpectNoMessage):
                        old_timeout = self.state.msg_sock.sock.gettimeout()
                        self.state.msg_sock.sock.settimeout(node.timeout)
                    # check peer response
                    try:
                        header, parser = self.state.msg_sock.\
                            recvMessageBlocking()
                    except (TLSAbruptCloseError, socket.error) as exc:
                        if isinstance(exc, socket.timeout) and \
                                isinstance(node, ExpectNoMessage):
                            # for ExpectNoMessage we have nothing to do
                            # but to continue
                            self.state.msg_sock.sock.settimeout(old_timeout)
                            node = node.child
                            continue
                        close_node = next((n for n in node.get_all_siblings()
                                           if isinstance(n, ExpectClose)),
                                          None)
                        # timeout will happen if the other side hanged, to
                        # try differentiated between (when no alerts are sent)
                        # allow for close only when the connection was actively
                        # closed
                        if close_node and not isinstance(exc, socket.timeout):
                            close_node.process(self.state, None)
                            node = close_node.child
                            continue
                        else:
                            if isinstance(exc, socket.timeout):
                                raise AssertionError(
                                    "Timeout when waiting for peer message")
                            else:
                                raise AssertionError(
                                    "Unexpected closure from peer")
                    msg = Message(header.type, parser.bytes)
                    old_node = node

                    node = next((proc for proc in node.get_all_siblings()
                                 if proc.is_match(msg)), None)
                    if node is None:
                        # since we're aborting, the user can't clean up
                        self.state.msg_sock.sock.close()
                        raise AssertionError("Unexpected message from peer: " +
                                             guess_response(\
                                                 msg.contentType,
                                                 msg.write(),
                                                 isinstance(header,
                                                            RecordHeader2)))

                    node.process(self.state, msg)

                    node = node.child
                    continue
                elif node.is_generator():
                    # send message to peer
                    msg = node.generate(self.state)
                    try:
                        if msg.write():
                            # sendMessageBlocking is buffered and fragmenting
                            # that means that 0-length messages would get lost
                            self.state.msg_sock.sendMessageBlocking(msg)
                        else:
                            for _ in self.state.msg_sock.sendRecord(msg):
                                # make the method into a blocking one
                                pass
                    except socket.error:
                        close_node = next(
                            (n for n in node.get_all_siblings()
                             if isinstance(n, (ExpectClose, ExpectAlert))),
                            None)
                        if close_node:
                            node = close_node.child
                            continue
                        else:
                            raise AssertionError("Unexpected closure from peer")
                    # allow generators to perform actions after the message
                    # was sent like updating handshake hashes
                    node.post_send(self.state)

                    node = node.child
                    continue
                else:
                    raise AssertionError("Unknown decision tree node")
        except:
            if self.state.msg_sock:
                self.state.msg_sock.sock.close()
            # TODO put into a log
            if node is None:
                node = old_node
            print("Error encountered while processing node " + str(node) +
                  " (child: " + str(node.child) + ") with last message " +
                  "being: " + repr(msg))
            raise
