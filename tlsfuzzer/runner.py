# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Main event loop for running test cases"""

from __future__ import print_function

import socket
from tlslite.messages import Message, Certificate, RecordHeader2
from tlslite.handshakehashes import HandshakeHashes
from tlslite.errors import TLSAbruptCloseError
from tlslite.constants import ContentType, HandshakeType, AlertLevel, \
        AlertDescription, SSL2HandshakeType, CipherSuite, TLS_1_3_HRR
from tlslite.utils.codec import Parser
from .expect import ExpectClose, ExpectNoMessage

class ConnectionState(object):
    """
    Keeps state information of the connection.

    Currently just session ID and connection state, but will be extended
    to allow resumption, etc.
    """

    def __init__(self):
        """Prepare object for keeping connection state"""
        # variable holding the session ID of the client
        self.session_id = bytearray(0)
        # variable holding the session ID of the server
        self.server_session_id = bytearray(0)
        # variable holding the master secret of the session
        self.master_secret = bytearray(0)
        # variable holding the extended master secret of the session
        self.extended_master_secret = False
        # variable holding the cipher suite of the session
        self.cipher = None
        # variable holding the version of the session
        self.version = None
        # variable holding the handshake hashes
        self.handshake_hashes = HandshakeHashes()
        # variable holding the handshake messages
        self.handshake_messages = []
        # variable holding the client random
        self.client_random = None
        # variable holding the server random
        self.server_random = None
        # variable holding the resumption master secret
        self.resumption_master_secret = None
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
        """Extract server public key from the last server Certificate message.

        Uses the most recent Certificate message so that resumption and
        multi-handshake conversations pick the certificate that applies to
        the current handshake rather than an earlier one.
        """
        cert_message = self.get_last_message_of_type(Certificate)
        if cert_message is None:
            raise StopIteration("No Certificate message in handshake_messages")
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
            if data[0] == HandshakeType.server_hello and \
                    data[6:6+32] == TLS_1_3_HRR:
                return "Handshake(server_hello, hello_retry_request)"
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
                    if node.is_expect():
                        node.process(self.state, msg)
                    else:
                        raise AssertionError("Node is neither command, expect "
                                             "nor generator")
                elif node.is_generator():
                    # generate message
                    msg = node.generate(self.state)
                    if msg is not None:
                        self.state.msg_sock.sendMessageBlocking(msg)
                    node = node.child
                    continue
                else:
                    raise AssertionError("Node is neither command, expect "
                                         "nor generator")
                node = node.child
        except AssertionError as e:
            print("Error encountered while processing node {0} "
                  "(child: {1}) with last message being: {2}".format(
                      node, node.child if node else None, msg))
            print("Error while processing")
            raise
