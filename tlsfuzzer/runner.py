# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Main event loop for running test cases"""

from __future__ import print_function

import socket
from tlslite.messages import Message, Certificate
from tlslite.handshakehashes import HandshakeHashes
from tlslite.errors import TLSAbruptCloseError
from tlslite.constants import ContentType, HandshakeType, AlertLevel, \
        AlertDescription
from .expect import ExpectClose

class ConnectionState(object):

    """
    Keeps the TLS connection state for sending of messages

    @type msg_sock: L{tlslite.messagesocket.MessageSocket}
    @ivar msg_sock: message level abstraction for TLS Record Socket

    @ivar handshake_hashes: all handhsake messages hashed

    @ivar handshake_messages: all hadshake messages exchanged between peers
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
        # all handshake messages exchanged so far
        self.handshake_messages = []

        # are we a client or server side of connection (influences just the
        # way encryption and MAC keys are calculated)
        self.client = True

        # calculated value for premaster secret
        self.premaster_secret = bytearray(0)

        # negotiated value for master secret
        self.master_secret = bytearray(0)

        # random values shared by peers
        self.server_random = bytearray(0)
        self.client_random = bytearray(0)

        # session ID set by server
        self.session_id = bytearray(0)

        # Finished message data for secure renegotiation
        self.client_verify_data = bytearray(0)
        self.server_verify_data = bytearray(0)

        # Whether we are currently resuming a previously negotiated session
        self.resuming = False

        # variable holding the intermediate state for DHE (and similar) key
        # exchanges
        self.key_exchange = None

        # Whether the session we're currently using is using extended master
        # secret calculation defined in RFC 7627
        self.extended_master_secret = False

    def get_server_public_key(self):
        """Extract server public key from server Certificate message"""
        certificates = (msg for msg in self.handshake_messages if\
                        isinstance(msg, Certificate))
        cert_message = next(certificates)
        return cert_message.certChain.getEndEntityPublicKey()

    def get_last_message_of_type(self, msg_type):
        """Returns last handshake message of provided type"""
        for msg in reversed(self.handshake_messages):
            if isinstance(msg, msg_type):
                return msg
        return None

def guess_response(content_type, data):
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
                    # check peer response
                    try:
                        header, parser = self.state.msg_sock.recvMessageBlocking()
                    except (TLSAbruptCloseError, socket.error):
                        close_node = next((n for n in node.get_all_siblings() \
                                           if isinstance(n, ExpectClose)), None)
                        if close_node:
                            node = close_node.child
                            continue
                        else:
                            raise AssertionError("Unexpected closure from peer")
                    msg = Message(header.type, parser.bytes)
                    old_node = node

                    node = next((proc for proc in node.get_all_siblings()
                                 if proc.is_match(msg)), None)
                    if node is None:
                        # since we're aborting, the user can't clean up
                        self.state.msg_sock.sock.close()
                        raise AssertionError("Unexpected message from peer: " +
                                             guess_response(msg.contentType,
                                                            msg.write()))

                    node.process(self.state, msg)

                    node = node.child
                    continue
                elif node.is_generator():
                    # send message to peer
                    msg = node.generate(self.state)
                    try:
                        self.state.msg_sock.sendMessageBlocking(msg)
                    except socket.error:
                        close_node = next((n for n in node.get_all_siblings()
                                           if isinstance(n, ExpectClose)), None)
                        if close_node:
                            node = close_node.child
                            continue
                        else:
                            raise AssertionError("Unexpected closure from peer")
                    node.post_send(self.state)

                    node = node.child
                    continue
                else:
                    raise AssertionError("Unknown decision tree node")
        except:
            # TODO put into a log
            if node is None:
                node = old_node
            print("Error encountered while processing node " + str(node) +
                  " (child: " + str(node.child) + ") with last message " +
                  "being: " + repr(msg))
            raise
