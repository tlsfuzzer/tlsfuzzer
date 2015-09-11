# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Main event loop for running test cases"""

from __future__ import print_function

from tlslite.messages import Message, Certificate
from tlslite.handshakehashes import HandshakeHashes
from tlslite.errors import TLSAbruptCloseError
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
        # version proposed in client hello, and later negotiated in connection
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

    def get_server_public_key(self):
        """Extract server public key from server Certificate message"""
        certificates = (msg for msg in self.handshake_messages if\
                        isinstance(msg, Certificate))
        cert_message = next(certificates)
        return cert_message.certChain.getEndEntityPublicKey()

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
                    except TLSAbruptCloseError:
                        if isinstance(node, ExpectClose):
                            node = node.child
                            continue
                        else:
                            raise AssertionError("Unexpected closure from peer")
                    msg = Message(header.type, parser.bytes)

                    node = next((proc for proc in node.get_all_siblings()
                                 if proc.is_match(msg)), None)
                    if node is None:
                        raise AssertionError("Unexpected message from peer: " +
                                             str(msg.contentType) + ", " +
                                             str(msg.write()[0]))

                    node.process(self.state, msg)

                    node = node.child
                    continue
                elif node.is_generator():
                    # send message to peer
                    msg = node.generate(self.state)
                    self.state.msg_sock.sendMessageBlocking(msg)
                    node.post_send(self.state)

                    node = node.child
                    continue
                else:
                    raise AssertionError("Unknown decision tree node")
        except:
            # TODO put into a log
            print("Error encountered while processing node " + str(node) +
                  " with last message being: " + repr(msg))
            raise
