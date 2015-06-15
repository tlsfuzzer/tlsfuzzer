# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
from __future__ import print_function

from tlslite.messages import Message

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
        self.cipher = 0
        self.handshake_hashes = None
        self.handshake_messages = []

class TreeNode(object):

    """
    Base class for decision tree objects
    """

    def __init__(self):
        """Prepare internode dependencies"""
        self.child = None
        self.next_sibling = None

    def get_all_siblings(self):
        """
        Return iterator with all siblings of node

        @rtype: iterator
        """
        node = self
        while node is not None:
            yield node.next_sibling
            node = node.next_sibling

    def is_command(self):
        """
        Checks if the object is a standalone state modifier

        @rtype: bool
        """
        raise NotImplementedError("Subclasses need to implement this!")

    def is_expect(self):
        """
        Checks if the object is a node which processes messages

        @rtype: bool
        """
        raise NotImplementedError("Subclasses need to implement this!")

    def is_generator(self):
        """
        Checks if the object is a generator for messages to send

        @rtype: bool
        """
        raise NotImplementedError("Subclasses need to implement this!")

class Runner(object):

    """
    Test if sending a set of commands returns expected values
    """

    def __init__(self, conversation):
        """Link conversation with runner"""
        self.conversation = conversation
        self.state = ConnectionState()

    def run(self):
        """Execute conversation"""
        node = self.conversation
        while node is not None:
            if node.is_command():
                # update connection state
                node.process(self.state)

                node = node.child
                continue
            elif node.is_expect():
                # check peer response
                header, parser = self.state.msg_sock.recvMessageBlocking()
                msg = Message(header.type, parser.bytes)

                node = next((proc for proc in node.get_all_siblings()
                             if proc.is_match(msg)), None)
                if node is None:
                    raise AssertionError("Unexpected message from peer")

                node.process(self.state, msg)

                node = node.child
                assert node is not None
                continue
            elif node.is_generator():
                # send message to peer
                msg = node.generate(self.state)
                self.state.msg_sock.sendMessageBlocking(msg)
                node.post_send(self.state)

                node = node.child
                assert node is not None
                continue
            else:
                raise AssertionError("Unknown decision tree node")
