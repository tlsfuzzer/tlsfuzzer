# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Handling of event tree nodes"""


class TreeNode(object):
    """Base class for decision tree objects."""

    def __init__(self):
        """Prepare internode dependencies"""
        self.child = None
        self.next_sibling = None

    def add_child(self, child):
        """
        Sets the parameter as the child of the node

        :return: the child node
        """
        self.child = child
        return self.child

    def get_all_siblings(self):
        """
        Return iterator with all siblings of node

        :rtype: iterator
        """
        yield self
        node = self
        while node.next_sibling is not None:
            yield node.next_sibling
            node = node.next_sibling

    def is_command(self):
        """
        Checks if the object is a standalone state modifier

        :rtype: bool
        """
        raise NotImplementedError("Subclasses need to implement this!")

    def is_expect(self):
        """
        Checks if the object is a node which processes messages

        :rtype: bool
        """
        raise NotImplementedError("Subclasses need to implement this!")

    def is_generator(self):
        """
        Checks if the object is a generator for messages to send

        :rtype: bool
        """
        raise NotImplementedError("Subclasses need to implement this!")

    def _repr(self, attributes):
        """
        Return a text representation of the object.

        :param list(str) attributes: names of attributes of the object that
            will be included in the text representation
        """
        return "{0}({1})".format(
            self.__class__.__name__,
            ", ".join("{0}={1!r}".format(name, getattr(self, name)) for name
                      in attributes if getattr(self, name) is not None))
