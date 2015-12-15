# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call

from tlsfuzzer.tree import TreeNode

class TestTreeNode(unittest.TestCase):
    def test___init__(self):
        node = TreeNode()

        self.assertIsNotNone(node)
        self.assertIsNone(node.child)
        self.assertIsNone(node.next_sibling)

    def test_add_child(self):
        node = TreeNode()
        child = mock.MagicMock()

        ret = node.add_child(child)

        self.assertIs(child, ret)
        self.assertIs(node.child, child)

    def test_get_all_siblings(self):
        node = TreeNode()

        self.assertEqual([node], list(node.get_all_siblings()))

    def test_get_all_siblings_with_siblings(self):
        node = TreeNode()
        sibling = TreeNode()
        node.next_sibling = sibling

        self.assertEqual([node, sibling], list(node.get_all_siblings()))

    def test_is_command(self):
        node = TreeNode()
        with self.assertRaises(NotImplementedError):
            node.is_command()

    def test_is_generator(self):
        node = TreeNode()
        with self.assertRaises(NotImplementedError):
            node.is_generator()

    def test_is_expect(self):
        node = TreeNode()
        with self.assertRaises(NotImplementedError):
            node.is_expect()
