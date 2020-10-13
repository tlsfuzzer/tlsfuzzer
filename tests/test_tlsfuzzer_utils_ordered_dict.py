# Author: Hubert Kario, (c) 2017
# Released under Gnu GPL v2.0, see LICENSE file for details

try:
        import unittest2 as unittest
except ImportError:
        import unittest

from tlsfuzzer.utils.ordered_dict import OrderedDict

class TestOrderedDict(unittest.TestCase):
    def setUp(self):
        self.d = OrderedDict()
        self.d[1] = "a"
        self.d[2] = "b"
        self.d[3] = "c"

    def test___init__(self):
        d = OrderedDict()

        self.assertIsInstance(d, dict)

    def test___init___with_invalid_params(self):
        with self.assertRaises(TypeError):
            OrderedDict(12, "a")

    def test___init___with_dict(self):
        d = OrderedDict({12: "a", 14: "b"})

        self.assertEqual({12: "a", 14: "b"}, d)

    def test_add_in_order(self):
        d = OrderedDict()
        d[1] = "a"
        d[2] = "b"
        d[3] = "c"
        d[4] = "d"
        d[5] = "e"
        d[6] = "f"
        d[7] = "g"

        self.assertEqual([1, 2, 3, 4, 5, 6, 7], list(d.keys()))
        self.assertEqual(["a", "b", "c", "d", "e", "f", "g"], list(d.values()))

    def test_del(self):
        del self.d[2]

        self.assertEqual([1, 3], list(self.d.keys()))
        self.assertEqual(["a", "c"], list(self.d.values()))

    def test_iter(self):
        self.assertEqual([1, 2, 3], list(iter(self.d)))

    def test_popitem(self):
        n, v = self.d.popitem()

        self.assertEqual(n, 3)
        self.assertEqual(v, "c")
        self.assertEqual([1, 2], list(self.d.keys()))
        self.assertEqual(["a", "b"], list(self.d.values()))

    def test_popitem_on_empty(self):
        d = OrderedDict()

        with self.assertRaises(KeyError):
            d.popitem()

    def test_popitem_first(self):
        if type(self.d) is dict:
            self.skipTest("not popitem(last=False) in dict")
        else:
            n, v = self.d.popitem(last=False)

            self.assertEqual(n, 1)
            self.assertEqual(v, "a")
            self.assertEqual([2, 3], list(self.d.keys()))
            self.assertEqual(["b", "c"], list(self.d.values()))

    def test_items(self):
        self.assertEqual([(1, "a"), (2, "b"), (3, "c")], list(self.d.items()))

    def test_iterkeys(self):
        if type(self.d) is dict:
            self.skipTest("no iterkeys in dict")
        else:
            self.assertEqual(list(self.d.iterkeys()), list(iter(self.d)))

    def test_clear(self):
        self.d.clear()
        self.assertEqual([], list(self.d.items()))

    def test_itervalues(self):
        if type(self.d) is dict:
            self.skipTest("no itervalues in dict")
        else:
            self.assertEqual(list(self.d.itervalues()), self.d.values())

    def test_update_with_too_many_args(self):
        with self.assertRaises(TypeError):
            self.d.update(0, None)

    def test_update_with_dict(self):
        self.d.update({0: None})

        self.assertEqual([(1, "a"), (2, "b"), (3, "c"), (0, None)],
                         list(self.d.items()))

    def test_update_with_list_of_tuples(self):
        d = OrderedDict()
        d.update([(3, "c"), (2, "b"), (1, "a")])
        self.assertEqual([3, 2, 1], list(d.keys()))
        self.assertEqual(["c", "b", "a"], list(d.values()))

    def test_update_with_keyword_args(self):
        d = OrderedDict()
        d.update(a='1', b='2', c='3')
        self.assertEqual(set(['1', '2', '3']), set(d.values()))
        self.assertEqual(set(['a', 'b', 'c']), set(d.keys()))

    def test_pop(self):
        v = self.d.pop(2)
        self.assertEqual(v, "b")

        self.assertEqual([(1, "a"), (3, "c")], list(self.d.items()))

    def test_pop_non_existent(self):
        with self.assertRaises(KeyError):
            self.d.pop(4)

    def test_pop_with_default(self):
        if type(self.d) is dict:
            a = self.d.pop(0, "foo")
            self.assertEqual(a, "foo")
        else:
            a = self.d.pop(0, default="foo")
            self.assertEqual(a, "foo")

    def test_repr(self):
        if type(self.d) is dict:
            self.assertEqual("{1: 'a', 2: 'b', 3: 'c'}",
                             repr(self.d))
        else:
            self.assertEqual("OrderedDict([(1, 'a'), (2, 'b'), (3, 'c')])",
                             repr(self.d))

    def test_repr_with_circular_dependancy(self):
        del self.d[2]
        self.d[2] = self.d

        if type(self.d) is dict:
            self.assertEqual("{1: 'a', 3: 'c', 2: {...}}",
                             repr(self.d))
        else:
            self.assertEqual("OrderedDict([(1, 'a'), (3, 'c'), (2, ...)])",
                             repr(self.d))

    def test_repr_with_empty(self):
        d = OrderedDict()

        if type(self.d) is dict:
            self.assertEqual("{}", repr(d))
        else:
            self.assertEqual("OrderedDict()", repr(d))

    def test_compare_different_order(self):
        d2 = OrderedDict()
        d2[1] = "a"
        d2[3] = "c"
        d2[2] = "b"

        self.assertNotEqual(list(self.d.items()), list(d2.items()))
