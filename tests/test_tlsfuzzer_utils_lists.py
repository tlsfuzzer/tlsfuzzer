try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlsfuzzer.utils.lists import natural_sort_keys

class TestNaturalSortKeys(unittest.TestCase):
    def test_with_dict(self):
        a = {"a20": "something", "a100": "else"}
        b = sorted(a, key=natural_sort_keys)
        self.assertEqual(["a20", "a100"], b)
