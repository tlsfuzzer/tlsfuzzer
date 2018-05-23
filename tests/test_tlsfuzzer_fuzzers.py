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

from tlsfuzzer.fuzzers import structured_random_iter, StructuredRandom


class TestStructuredRandom(unittest.TestCase):
    def test_data(self):
        rand = StructuredRandom([(16, 0)])

        self.assertEqual(rand.data, bytearray([0] * 16))

    def test___repr__(self):
        rand = StructuredRandom([(16, 0)])

        self.assertEqual(str(rand), "StructuredRandom(vals=[(16, 0)])")

    def test_data_with_random(self):
        rand = StructuredRandom([(16, None)])

        self.assertEqual(len(rand.data), 16)
        self.assertGreater(len(set(rand.data)), 1)

    def test_min_eq_max(self):
        it = structured_random_iter(1, min_length=16, max_length=16, step=16)

        ret = [i for i in it]

        self.assertEqual(len(ret), 1)
        self.assertIsInstance(ret[0], StructuredRandom)
        self.assertEqual(len(ret[0].data), 16)

    def test_min_and_max(self):
        for _ in range(100):
            it = structured_random_iter(1, min_length=16, max_length=256,
                                        step=16)

            ret = [i for i in it]

            self.assertIn(len(ret), [1])
            for r in ret:
                self.assertIsInstance(r, StructuredRandom)
                self.assertIn(len(r.data), range(16, 257, 16))
                if r.vals[0][1] is not None:
                    self.assertEqual(r.data[0], r.vals[0][1])

