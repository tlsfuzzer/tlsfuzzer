try:
    import unittest2 as unittest
except ImportError:
    import unittest

import random
import math
import itertools
from tlsfuzzer.utils.summer import Summer


class TestSummer(unittest.TestCase):
    def test_default_zero(self):
        i = Summer()

        self.assertEqual(i, 0.0)

    def test___add__(self):
        i = Summer()

        x = i + 0.5

        self.assertEqual(x, 0.5)
        self.assertEqual(i, 0.0)

    def test___iadd__(self):
        i = Summer()

        x = i
        x += 0.5

        self.assertIs(x, i)
        self.assertEqual(i, 0.5)

    def test___radd__(self):
        i = Summer()

        x = 0.5 + i

        self.assertEqual(x, 0.5)

    def test_sum_to_one(self):
        vals = [10 ** random.uniform(-50, 50) for _ in range(20)]
        zero_sum = vals + [-i for i in vals]
        one_sum = [1.0/1024 for _ in range(1024)] + zero_sum
        random.shuffle(one_sum)

        i = Summer()
        i.update(one_sum)

        self.assertEqual(i, 1.0)

    def test_random_sum(self):
        vals = [10 ** random.uniform(-50, 50) * random.choice((-1, 1)) for _
                in range(20)]
        i = Summer()
        i.update(vals)

        self.assertEqual(i, math.fsum(vals))

    def test_ten_thousand(self):
        i = Summer()

        i.update(itertools.repeat(0.001, 10000))

        self.assertEqual(i, math.fsum(itertools.repeat(0.001, 10000)))

    def test_init_from_float(self):
        i = Summer(0.5)

        self.assertEqual(i, 0.5)

    def test_init_from_summer(self):
        i = Summer(0.5)
        x = Summer(i)

        self.assertIsNot(i, x)
        self.assertEqual(x, 0.5)

    def test_init_from_list(self):
        i = Summer([0.25, 0.25])

        self.assertEqual(i, 0.5)

    def test___float__(self):
        i = Summer(0.5)

        self.assertIsInstance(float(i), float)
        self.assertEqual(float(i), 0.5)
