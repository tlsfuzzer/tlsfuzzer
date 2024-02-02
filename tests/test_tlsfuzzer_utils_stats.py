try:
    import unittest2 as unittest
except ImportError:
    import unittest

import random
failed_import = False
try:
    from tlsfuzzer.utils.stats import skillings_mack_result, \
        skillings_mack_test
    import numpy as np
except ImportError:
    failed_import = True


@unittest.skipIf(failed_import,
                 "Numpy missing")
class TestSkillingsMackTest(unittest.TestCase):
    def assertEqualApprox(self, a, b, eta=1e-6):
        if a > b * (1 + eta) or a < b * (1 - eta):
            raise AssertionError("{0} is not approximately equal {1}"
                                 .format(a, b))

    def test_with_duplcate_group_block_pairs(self):
        vals = [0, 0, 0]
        groups = [0, 1, 1]
        blocks = [0, 0, 0]

        with self.assertRaises(ValueError) as e:
            skillings_mack_test(vals, groups, blocks)

        self.assertIn("Duplicate group (1) in block (0)", str(e.exception))

    def test_empty_data(self):
        vals = []
        groups = []
        blocks = []
        with self.assertRaises(ValueError) as e:
            skillings_mack_test(vals, groups, blocks)

        self.assertIn("Empty data set", str(e.exception))

    def test_groups_not_compared(self):
        vals = [10, 20, 30]
        groups = [0, 1, 2]
        blocks = [0, 0, 1]

        with self.assertRaises(ValueError) as e:
            skillings_mack_test(vals, groups, blocks)

        self.assertIn("Groups with no comparisons found", str(e.exception))

    def test_blocks_not_sorted(self):
        vals = [10, 20, 30, 40, 50]
        groups = [0, 1, 2, 0, 2]
        blocks = [0, 0, 1, 1, 0]

        with self.assertRaises(ValueError) as e:
            skillings_mack_test(vals, groups, blocks)

        self.assertIn("blocks are not sorted", str(e.exception))

    def test_PMCMRplus_example(self):
        # check if it produces the same values as the example from PMCMRplus
        # R module documentation
        vals =   [3, 5, 15, 1, 3, 18, 5, 4, 21, 2, 6, 0, 2, 17, 0, 2, 10, 0,
                  3, 8, 0, 2, 13]
        groups = ['1', '2', '3', '1', '2', '3', '1', '2', '3', '1', '3', '1',
                  '2', '3', '1', '2', '3', '1', '2', '3', '1', '2', '3']
        blocks = [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
                  8, 8, 8]

        res = skillings_mack_test(vals, groups, blocks)

        self.assertIsInstance(res, skillings_mack_result)
        self.assertEqual(len(res), 3)

        self.assertEqualApprox(res.p_value, 0.001306405)
        self.assertEqualApprox(res.T, 13.28095)
        self.assertEqual(res.df, 2)

    def test_PMCMRplus_example_with_duplicate_use_last(self):
        # check if it produces the same values as the example from PMCMRplus
        # R module documentation
        vals =   [3, 5, 15, 1, 3, 18, 5, 4, 21, 2, 6, 0, 2, 17, 0, 2, 10, 0,
                  3, 8, 0, 2, 0, 13]
        groups = ['1', '2', '3', '1', '2', '3', '1', '2', '3', '1', '3', '1',
                  '2', '3', '1', '2', '3', '1', '2', '3', '1', '2', '3', '3']
        blocks = [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
                  8, 8, 8, 8]

        res = skillings_mack_test(vals, groups, blocks, duplicates="last")

        self.assertIsInstance(res, skillings_mack_result)
        self.assertEqual(len(res), 3)

        self.assertEqualApprox(res.p_value, 0.001306405)
        self.assertEqualApprox(res.T, 13.28095)
        self.assertEqual(res.df, 2)

    def test_PMCMRplus_example_with_duplicate_use_first(self):
        # check if it produces the same values as the example from PMCMRplus
        # R module documentation
        vals =   [3, 5, 15, 1, 3, 18, 5, 4, 21, 2, 6, 0, 2, 17, 0, 2, 10, 0,
                  3, 8, 0, 2, 13, 0]
        groups = ['1', '2', '3', '1', '2', '3', '1', '2', '3', '1', '3', '1',
                  '2', '3', '1', '2', '3', '1', '2', '3', '1', '2', '3', '3']
        blocks = [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
                  8, 8, 8, 8]

        res = skillings_mack_test(vals, groups, blocks, duplicates="first")

        self.assertIsInstance(res, skillings_mack_result)
        self.assertEqual(len(res), 3)

        self.assertEqualApprox(res.p_value, 0.001306405)
        self.assertEqualApprox(res.T, 13.28095)
        self.assertEqual(res.df, 2)

    def test_example_with_many_missing_values(self):
        vals = [3, 5, 15, 4, 1, 3, 5, 4, 21, 5, 2, 6, 0, 2, 17, 0, 2, 10, 0,
                3, 5, 0, 2, 13]
        groups = [1, 2, 3, 5, 1, 2, 1, 2, 3, 4, 1, 3, 1, 2, 3, 1, 2, 3, 1, 2,
                  4, 1, 2, 3]
        blocks = [1, 1, 1, 1, 2, 2, 3, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7,
                  7, 8, 8, 8]

        res = skillings_mack_test(vals, groups, blocks)

        self.assertEqualApprox(res.p_value, 0.01378318)
        self.assertEqualApprox(res.T, 12.53551)
        self.assertEqual(res.df, 4)

    def test_large_sample_with_obvious_difference(self):
        vals = []
        groups = []
        blocks = []
        for b in range(1000):
            for g in range(10):
                if random.uniform(0, 1) < 2**(-g):
                    if g != 2:
                        vals.append(random.gauss(0, 1))
                    else:
                        vals.append(random.gauss(2, 1))
                    groups.append(g)
                    blocks.append(b)

        res = skillings_mack_test(vals, groups, blocks)

        self.assertLess(res.p_value, 1e-6)

    def test_large_sample_with_no_difference(self):
        vals = []
        groups = []
        blocks = []
        for b in range(1000):
            for g in range(10):
                if random.uniform(0, 1) < 2**(-g):
                    vals.append(random.gauss(0, 1))
                    groups.append(g)
                    blocks.append(b)

        res = skillings_mack_test(vals, groups, blocks)

        self.assertGreater(res.p_value, 1e-6)
