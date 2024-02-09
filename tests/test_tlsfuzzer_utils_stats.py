try:
    import unittest2 as unittest
except ImportError:
    import unittest

import random
failed_import = False
try:
    from tlsfuzzer.utils.stats import skillings_mack_result, \
        skillings_mack_test, _block_slices, _slices, _summarise_chunk, \
        _set_unique
    import tlsfuzzer.utils.stats
    import numpy as np
except ImportError:
    failed_import = True


@unittest.skipIf(failed_import,
                 "Numpy missing")
class TestSummariseChunk(unittest.TestCase):
    def assertEqualApprox(self, a, b, eta=1e-6):
        if abs(a - b) > (min(abs(a), abs(b)) * eta):
            raise AssertionError("{0} is not approximately equal {1}"
                                 .format(a, b))

    def test_summarise_chunk(self):
        tlsfuzzer.utils.stats._values = \
            [3, 5, 15, 1, 3, 18, 5, 4, 21, 2, 6, 0, 2, 17, 0, 2, 10, 0,
             3, 8, 0, 2, 13]
        tlsfuzzer.utils.stats._groups = \
            ['1', '2', '3', '1', '2', '3', '1', '2', '3', '1', '3', '1',
             '2', '3', '1', '2', '3', '1', '2', '3', '1', '2', '3']
        all_groups = set(tlsfuzzer.utils.stats._groups)
        len_groups = len(tlsfuzzer.utils.stats._groups)
        tlsfuzzer.utils.stats._blocks = \
            [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
             8, 8, 8]

        ret = _summarise_chunk((all_groups, None, (0, len_groups)))

        progress, adjusted_ranks, block_counts, pair_counts = ret

        self.assertEqual(progress, len_groups)
        self.assertEqual(len(adjusted_ranks), 3)
        self.assertEqualApprox(adjusted_ranks['3'], 13.124355652982139)
        self.assertEqualApprox(adjusted_ranks['1'], -11.392304845413262)
        self.assertEqualApprox(adjusted_ranks['2'], -1.7320508075688772)
        self.assertEqual(block_counts, {'2': 14, '1': 15, '3': 15})
        self.assertEqual(pair_counts,
            {frozenset(['2', '1']): 7, frozenset(['3', '1']): 8,
             frozenset(['3', '2']): 7})

    def test_summarise_chunk_duplicate_use_last(self):
        # check if it produces the same values as the example from PMCMRplus
        # R module documentation
        tlsfuzzer.utils.stats._values = \
                [3, 5, 15, 1, 3, 18, 5, 4, 21, 2, 6, 0, 2, 17, 0, 2, 10, 0,
                  3, 8, 0, 2, 0, 13]
        tlsfuzzer.utils.stats._groups = \
                ['1', '2', '3', '1', '2', '3', '1', '2', '3', '1', '3', '1',
                  '2', '3', '1', '2', '3', '1', '2', '3', '1', '2', '3', '3']
        all_groups = set(tlsfuzzer.utils.stats._groups)
        len_groups = len(tlsfuzzer.utils.stats._groups)
        tlsfuzzer.utils.stats._blocks = \
                [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
                  8, 8, 8, 8]

        ret = _summarise_chunk((all_groups, 'last', (0, len_groups)))

        progress, adjusted_ranks, block_counts, pair_counts = ret

        self.assertEqual(progress, len_groups)
        self.assertEqual(len(adjusted_ranks), 3)
        self.assertEqualApprox(adjusted_ranks['3'], 13.124355652982139)
        self.assertEqualApprox(adjusted_ranks['1'], -11.392304845413262)
        self.assertEqualApprox(adjusted_ranks['2'], -1.7320508075688772)
        self.assertEqual(block_counts, {'2': 14, '1': 15, '3': 15})
        self.assertEqual(pair_counts,
            {frozenset(['2', '1']): 7, frozenset(['3', '1']): 8,
             frozenset(['3', '2']): 7})

    def test_summarise_chunk_duplicates(self):
        # check if it produces the same values as the example from PMCMRplus
        # R module documentation
        tlsfuzzer.utils.stats._values = \
                [3, 5, 15, 1, 3, 18, 5, 4, 21, 2, 6, 0, 2, 17, 0, 2, 10, 0,
                  3, 8, 0, 2, 0, 13]
        tlsfuzzer.utils.stats._groups = \
                ['1', '2', '3', '1', '2', '3', '1', '2', '3', '1', '3', '1',
                  '2', '3', '1', '2', '3', '1', '2', '3', '1', '2', '3', '3']
        all_groups = set(tlsfuzzer.utils.stats._groups)
        len_groups = len(tlsfuzzer.utils.stats._groups)
        tlsfuzzer.utils.stats._blocks = \
                [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
                  8, 8, 8, 8]

        with self.assertRaises(ValueError) as e:
            ret = _summarise_chunk((all_groups, None, (0, len_groups)))

        self.assertIn("Duplicate group (3) in block (8)", str(e.exception))

    def test_summarise_chunk_duplicate_use_first(self):
        # check if it produces the same values as the example from PMCMRplus
        # R module documentation
        tlsfuzzer.utils.stats._values = \
                [3, 5, 15, 1, 3, 18, 5, 4, 21, 2, 6, 0, 2, 17, 0, 2, 10, 0,
                  3, 8, 0, 2, 13, 0]
        tlsfuzzer.utils.stats._groups = \
                ['1', '2', '3', '1', '2', '3', '1', '2', '3', '1', '3', '1',
                  '2', '3', '1', '2', '3', '1', '2', '3', '1', '2', '3', '3']
        all_groups = set(tlsfuzzer.utils.stats._groups)
        len_groups = len(tlsfuzzer.utils.stats._groups)
        tlsfuzzer.utils.stats._blocks = \
                [1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7,
                  8, 8, 8, 8]

        ret = _summarise_chunk((all_groups, 'first', (0, len_groups)))

        progress, adjusted_ranks, block_counts, pair_counts = ret

        self.assertEqual(progress, len_groups)
        self.assertEqual(len(adjusted_ranks), 3)
        self.assertEqualApprox(adjusted_ranks['3'], 13.124355652982139)
        self.assertEqualApprox(adjusted_ranks['1'], -11.392304845413262)
        self.assertEqualApprox(adjusted_ranks['2'], -1.7320508075688772)
        self.assertEqual(block_counts, {'2': 14, '1': 15, '3': 15})
        self.assertEqual(pair_counts,
            {frozenset(['2', '1']): 7, frozenset(['3', '1']): 8,
             frozenset(['3', '2']): 7})

    def test_summarise_not_sorted(self):
        tlsfuzzer.utils.stats._values = [10, 20, 30, 40, 50]
        tlsfuzzer.utils.stats._groups = [0, 1, 2, 0, 2]
        tlsfuzzer.utils.stats._blocks = [0, 0, 1, 1, 0]
        all_groups = set(tlsfuzzer.utils.stats._groups)
        len_groups = len(tlsfuzzer.utils.stats._groups)
        with self.assertRaises(ValueError) as e:
            ret = _summarise_chunk((all_groups, None, (0, len_groups)))

        self.assertIn("blocks are not sorted", str(e.exception))

    def test_summarise_empty(self):
        tlsfuzzer.utils.stats._values = []
        tlsfuzzer.utils.stats._groups = []
        tlsfuzzer.utils.stats._blocks = []
        all_groups = set(tlsfuzzer.utils.stats._groups)
        len_groups = len(tlsfuzzer.utils.stats._groups)
        with self.assertRaises(ValueError) as e:
            ret = _summarise_chunk((all_groups, None, (0, len_groups)))

        self.assertIn("Empty data set", str(e.exception))

    def test_set_unique(self):
        tlsfuzzer.utils.stats._groups = \
            ['1', '2', '3', '1', '2', '3', '1', '2', '3', '1', '3', '1',
             '2', '3', '1', '2', '3', '1', '2', '3', '1', '2', '3']

        self.assertEqual(_set_unique((0, 24)), set(['1', '2', '3']))


@unittest.skipIf(failed_import,
                 "Numpy missing")
class TestSkillingsMackTest(unittest.TestCase):
    def assertEqualApprox(self, a, b, eta=1e-6):
        if abs(a - b) > (min(abs(a), abs(b)) * eta):
            raise AssertionError("{0} is not approximately equal {1}"
                                 .format(a, b))

    def test_with_different_lengths(self):
        vals = [0, 0]
        groups = [0, 1, 2]
        blocks = [0, 0, 0]
        with self.assertRaises(ValueError) as e:
            skillings_mack_test(vals, groups, blocks)

        self.assertIn("must be the same length", str(e.exception))

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

        status = [0, 1, None]
        res = skillings_mack_test(vals, groups, blocks, status=status)

        self.assertEqual(status[0], len(groups))
        self.assertEqual(status[1], len(groups))
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


@unittest.skipIf(failed_import,
                 "Numpy missing")
class TestBlockSlices(unittest.TestCase):
    def test_chunk_larger_than_data(self):
        blocks = [0, 0, 1, 1]
        ret = list(_block_slices(blocks, 10))
        self.assertEqual(ret, [(0, 4)])

    def test_slice_on_chunk_bounary(self):
        blocks = [0, 0, 0, 1, 1, 1]
        ret = list(_block_slices(blocks, 3))
        self.assertEqual(ret, [(0, 3), (3, 6)])

    def test_slice_on_chunk_bounary_multiple_chunks(self):
        blocks = [0, 0, 1, 1, 2, 2, 3, 3]
        ret = list(_block_slices(blocks, 2))
        self.assertEqual(ret, [(0, 2), (2, 4), (4, 6), (6, 8)])

    def test_slice_not_on_chunk_boundary(self):
        blocks = [0, 0, 0, 1, 1, 1, 2, 2, 2]
        ret = list(_block_slices(blocks, 4))
        self.assertEqual(ret, [(0, 6), (6, 9)])

    def test_one_slice(self):
        blocks = [0, 0, 0, 0, 0, 0, 0, 0]
        ret = list(_block_slices(blocks, 3))
        self.assertEqual(ret, [(0, 8)])

    def test_one_slice_at_end(self):
        blocks = [0, 0, 0, 1, 1, 1, 1, 1, 1]
        ret = list(_block_slices(blocks, 2))
        self.assertEqual(ret, [(0, 3), (3, 9)])



@unittest.skipIf(failed_import,
                 "Numpy missing")
class TestSlices(unittest.TestCase):
    def test_empty(self):
        ret = list(_slices(0, 10))
        self.assertEqual(ret, [])

    def test_smaller_than_chunk(self):
        ret = list(_slices(4, 10))
        self.assertEqual(ret, [(0, 4)])

    def test_equal_to_chunk_size(self):
        ret = list(_slices(10, 10))
        self.assertEqual(ret, [(0, 10)])

    def test_multiple_slices(self):
        ret = list(_slices(10, 2))
        self.assertEqual(ret, [(0, 2), (2, 4), (4, 6), (6, 8), (8, 10)])

    def test_length_not_multiple_of_slice_length(self):
        ret = list(_slices(10, 4))
        self.assertEqual(ret, [(0, 4), (4, 8), (8, 10)])
