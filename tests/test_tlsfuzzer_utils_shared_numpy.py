try:
    import unittest2 as unittest
except ImportError:
    import unittest

import sys
import tempfile
import pickle
from itertools import repeat, chain, cycle, islice
failed_import = False
try:
    # can't test numpy proxy classes without numpy
    import numpy as np
except ImportError:
    failed_import = True


if not failed_import:
    from tlsfuzzer.utils.shared_numpy import SharedMemmap, SharedNDarray


@unittest.skipIf(failed_import,
                "Numpy missing")
class TestSharedMemmap(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backing_file = tempfile.NamedTemporaryFile()
        cls.dtype = [('block', np.int64),
                     ('group', np.int32),
                     ('value', np.float64)]
        shared_memmap = SharedMemmap(
            cls.backing_file.name,
            dtype=cls.dtype,
            mode="w+",
            shape=(1000, 1),
            order="C")

        shared_memmap['block'][:,0] = \
            list(chain(*[repeat(i, 4) for i in range(1000//4)]))
        shared_memmap['group'][:,0] = list(islice(cycle(range(4)), 1000))

        # write data to disk
        del shared_memmap

        cls.shared_memmap = SharedMemmap(
            cls.backing_file.name,
            dtype=cls.dtype,
            mode="r+",
            shape=(1000, 1),
            order="C")

    def test_sanity(self):
        self.assertIsNotNone(self.shared_memmap)

    def test_pickle(self):
        x = pickle.dumps(self.shared_memmap)
        self.assertLess(len(x), self.shared_memmap.value.nbytes)

    def test_pickle_load(self):
        x = pickle.dumps(self.shared_memmap)
        ret = pickle.loads(x)
        self.assertEqual(ret['block'][4], 1)
        self.assertEqual(ret['group'][3], 3)
        self.assertEqual(ret['group'][4], 0)
        self.assertEqual(ret['block'][-1], 249)

        self.assertEqual(len(self.shared_memmap), len(ret))

        self.assertTrue(all(i == j for i, j in zip(self.shared_memmap, ret)))

    def test_with_specified_column(self):
        x = SharedMemmap(
            self.backing_file.name,
            dtype=self.dtype,
            shape=(1000, 1),
            column="group")

        self.assertEqual(list(x[0:8]), [0, 1, 2, 3, 0, 1, 2, 3])

    @classmethod
    def tearDownClass(cls):
        cls.backing_file.close()


@unittest.skipIf(failed_import or sys.version_info < (3, 8),
                "Numpy missing or too old Python")
class TestSharedNDarray(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.shared_array = SharedNDarray(np.array(range(1000), dtype=np.int64))

    def test_sanity(self):
        self.assertIsNotNone(self.shared_array)

    def test_values(self):
        self.assertEqual(len(self.shared_array), 1000)
        self.assertEqual([0, 1, 2, 3, 4], list(self.shared_array[:5]))
        self.assertTrue(
            all(i == j for i, j in zip(self.shared_array, range(1000))))

    def test_pickle(self):
        x = pickle.dumps(self.shared_array)

        self.assertLess(len(x), self.shared_array.value.nbytes)

    def test_pickle_load(self):
        x = pickle.dumps(self.shared_array)

        ret = pickle.loads(x)

        self.assertTrue(
            all(i == j for i, j in zip(self.shared_array, ret)))

    @classmethod
    def tearDownClass(cls):
        cls.shared_array.shm.close()
        cls.shared_array.shm.unlink()
        del cls.shared_array
