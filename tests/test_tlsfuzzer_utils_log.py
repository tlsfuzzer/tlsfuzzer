# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
except ImportError:
    import unittest.mock as mock

from tlsfuzzer.utils.log import Log


class TestLog(unittest.TestCase):
    def setUp(self):
        self.logfile = "test.log"

        # fix mock not supporting iterators
        self.mock_open = mock.mock_open()
        self.mock_open.return_value.__iter__ = lambda s: s
        self.mock_open.return_value.__next__ = lambda s: s.readline()

        with mock.patch('tlsfuzzer.utils.log', self.mock_open):
            self.log = Log(self.logfile)

    def test_classes(self):
        self.log.start_log(["A", "B", "C"])
        self.log.write()

        classes = self.log.get_classes()
        self.assertEqual(classes, ["A", "B", "C"])

    def test_add_run(self):
        classes = ["A", "B", "C"]
        self.log.start_log(classes)

        # add regular runs
        runs = [0, 2, 1, 2, 0, 1, 2, 1, 0]
        self.log.add_run(runs[0:3])
        self.log.add_run(runs[3:6])
        self.log.add_run(runs[6:9])

        self.log.write()

        i = 0
        for index in self.log.iterate_log():
            self.assertEqual(index, runs[i])
            i += 1
        self.assertEqual(i, len(runs))

    def test_shuffled_run(self):
        classes = ["A", "B", "C"]
        self.log.start_log(classes)

        num = 3
        for _ in range(num):
            self.log.shuffle_new_run()

        self.log.write()

        i = 0
        for index in self.log.iterate_log():
            self.assertTrue(0 <= index < len(classes))
            i += 1
        self.assertEqual(i, num * len(classes))

    def test_write_read(self):
        # set up first log with example data
        classes = ["A", "B", "C"]
        self.log.start_log(classes)

        for _ in range(3):
            self.log.shuffle_new_run()

        self.log.write()
        runs1 = list(self.log.iterate_log())

        # create a new log from the logfile
        with mock.patch('tlsfuzzer.utils.log', self.mock_open):
            log2 = Log(self.logfile)
        log2.read_log()
        runs2 = list(log2.iterate_log())

        self.assertEqual(log2.get_classes(), classes)
        self.assertEqual(runs1, runs2)
