# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import tempfile
from os.path import join
from shutil import rmtree
from tlsfuzzer.utils.log import Log


class TestLog(unittest.TestCase):
    def setUp(self):
        # setup temp dir
        self.tmpdir = tempfile.mkdtemp()
        self.logfile = join(self.tmpdir, "test.log")
    
    def tearDown(self):
        # clean up
        rmtree(self.tmpdir, ignore_errors=True)
    
    def test_classes(self):
        log = Log(self.logfile)

        log.start_log(["A", "B", "C"])
        log.write()

        classes = log.get_classes()
        self.assertEqual(classes, ["A", "B", "C"])

    def test_add_run(self):
        log = Log(self.logfile)
        classes = ["A", "B", "C"]
        log.start_log(classes)

        # add regular runs
        runs = [0, 2, 1, 2, 0, 1, 2, 1, 0]
        log.add_run(runs[0:3])
        log.add_run(runs[3:6])
        log.add_run(runs[6:9])

        log.write()

        i = 0
        for index in log.iterate_log():
            self.assertEqual(index, runs[i])
            i += 1
        self.assertEqual(i, len(runs))

    def test_shuffled_run(self):
        log = Log(self.logfile)
        classes = ["A", "B", "C"]
        log.start_log(classes)

        num = 3
        for _ in range(num):
            log.shuffle_new_run()
    
        log.write()
        
        i = 0
        for index in log.iterate_log():
            self.assertTrue(0 <= index < len(classes))
            i += 1
        self.assertEqual(i, num * len(classes))

    def test_write_read(self):
        # set up first log with example data
        log1 = Log(self.logfile)
        classes = ["A", "B", "C"]
        log1.start_log(classes)

        for _ in range(3):
            log1.shuffle_new_run()

        log1.write()
        runs1 = [index for index in log1.iterate_log()]

        # create a new log from the logfile
        log2 = Log(self.logfile)
        log2.read_log()
        runs2 = [index for index in log2.iterate_log()]

        self.assertEqual(log2.get_classes(), classes)
        self.assertEqual(runs1, runs2)
