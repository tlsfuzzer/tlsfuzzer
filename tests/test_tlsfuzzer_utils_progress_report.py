# Author: Hubert Kario, (c) 2023
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
from threading import Event, Thread
try:
    import unittest2 as unittest
except ImportError:
    import unittest
try:
    import mock
except ImportError:
    import unittest.mock as mock
import sys
import time

from tlsfuzzer.utils.progress_report import _format_seconds, _binary_prefix, \
        progress_report

if sys.version_info < (3, 0):
    BUILTIN_PRINT = "__builtin__.print"
else:
    BUILTIN_PRINT = "builtins.print"


class TestFormatSeconds(unittest.TestCase):
    def test_days(self):
        self.assertEqual(_format_seconds(60 * 60 * 24 * 3),
                          " 3d  0h  0m  0.00s")

    def test_hours(self):
        self.assertEqual(_format_seconds(60 * 60 * 4),
                          " 4h  0m  0.00s")

    def test_minutes(self):
        self.assertEqual(_format_seconds(60 * 15), "15m  0.00s")

    def test_all(self):
        self.assertEqual(_format_seconds(
            60 * 60 * 24 * 4 +
            60 * 60 * 5 +
            60 * 14 +
            7), " 4d  5h 14m  7.00s")


class TestBinaryPrefix(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(_binary_prefix(12), "12.00")

    def test_kilobytes(self):
        self.assertEqual(_binary_prefix(1024*12), "12.00ki")


class TestInvalidInputs(unittest.TestCase):
    def test_wrong_status(self):
        with self.assertRaises(ValueError) as e:
            progress_report([0, 1, 2, 3])

        self.assertIn("status is not a 3 element", str(e.exception))

    def test_wrong_prefix(self):
        with self.assertRaises(AssertionError):
            progress_report([0, 1, 2], prefix="none")


class TestOperation(unittest.TestCase):
    @mock.patch(BUILTIN_PRINT)
    def test_with_binary_prefix(self, mock_print):
        status = [10000, 100000, Event()]
        params = {'prefix': 'binary', 'delay': 0.001}
        progress = Thread(target=progress_report, args=(status,),
                          kwargs=params)
        progress.start()
        while not mock_print.mock_calls:
            pass
        status[2].set()
        progress.join()
        self.assertIn('Done:  10.00%', str(mock_print.mock_calls[0]))

    @mock.patch(BUILTIN_PRINT)
    def test_with_bool(self, mock_print):
        status = [200, 1000, True]
        params = {'delay': 0.001}
        progress = Thread(target=progress_report, args=(status,),
                          kwargs=params)
        progress.start()
        while not mock_print.mock_calls:
            pass
        status[0] = 1000
        while len(mock_print.mock_calls) < 2:
            pass
        status[2] = False
        progress.join()
        self.assertIn('Done:  20.00%', str(mock_print.mock_calls[0]))
        self.assertIn('Done: 100.00%', str(mock_print.mock_calls[-1]))

    @mock.patch(BUILTIN_PRINT)
    def test_with_zero_start(self, mock_print):
        status = [0, 1000, True]
        params = {'delay': 0.001}
        progress = Thread(target=progress_report, args=(status,),
                          kwargs=params)
        progress.start()
        while not mock_print.mock_calls:
            pass
        status[0] = 1000
        while len(mock_print.mock_calls) < 2:
            pass
        status[2] = False
        progress.join()
        self.assertIn('Done:   0.00%', str(mock_print.mock_calls[0]))
        self.assertIn('Done: 100.00%', str(mock_print.mock_calls[-1]))
