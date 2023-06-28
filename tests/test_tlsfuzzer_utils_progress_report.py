# Author: Hubert Kario, (c) 2023
# Released under Gnu GPL v2.0, see LICENSE file for details

try:
        import unittest2 as unittest
except ImportError:
        import unittest

from tlsfuzzer.utils.progress_report import _format_seconds, _binary_prefix

class TestFormatSeconds(unittest.TestCase):
    def test_days(self):
        self.assertEquals(_format_seconds(60 * 60 * 24 * 3),
                          " 3d  0h  0m  0.00s")

    def test_hours(self):
        self.assertEquals(_format_seconds(60 * 60 * 4),
                          " 4h  0m  0.00s")

    def test_minutes(self):
        self.assertEquals(_format_seconds(60 * 15), "15m  0.00s")

    def test_all(self):
        self.assertEquals(_format_seconds(
            60 * 60 * 24 * 4 +
            60 * 60 * 5 +
            60 * 14 +
            7), " 4d  5h 14m  7.00s")
