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
        self.log = Log(self.logfile)

    @staticmethod
    def _mock_open(*args, **kwargs):
        """Fix mock not supporting iterators in all Python versions."""
        mock_open = mock.mock_open(*args, **kwargs)
        mock_open.return_value.__iter__ = lambda s: iter(s.readline, '')
        return mock_open

    def test_write_classes(self):
        with mock.patch('__main__.__builtins__.open', self._mock_open()) as mock_file:
            self.log.start_log(["A", "B", "C"])
            self.log.write()
            mock_file.return_value.write.assert_called_once_with("A,B,C\r\n")
            mock_file.return_value.close.assert_called_once_with()

    def test_read_classes(self):
        with mock.patch('__main__.__builtins__.open', self._mock_open(read_data="A,B,C\r\n")):
            classes = self.log.get_classes()
            self.assertEqual(classes, ["A", "B", "C"])

    def test_add_run(self):
        with mock.patch('__main__.__builtins__.open', self._mock_open()) as mock_file:
            classes = ["A", "B", "C"]
            self.log.start_log(classes)
            mock_file.return_value.write.assert_called_with("A,B,C\r\n")
            # add regular runs
            runs = [0, 2, 1, 2, 0, 1, 2, 1, 0]
            self.log.add_run(runs[0:3])
            mock_file.return_value.write.assert_called_with("0,2,1\r\n")

            self.log.add_run(runs[3:6])
            mock_file.return_value.write.assert_called_with("2,0,1\r\n")
            self.log.add_run(runs[6:9])
            mock_file.return_value.write.assert_called_with("2,1,0\r\n")

            self.log.write()
            mock_file.return_value.close.assert_called_once()

    def test_read_run(self):
        runs = [0, 2, 1, 2, 0, 1, 2, 1, 0]
        i = 0
        with mock.patch('__main__.__builtins__.open',
                        self._mock_open(read_data="A,B,C\r\n0,2,1\r\n2,0,1\r\n2,1,0\r\n")):
            for index in self.log.iterate_log():
                self.assertEqual(index, runs[i])
                i += 1
        self.assertEqual(i, len(runs))

    def test_shuffled_run(self):
        def check_indexes(class_count, line):
            indexes = line.strip().split(',')
            self.assertTrue(all(indexes) in range(0, class_count))

        with mock.patch('__main__.__builtins__.open', self._mock_open()) as mock_file:
            classes = ["A", "B", "C"]
            self.log.start_log(classes)
            mock_file.return_value.write.side_effect = lambda s: check_indexes(len(classes), s)
            num = 3
            for _ in range(num):
                self.log.shuffle_new_run()
            self.assertEqual(mock_file.return_value.write.call_count, 4)
