# Author Hubert Kario, copyright (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
except ImportError:
    import unittest.mock as mock

import sys

from tlsfuzzer.combine import help_msg, get_format, read_row_based_csv, \
    read_column_based_csv, main, combine, combine_measurements

if sys.version_info < (3, 0):
    BUILTIN_PRINT = "__builtin__.print"
else:
    BUILTIN_PRINT = "builtins.print"


class TestHelpMsg(unittest.TestCase):
    @mock.patch(BUILTIN_PRINT)
    def test_help(self, mock_print):
        help_msg()
        mock_print.assert_called_once()
        self.assertIn('--help', mock_print.call_args[0][0])


class TestGetFormat(unittest.TestCase):
    def test_with_col_based_file(self):
        with mock.patch("__main__.__builtins__.open",
                mock.mock_open(read_data='hed,er\n1,2\n2,3\n3,4\n4,5')) \
                as mock_open:
            self.assertEqual(get_format("./non-existant"), "column-based")

    def test_with_row_based_file(self):
        with mock.patch("__main__.__builtins__.open",
                mock.mock_open(read_data='hed,1,2,3,4\ner,2,3,4,5')) \
                as mock_open:
            self.assertEqual(get_format("./non-existant"), "row-based")

    def test_with_quoted_comma(self):
        with mock.patch("__main__.__builtins__.open",
                mock.mock_open(read_data='"head, torso",1,2,3,4\ner,2,3,4,5'))\
                as mock_open:
            self.assertEqual(get_format("./non-existant"), "row-based")

    def test_with_wrong_quote(self):
        with mock.patch("__main__.__builtins__.open",
                mock.mock_open(read_data='"head, torso,1,2,3,4\ner,2,3,4,5'))\
                as mock_open:
            with self.assertRaises(ValueError):
                self.assertEqual(get_format("./non-existant"), "row-based")

    @unittest.skipIf(sys.version_info < (2, 7),
                     "mock_open doesn't work correctly in mock v2.0.0")
    def test_with_empty_file(self):
        with mock.patch("__main__.__builtins__.open",
                mock.mock_open(read_data=''))\
                as mock_open:
            with self.assertRaises(ValueError) as exc:
                get_format("./non-existant")
            self.assertIn("Empty file", str(exc.exception))

    def test_with_single_column(self):
        with mock.patch("__main__.__builtins__.open",
                mock.mock_open(read_data='heder\n1\n2\n3\n4')) \
                as mock_open:
            self.assertEqual(get_format("./non-existant"), "column-based")


class TestParseFile(unittest.TestCase):
    parsed_data = [['A', 'B', 'C'],
                   ['1', '2', '3'],
                   ['4', '5', '6'],
                   ['7', '8', '9'],
                   ['10', '11', '12']]

    row_based_file = "A,1,4,7,10\nB,2,5,8,11\nC,3,6,9,12"
    column_based_file = "A,B,C\n1,2,3\n4,5,6\n7,8,9\n10,11,12"

    @unittest.skipIf(sys.version_info < (2, 7),
                     "mock_open doesn't work correctly in mock v2.0.0")
    def test_row_based_file(self):
        with mock.patch("__main__.__builtins__.open",
                mock.mock_open(read_data=self.row_based_file))\
                as mock_open:
            self.assertEqual(
                list(read_row_based_csv('./non-existant')),
                self.parsed_data)

    @unittest.skipIf(sys.version_info < (2, 7),
                     "mock_open doesn't work correctly in mock v2.0.0")
    def test_column_based_file(self):
        with mock.patch("__main__.__builtins__.open",
                mock.mock_open(read_data=self.column_based_file))\
                as mock_open:
            self.assertEqual(
                list(read_column_based_csv('./non-existant')),
                self.parsed_data)


class TestCombine(unittest.TestCase):
    @unittest.skipIf(sys.version_info < (2, 7),
                     "mock_open doesn't work correctly in mock v2.0.0")
    def test_combine_same_row_format(self):
        open_write = mock.mock_open()
        def file_selector(file_name, mode):
            if file_name[:4] == "/tmp":
                return open_write(file_name, mode)
            elif file_name == "file1":
                return mock.mock_open(read_data="A,1,2,3,4\nB,5,6,7,8")\
                    (file_name, mode)
            assert file_name == "file2", file_name
            return mock.mock_open(read_data="A,10,11,12\nB,13,14,15")\
                (file_name, mode)

        open_mock = mock.MagicMock()
        open_mock.side_effect = file_selector

        with mock.patch("__main__.__builtins__.open", open_mock):
            combine("/tmp", ["file1", "file2"])

        calls = open_write().write.call_args_list

        exp = [mock.call("{0}\r\n".format(i)) for i in
               ("A,B", "1,5", "2,6", "3,7", "4,8", "10,13", "11,14",
                "12,15")]
        self.assertEqual(calls, exp)

    @unittest.skipIf(sys.version_info < (2, 7),
                     "mock_open doesn't work correctly in mock v2.0.0")
    def test_combine_different_row_format(self):
        open_write = mock.mock_open()
        def file_selector(file_name, mode):
            if file_name[:4] == "/tmp":
                return open_write(file_name, mode)
            elif file_name == "file1":
                return mock.mock_open(read_data="A,1,2,3,4\nB,5,6,7,8")\
                    (file_name, mode)
            assert file_name == "file2", file_name
            return mock.mock_open(read_data="A,B\n10,13\n11,14\n12,15")\
                (file_name, mode)

        open_mock = mock.MagicMock()
        open_mock.side_effect = file_selector

        with mock.patch("__main__.__builtins__.open", open_mock):
            combine("/tmp", ["file1", "file2"])

        calls = open_write().write.call_args_list

        exp = [mock.call("{0}\r\n".format(i)) for i in
               ("A,B", "1,5", "2,6", "3,7", "4,8", "10,13", "11,14",
                "12,15")]
        self.assertEqual(calls, exp)

    @unittest.skipIf(sys.version_info < (2, 7),
                     "mock_open doesn't work correctly in mock v2.0.0")
    def test_combine_mismatched_column_names(self):
        open_write = mock.mock_open()
        def file_selector(file_name, mode):
            if file_name[:4] == "/tmp":
                return open_write(file_name, mode)
            elif file_name == "file1":
                return mock.mock_open(read_data="A,1,2,3,4\nB,5,6,7,8")\
                    (file_name, mode)
            assert file_name == "file2", file_name
            return mock.mock_open(read_data="B,A\n10,13\n11,14\n12,15")\
                (file_name, mode)

        open_mock = mock.MagicMock()
        open_mock.side_effect = file_selector

        with mock.patch("__main__.__builtins__.open", open_mock):
            with self.assertRaises(ValueError) as err:
                combine("/tmp", ["file1", "file2"])
            self.assertIn("don't match column", str(err.exception))


class TestMeasurementsCombine(unittest.TestCase):

    @staticmethod
    def _mock_open(*args, **kwargs):
        """Fix mock not supporting iterators in all Python versions."""
        mock_open = mock.mock_open(*args, **kwargs)
        mock_open.return_value.__iter__ = lambda s: iter(s.readline, '')
        return mock_open

    def test_combine_measurements(self):
        open_write = self._mock_open()
        def file_selector(file_name, mode):
            if file_name[:4] == "/tmp":
                return open_write(file_name, mode)
            elif file_name == "file1":
                return self._mock_open(
                    read_data="0,256,1\n0,255,100\n1,256,2\n1,254,101"
                )(file_name, mode)
            assert file_name == "file2", file_name
            return self._mock_open(
                read_data="0,256,3\n0,255,102\n0,254,103\n1,256,4\n1,254,104"
            )(file_name, mode)

        open_mock = mock.MagicMock()
        open_mock.side_effect = file_selector

        with mock.patch("__main__.__builtins__.open", open_mock):
            combine_measurements("/tmp", ["file1", "file2"])

        calls = open_write().write.call_args_list

        exp = [mock.call("{0}\n".format(i)) for i in
               ("0,256,1", "0,255,100", "1,256,2", "1,254,101", "2,256,3",
                "2,255,102", "2,254,103", "3,256,4", "3,254,104")]
        self.assertEqual(calls[:-1], exp)

    def test_combine_measurements_wrong_format(self):
        open_write = self._mock_open()
        def file_selector(file_name, mode):
            if file_name[:4] == "/tmp":
                return open_write(file_name, mode)
            elif file_name == "file1":
                return self._mock_open(
                    read_data="0,256,1\n0,255,100\n1,256,2\n1,254,101"
                )(file_name, mode)
            assert file_name == "file2", file_name
            return self._mock_open(
                read_data="0,256,3\n0,255,102\n0,254,103\n1,256\n1,254,104"
            )(file_name, mode)

        open_mock = mock.MagicMock()
        open_mock.side_effect = file_selector

        with mock.patch("__main__.__builtins__.open", open_mock):
            with self.assertRaises(ValueError) as e:
                combine_measurements("/tmp", ["file1", "file2"])

        self.assertIn("File does not have correct format",str(e.exception))


class TestMain(unittest.TestCase):
    @mock.patch(BUILTIN_PRINT)
    def test_help(self, mock_print):
        args = ["./combine.py", "--help"]

        with mock.patch("sys.argv", args):
            with self.assertRaises(SystemExit):
                main()

        self.assertIn("--help", mock_print.call_args[0][0])

    def test_missing_params(self):
        args = ["./combine.py"]

        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError) as err:
                main()

        self.assertIn("No input files", str(err.exception))

    def test_missing_output_file(self):
        args = ["combine.py", "./some/input/file.csv"]

        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError) as err:
                main()

        self.assertIn("No output", str(err.exception))

    @mock.patch('tlsfuzzer.combine.combine_measurements')
    @mock.patch('tlsfuzzer.combine.combine')
    def test_correct_call(self, mock_combine, mock_combine_measurements):
        args = ["combine.py", "-o", "/tmp/output",
                "./input1.csv", "./input2.csv"]

        with mock.patch("sys.argv", args):
            main()

        mock_combine.assert_called_once_with(
            "/tmp/output", ["./input1.csv", "./input2.csv"])
        mock_combine_measurements.assert_not_called()

    @mock.patch('tlsfuzzer.combine.combine_measurements')
    @mock.patch('tlsfuzzer.combine.combine')
    def test_measurements_call(self, mock_combine, mock_combine_measurements):
        args = ["combine.py", "--long-format", "-o", "/tmp/output",
                "./input1.csv", "./input2.csv"]

        with mock.patch("sys.argv", args):
            main()

        mock_combine_measurements.assert_called_once_with(
            "/tmp/output", ["./input1.csv", "./input2.csv"])
        mock_combine.assert_not_called()
