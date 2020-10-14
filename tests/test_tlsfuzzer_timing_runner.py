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

import io
import subprocess
from sys import version_info

from tlsfuzzer.timing_runner import TimingRunner
from tlsfuzzer.utils.statics import WARM_UP


def is_33():
    return (3, 3) == version_info[:2]


class TestRunner(unittest.TestCase):
    def setUp(self):
        with mock.patch('tlsfuzzer.timing_runner.os.mkdir'):
            with mock.patch('tlsfuzzer.timing_runner.TimingRunner.check_tcpdump'):
                self.runner = TimingRunner("test", [], "/outdir", "localhost", 4433, "lo")

    @staticmethod
    def _mock_open(*args, **kwargs):
        """Fix mock not supporting iterators in all Python versions."""
        mock_open = mock.mock_open(*args, **kwargs)
        mock_open.return_value.__iter__ = lambda s: iter(s.readline, '')
        return mock_open

    def test_init_without_tcpdump(self):
        mock_check = mock.Mock()
        mock_check.return_value = False
        with mock.patch('tlsfuzzer.timing_runner.os.mkdir'):
            with mock.patch('tlsfuzzer.timing_runner.TimingRunner.check_tcpdump', mock_check):
                self.assertRaises(Exception, TimingRunner, "test", [], "/outdir", "localhost", 4433, "lo")

    def test_check_tcpdump(self):
        mock_call = mock.Mock(spec=subprocess.check_call)

        def raise_error(*args, **kwargs):
            raise subprocess.CalledProcessError(1, "")

        with mock.patch("tlsfuzzer.timing_runner.subprocess.check_call", mock_call) as mock_c:
            ret = TimingRunner.check_tcpdump()
            mock_c.assert_called_once()
            self.assertTrue(ret)
            mock_c.side_effect = raise_error
            ret = TimingRunner.check_tcpdump()
            self.assertFalse(ret)

    def test_sniff(self):
        self.runner.tcpdump_running = False

        mock_popen = mock.Mock(spec=subprocess.Popen)
        mock_popen.return_value.stderr = io.BytesIO(b"listening\n")
        with mock.patch("tlsfuzzer.timing_runner.subprocess.Popen", mock_popen):
            self.runner.sniff()
            self.assertTrue(self.runner.tcpdump_running)

            mock_popen.return_value.stderr = io.BytesIO(b"\n")
            self.assertRaises(SystemExit, self.runner.sniff)
            self.assertFalse(self.runner.tcpdump_running)

    def test_tcpdump_status(self):
        mock_popen = mock.Mock(spec=subprocess.Popen)
        mock_popen.communicate.return_value = ("", b"Error")
        mock_popen.returncode = 1

        self.runner.tcpdump_running = True
        self.runner.tcpdump_status(mock_popen)
        self.assertFalse(self.runner.tcpdump_running)

        self.runner.tcpdump_running = False
        self.runner.tcpdump_status(mock_popen)
        self.assertFalse(self.runner.tcpdump_running)

    def test_generate_log_sanity(self):
        self.runner.tests = [("sanity", None), ("regular", None)]
        with mock.patch('__main__.__builtins__.open', mock.mock_open()) as mock_file:
            self.runner.generate_log(set(), set(), 10)
            self.assertEqual(self.runner.log.classes, ["regular"])
            self.assertEqual(self.runner.tests, {"regular": None})
            self.assertEqual(mock_file.return_value.write.call_count, 11)

    def test_generate_log_exclusion(self):
        self.runner.tests = [("regular", None), ("exclude", None)]
        with mock.patch('__main__.__builtins__.open', mock.mock_open()) as mock_file:
            self.runner.generate_log(set(), set(["exclude"]), 10)
            self.assertEqual(self.runner.log.classes, ["regular"])
            self.assertEqual(mock_file.return_value.write.call_count, 11)

    def test_generate_log_run_only(self):
        self.runner.tests = [("regular", None), ("exclude", None)]
        with mock.patch('__main__.__builtins__.open', mock.mock_open()) as mock_file:
            self.runner.generate_log(set(["regular"]), set(), 10)
            self.assertEqual(self.runner.log.classes, ["regular"])
            self.assertEqual(mock_file.return_value.write.call_count, 11)

    def test_create_dir(self):
        with mock.patch('tlsfuzzer.timing_runner.os.mkdir') as mock_mkdir:
            TimingRunner("test", [], "/outdir", "localhost", 4433, "lo")
            mock_mkdir.assert_called_once()

    def test_check_extraction_availability(self):
        extraction_present = True
        try:
            from tlsfuzzer.extract import Extract
        except ImportError:
            extraction_present = False

        self.assertEqual(TimingRunner.check_extraction_availability(), extraction_present)

    def test_check_analysis_availability(self):
        analysis_present = True
        try:
            from tlsfuzzer.analysis import Analysis
        except ImportError:
            analysis_present = False

        self.assertEqual(TimingRunner.check_analysis_availability(), analysis_present)

    def test_extract(self):
        check_extract = mock.Mock()
        check_extract.return_value = False

        with mock.patch("tlsfuzzer.timing_runner.TimingRunner.check_extraction_availability", check_extract):
            self.assertFalse(self.runner.extract())

        self.runner.log = mock.Mock(autospec=True)
        with mock.patch("__main__.__builtins__.__import__"):
            self.assertTrue(self.runner.extract())

    def test_analyse(self):
        check_analysis = mock.Mock()
        check_analysis.return_value = False

        with mock.patch("tlsfuzzer.timing_runner.TimingRunner.check_analysis_availability", check_analysis):
            self.assertEqual(self.runner.analyse(), 2)

        self.runner.log = mock.Mock(autospec=True)
        with mock.patch("__main__.__builtins__.__import__"):
            self.assertNotEqual(self.runner.analyse(), 2)

    def test_run(self):
        self.runner.tests = {"A": None, "B": None, "C": None}
        self.runner.tcpdump_running = True
        analyse = mock.Mock()
        analyse.return_value = 1
        with mock.patch('__main__.__builtins__.open',
                        self._mock_open(read_data="A,B,C\r\n0,2,1\r\n2,0,1\r\n2,1,0\r\n")):
            with mock.patch('tlsfuzzer.timing_runner.TimingRunner.sniff'):
                with mock.patch('tlsfuzzer.timing_runner.TimingRunner.extract') as extract:
                    with mock.patch('tlsfuzzer.timing_runner.TimingRunner.analyse', analyse):
                        with mock.patch('tlsfuzzer.timing_runner.Thread'):
                            with mock.patch('tlsfuzzer.timing_runner.time.sleep'):
                                with mock.patch('tlsfuzzer.timing_runner.Runner') as runner:
                                    ret = self.runner.run()
                                    self.assertEqual(runner.call_count, WARM_UP + 9)
                                    extract.assert_called_once()
                                    analyse.assert_called_once()
                                    self.assertEqual(ret, 1)

    def test_run_no_extraction(self):
        self.runner.tests = {"A": None, "B": None, "C": None}
        self.runner.tcpdump_running = True
        extract = mock.Mock()
        extract.return_value = False
        with mock.patch('__main__.__builtins__.open',
                        self._mock_open(read_data="A,B,C\r\n0,2,1\r\n2,0,1\r\n2,1,0\r\n")):
            with mock.patch('tlsfuzzer.timing_runner.TimingRunner.sniff'):
                with mock.patch('tlsfuzzer.timing_runner.TimingRunner.extract', extract):
                    with mock.patch('tlsfuzzer.timing_runner.TimingRunner.analyse') as analyse:
                        with mock.patch('tlsfuzzer.timing_runner.Thread'):
                            with mock.patch('tlsfuzzer.timing_runner.time.sleep'):
                                with mock.patch('tlsfuzzer.timing_runner.Runner') as runner:
                                    ret = self.runner.run()
                                    self.assertEqual(runner.call_count, WARM_UP + 9)
                                    extract.assert_called_once()
                                    self.assertEqual(analyse.call_count, 0)
                                    self.assertEqual(ret, 2)

    def test_run_tcpdump_failure(self):
        self.runner.tests = {"A": None, "B": None, "C": None}
        with mock.patch('__main__.__builtins__.open',
                        self._mock_open(read_data="A,B,C\r\n0,2,1\r\n2,0,1\r\n2,1,0\r\n")):
            with mock.patch('tlsfuzzer.timing_runner.TimingRunner.sniff'):
                with mock.patch('tlsfuzzer.timing_runner.TimingRunner.extract'):
                    with mock.patch('tlsfuzzer.timing_runner.TimingRunner.analyse'):
                        with mock.patch('tlsfuzzer.timing_runner.Thread'):
                            with mock.patch('tlsfuzzer.timing_runner.time.sleep'):
                                with mock.patch('tlsfuzzer.timing_runner.Runner') as runner:
                                    self.runner.tcpdump_running = False
                                    self.assertRaises(SystemExit, self.runner.run)
                                    self.assertEqual(runner.call_count, 0)

    @unittest.skipIf(is_33(), reason="Skipping because of a bug in unittest")
    def test_run_test_failure(self):
        self.runner.tests = {"A": None, "B": None, "C": None}
        self.runner.tcpdump_running = True

        def raise_error(*args, **kwargs):
            raise Exception()

        with mock.patch('__main__.__builtins__.open',
                        self._mock_open(read_data="A,B,C\r\n0,2,1\r\n2,0,1\r\n2,1,0\r\n")):
            with mock.patch('tlsfuzzer.timing_runner.TimingRunner.sniff'):
                with mock.patch('tlsfuzzer.timing_runner.TimingRunner.analyse'):
                    with mock.patch('tlsfuzzer.timing_runner.TimingRunner.extract'):
                        with mock.patch('tlsfuzzer.timing_runner.Thread'):
                            with mock.patch('tlsfuzzer.timing_runner.time.sleep'):
                                with mock.patch('tlsfuzzer.timing_runner.Runner') as runner:
                                    runner.return_value.run.side_effect = raise_error
                                    self.assertRaises(AssertionError, self.runner.run)

    def test__format_seconds_with_seconds(self):
        self.assertEqual(TimingRunner._format_seconds(12.5), "12.50s")

    def test__format_seconds_with_minutes(self):
        self.assertEqual(TimingRunner._format_seconds(60*35), "35m 0.00s")

    def test__format_seconds_with_hours(self):
        self.assertEqual(TimingRunner._format_seconds(60*60), "1h 0m 0.00s")

    def test__format_seconds_with_days(self):
        self.assertEqual(TimingRunner._format_seconds(24*60*60*2),
                         "2d 0h 0m 0.00s")
