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

import sys
from socket import inet_aton
from os.path import join, dirname, abspath

from tlsfuzzer.utils.log import Log

failed_import = False
try:
    from tlsfuzzer.extract import Extract, main, help_msg
except ImportError:
    failed_import = True


@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
class TestHostnameToIp(unittest.TestCase):

    def test_valid_ip(self):
        ip_addr = "127.0.0.1"
        self.assertEqual(Extract.hostname_to_ip(ip_addr), inet_aton(ip_addr))

    def test_invalid_ip(self):
        invalid_ip_addr = "256.0.0.1"
        with self.assertRaises(Exception):
            Extract.hostname_to_ip(invalid_ip_addr)

    def test_valid_hostname(self):
        hostname = "localhost"
        self.assertEqual(Extract.hostname_to_ip(hostname),
                         inet_aton("127.0.0.1"))

    def test_invalid_hostname(self):
        invalid_hostname = "#invalidhostname*"
        with self.assertRaises(Exception):
            Extract.hostname_to_ip(invalid_hostname)


@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
class TestExtraction(unittest.TestCase):
    def setUp(self):
        self.logfile = join(dirname(abspath(__file__)), "test.log")
        log_content = "A,B\n1,0\n0,1\n1,0\n0,1\n0,1\n0,1\n0,1\n1,0\n1,0\n1,0\n"
        self.expected = (
            "A,B\n"
            "0.000742286,0.000729452\n"
            "0.000680365,0.000906201\n"
            "0.000962871,0.001307492\n"
            "0.000974224,0.000890191\n"
            "0.000861659,0.000753251\n"
            "0.000719014,0.000738350\n"
            "0.000740653,0.000844232\n"
            "0.000653504,0.000692056\n"
            "0.000657394,0.000654963\n"
            "0.000774939,0.000978703\n")
        self.time_vals = "\n".join(["some random header"] +
                                   list(str(i) for i in range(20)))
        # fix mock not supporting iterators
        self.mock_log = mock.mock_open(read_data=log_content)
        self.mock_log.return_value.__iter__ = lambda s: iter(s.readline, '')

        with mock.patch('__main__.__builtins__.open', self.mock_log):
            self.log = Log(self.logfile)
            self.log.read_log()

        self.builtin_open = open

    def file_selector(self, *args, **kwargs):
        name = args[0]
        mode = args[1]
        if "timing.csv" in name:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: self.assertIn(
                    s.strip(), self.expected.splitlines())
            return r
        return self.builtin_open(*args, **kwargs)

    def test_extraction_from_external_time_source(self):
        extract = Extract(self.log, None, "/tmp", None, None,
                          join(dirname(abspath(__file__)), "times-log.csv"))

        with mock.patch('builtins.open') as mock_file:
            mock_file.side_effect = self.file_selector
            extract.parse()

    def test_extraction_from_external_source_with_wrong_file(self):
        extract = Extract(self.log, None, "/tmp", None, None,
                          join(dirname(abspath(__file__)),
                               "raw_times_detail.csv"))

        with mock.patch('builtins.open') as mock_file:
            mock_file.side_effect = self.file_selector
            with self.assertRaises(ValueError) as exc:
                extract.parse()

            self.assertIn("Multiple columns", str(exc.exception))

    def test_extraction_from_external_source_with_multiple_columns(self):
        extract = Extract(self.log, None, "/tmp", None, None,
                          join(dirname(abspath(__file__)),
                               "raw_times_detail.csv"), col_name="clnt_0_rtt")

        with mock.patch('builtins.open') as mock_file:
            mock_file.side_effect = self.file_selector
            extract.parse()

    def test_extraction(self):
        extract = Extract(self.log,
                          join(dirname(abspath(__file__)), "capture.pcap"),
                          "/tmp", "localhost", 4433)

        with mock.patch('builtins.open') as mock_file:
            mock_file.side_effect = self.file_selector
            extract.parse()


@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
class TestCommandLine(unittest.TestCase):
    def test_command_line(self):
        capture = "capture.pcap"
        logfile = "log.csv"
        host = "localhost"
        port = "4433"
        output = "/tmp"
        args = ["extract.py",
                "-l", logfile,
                "-c", capture,
                "-h", host,
                "-p", port,
                "-o", output]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.parse'):
            with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
                with mock.patch('tlsfuzzer.extract.Extract._write_csv'):
                    with mock.patch('tlsfuzzer.extract.Extract._write_pkts'):
                        with mock.patch('tlsfuzzer.extract.Log') as mock_log:
                            with mock.patch("sys.argv", args):
                                main()
                                mock_log.assert_called_once_with(logfile)
                                mock_init.assert_called_once_with(
                                    mock.ANY, capture, output, host, int(port),
                                    None, None)

    def test_raw_times(self):
        raw_times = "raw_times_detail.csv"
        logfile = "log.csv"
        output = "/tmp"
        column_name = "clnt_0_rtt"
        args = ["extract.py",
                "-l", logfile,
                "-o", output,
                "--raw-times", raw_times,
                "-n", column_name]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.parse'):
            with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
                with mock.patch('tlsfuzzer.extract.Extract._write_csv'):
                    with mock.patch('tlsfuzzer.extract.Extract._write_pkts'):
                        with mock.patch('tlsfuzzer.extract.Log') as mock_log:
                            with mock.patch("sys.argv", args):
                                main()
                                mock_log.assert_called_once_with(logfile)
                                mock_init.assert_called_once_with(
                                    mock.ANY, None, output, None, None,
                                    raw_times, column_name)

    def test_raw_times_with_column_name(self):
        raw_times = "times-log.csv"
        logfile = "log.csv"
        output = "/tmp"
        args = ["extract.py",
                "-l", logfile,
                "-o", output,
                "--raw-times", raw_times]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.parse'):
            with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
                with mock.patch('tlsfuzzer.extract.Extract._write_csv'):
                    with mock.patch('tlsfuzzer.extract.Extract._write_pkts'):
                        with mock.patch('tlsfuzzer.extract.Log') as mock_log:
                            with mock.patch("sys.argv", args):
                                main()
                                mock_log.assert_called_once_with(logfile)
                                mock_init.assert_called_once_with(
                                    mock.ANY, None, output, None, None,
                                    raw_times, None)

    def test_help(self):
        args = ["extract.py", "--help"]
        with mock.patch('tlsfuzzer.extract.help_msg') as help_mock:
            with mock.patch("sys.argv", args):
                self.assertRaises(SystemExit, main)
                help_mock.assert_called_once()

    def test_help_msg(self):
        with mock.patch('__main__.__builtins__.print') as print_mock:
            help_msg()
            self.assertGreaterEqual(print_mock.call_count, 1)

    def test_missing_output(self):
        args = ["extract.py"]
        with mock.patch("sys.argv", args):
            self.assertRaises(SystemExit, main)

    def test_incompatible_options(self):
        args = ["extract.py", "-c", "capture.pcap", "--raw-times",
                "times-log.csv"]
        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError):
                main()

    def test_incomplete_packet_capture_options(self):
        args = ["extract.py", "-c", "capture.pcap", "-l", "log.csv",
                "-o", "/tmp"]
        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError):
                main()

    def test_incomplete_ext_times_options(self):
        args = ["extract.py", "--raw-times", "times-log.csv", "-o", "/tmp"]
        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError):
                main()
