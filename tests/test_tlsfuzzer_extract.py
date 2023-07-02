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

        self.expected_raw = (
            "raw times\n"
            "12354\n"
            "65468\n"
            "21235\n"
            "45623\n"
            "88965\n"
            "21232\n"
            "12223\n"
            "32432\n"
            "22132\n"
            "21564\n"
            "56489\n"
            "54987\n"
            "25654\n"
            "54922\n"
            "56488\n"
            "89477\n"
            "52616\n"
            "21366\n"
            "56487\n"
            "21313\n")

        self.expected_binary_conv = (
            "A,B\n"
            "65468.000000000,12354.000000000\n"
            "21235.000000000,45623.000000000\n"
            "21232.000000000,88965.000000000\n"
            "12223.000000000,32432.000000000\n"
            "22132.000000000,21564.000000000\n"
            "56489.000000000,54987.000000000\n"
            "25654.000000000,54922.000000000\n"
            "89477.000000000,56488.000000000\n"
            "21366.000000000,52616.000000000\n"
            "21313.000000000,56487.000000000\n"
            )

        self.expected_no_quickack = (
            "A,B\n"
            "0.000758130,0.000747009\n"
            "0.000696718,0.000920462\n"
            "0.000980080,0.001327954\n"
            "0.000988899,0.000904547\n"
            "0.000875510,0.000768453\n"
            "0.000734843,0.000752226\n"
            "0.000754852,0.000862102\n"
            "0.000667378,0.000706491\n"
            "0.000671230,0.000668237\n"
            "0.000790935,0.000992733\n"
            )

    def file_selector(self, *args, **kwargs):
        name = args[0]
        mode = args[1]
        if "timing.csv" in name:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: self.assertIn(
                    s.strip(), self.expected.splitlines())
            return r
        return self.builtin_open(*args, **kwargs)

    def file_selector_no_quickack(self, *args, **kwargs):
        name = args[0]
        mode = args[1]
        if "timing.csv" in name:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: self.assertIn(
                    s.strip(), self.expected_no_quickack.splitlines())
            return r
        return self.builtin_open(*args, **kwargs)

    def file_selector_binary(self, *args, **kwargs):
        name = args[0]
        mode = args[1]
        if "timing.csv" in name:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: self.assertIn(
                    s.strip(), self.expected_binary_conv.splitlines())
            return r
        elif "raw_times.csv" in name:
            if "r" in mode:
                return mock.mock_open(read_data=self.expected_raw)(name, mode)
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: self.assertIn(
                    s.strip(), self.expected_raw.splitlines())
            return r
        return self.builtin_open(*args, **kwargs)

    def test_extraction_from_external_time_source(self):
        extract = Extract(self.log, None, "/tmp", None, None,
                          join(dirname(abspath(__file__)), "times-log.csv"))

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_selector
            extract.parse()

    def test_extraction_from_external_source_with_wrong_file(self):
        extract = Extract(self.log, None, "/tmp", None, None,
                          join(dirname(abspath(__file__)),
                               "raw_times_detail.csv"))

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_selector
            with self.assertRaises(ValueError) as exc:
                extract.parse()

            self.assertIn("Multiple columns", str(exc.exception))

    def test_extraction_from_external_source_with_multiple_columns(self):
        extract = Extract(self.log, None, "/tmp", None, None,
                          join(dirname(abspath(__file__)),
                               "raw_times_detail.csv"), col_name="clnt_0_rtt")

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_selector
            extract.parse()

    def test_extraction(self):
        extract = Extract(self.log,
                          join(dirname(abspath(__file__)), "capture.pcap"),
                          "/tmp", "localhost", 4433)

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_selector
            extract.parse()

    def test_extraction_with_no_quickack(self):
        extract = Extract(self.log,
                          join(dirname(abspath(__file__)), "capture.pcap"),
                          "/tmp", "localhost", 4433, no_quickack=True)

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_selector_no_quickack
            extract.parse()

    def test_binary_convert(self):
        extract = Extract(self.log, None, "/tmp", None, None,
                          join(dirname(abspath(__file__)),
                               "raw_times.bin"), binary=4)

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_selector_binary
            extract.parse()


@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
class TestCommandLine(unittest.TestCase):

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_command_line(self, mock_parse, mock_write, mock_write_pkt,
                          mock_log):
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
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_log.assert_called_once_with(logfile)
                mock_init.assert_called_once_with(
                    mock.ANY, capture, output, host, int(port),
                    None, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None)

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_delay_and_CR(self, mock_parse, mock_write, mock_write_pkt,
                          mock_log):
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
                "-o", output,
                "--status-delay", "3.5",
                "--status-newline"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_log.assert_called_once_with(logfile)
                mock_init.assert_called_once_with(
                    mock.ANY, capture, output, host, int(port),
                    None, None, binary=None, endian="little",
                    no_quickack=False, delay=3.5, carriage_return='\n')

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_no_quickack(self, mock_parse, mock_write, mock_write_pkt,
                          mock_log):
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
                "-o", output,
                "--no-quickack"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_log.assert_called_once_with(logfile)
                mock_init.assert_called_once_with(
                    mock.ANY, capture, output, host, int(port),
                    None, None, binary=None, endian="little",
                    no_quickack=True, delay=None, carriage_return=None)

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_raw_times(self, mock_parse, mock_write, mock_write_pkt, mock_log):
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
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_log.assert_called_once_with(logfile)
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, column_name, binary=None, endian='little',
                    no_quickack=False, delay=None, carriage_return=None)

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_raw_binary_times(self, mock_parse, mock_write, mock_write_pkt, mock_log):
        raw_times = "raw_times_detail.csv"
        logfile = "log.csv"
        output = "/tmp"
        column_name = "clnt_0_rtt"
        args = ["extract.py",
                "-l", logfile,
                "-o", output,
                "--raw-times", raw_times,
                "--binary", "4",
                "--endian", "big"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_log.assert_called_once_with(logfile)
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=4, endian='big',
                    no_quickack=False, delay=None, carriage_return=None)

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_wrong_endian_name(self, mock_parse, mock_write, mock_write_pkt, mock_log):
        raw_times = "raw_times_detail.csv"
        logfile = "log.csv"
        output = "/tmp"
        column_name = "clnt_0_rtt"
        args = ["extract.py",
                "-l", logfile,
                "-o", output,
                "--raw-times", raw_times,
                "--binary", "4",
                "--endian", "middle"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                with self.assertRaises(ValueError) as e:
                    main()

                self.assertIn("Only 'little' and 'big'", str(e.exception))

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_binary_without_raw_times(self, mock_parse, mock_write, mock_write_pkt, mock_log):
        raw_times = "raw_times_detail.csv"
        logfile = "log.csv"
        output = "/tmp"
        column_name = "clnt_0_rtt"
        args = ["extract.py",
                "-l", logfile,
                "-o", output,
                "--binary", "4",
                "--endian", "big"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                with self.assertRaises(ValueError) as e:
                    main()

                self.assertIn("Can't specify binary number", str(e.exception))

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_column_name_with_binary_file(self, mock_parse, mock_write, mock_write_pkt, mock_log):
        raw_times = "raw_times_detail.csv"
        logfile = "log.csv"
        output = "/tmp"
        column_name = "clnt_0_rtt"
        args = ["extract.py",
                "-l", logfile,
                "-o", output,
                "-n", column_name,
                "--raw-times", raw_times,
                "--binary", "4",
                "--endian", "big"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                with self.assertRaises(ValueError) as e:
                    main()

                self.assertIn("Binary format doesn't support column names",
                              str(e.exception))

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_raw_times_with_column_name(self, mock_parse, mock_write,
            mock_write_pkt, mock_log):
        raw_times = "times-log.csv"
        logfile = "log.csv"
        output = "/tmp"
        args = ["extract.py",
                "-l", logfile,
                "-o", output,
                "--raw-times", raw_times]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_log.assert_called_once_with(logfile)
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian='little',
                    no_quickack=False, delay=None, carriage_return=None)

    @mock.patch('__main__.__builtins__.print')
    @mock.patch('tlsfuzzer.extract.help_msg')
    def test_help(self, help_mock, print_mock):
        args = ["extract.py", "--help"]
        with mock.patch("sys.argv", args):
            self.assertRaises(SystemExit, main)
            help_mock.assert_called_once()

    @mock.patch('__main__.__builtins__.print')
    def test_help_msg(self, print_mock):
        help_msg()
        self.assertGreaterEqual(print_mock.call_count, 1)

    @mock.patch('__main__.__builtins__.print')
    def test_missing_output(self, print_mock):
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
