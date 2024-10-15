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

from collections import defaultdict
import os
from socket import inet_aton
from os.path import join, dirname, abspath
import hashlib
from random import choice
import ecdsa

from tlsfuzzer.utils.log import Log

failed_import = False
try:
    from tlsfuzzer.extract import Extract, main, help_msg
    import multiprocessing as mp
except ImportError:
    failed_import = True

try:
    TUPLE_RANDOMNESS_TESTS = os.environ["TUPLE_RANDOMNESS_TESTS"]
except KeyError:
    TUPLE_RANDOMNESS_TESTS = False

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
            "7.422860000e-04,7.294520000e-04\n"
            "6.803650000e-04,9.062010000e-04\n"
            "9.628710000e-04,1.307492000e-03\n"
            "9.742240000e-04,8.901910000e-04\n"
            "8.616590000e-04,7.532510000e-04\n"
            "7.190140000e-04,7.383500000e-04\n"
            "7.406530000e-04,8.442320000e-04\n"
            "6.535040000e-04,6.920560000e-04\n"
            "6.573940000e-04,6.549630000e-04\n"
            "7.749390000e-04,9.787030000e-04\n")
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
            "6.546800000e+04,1.235400000e+04\n"
            "2.123500000e+04,4.562300000e+04\n"
            "2.123200000e+04,8.896500000e+04\n"
            "1.222300000e+04,3.243200000e+04\n"
            "2.213200000e+04,2.156400000e+04\n"
            "5.648900000e+04,5.498700000e+04\n"
            "2.565400000e+04,5.492200000e+04\n"
            "8.947700000e+04,5.648800000e+04\n"
            "2.136600000e+04,5.261600000e+04\n"
            "2.131300000e+04,5.648700000e+04\n"
            )

        self.expected_no_quickack = (
            "A,B\n"
            "7.581300000e-04,7.470090000e-04\n"
            "6.967180000e-04,9.204620000e-04\n"
            "9.800800000e-04,1.327954000e-03\n"
            "9.888990000e-04,9.045470000e-04\n"
            "8.755100000e-04,7.684530000e-04\n"
            "7.348430000e-04,7.522260000e-04\n"
            "7.548520000e-04,8.621020000e-04\n"
            "6.673780000e-04,7.064910000e-04\n"
            "6.712300000e-04,6.682370000e-04\n"
            "7.909350000e-04,9.927330000e-04\n"
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

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_command_line(self, mock_parse, mock_write, mock_write_pkt,
                          mock_log, mock_measurements):
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
                    no_quickack=False, delay=None, carriage_return=None,
                    data=None, data_size=None, sigs=None, priv_key=None,
                    key_type=None, frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_measurements.assert_not_called()

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_delay_and_CR(self, mock_parse, mock_write, mock_write_pkt,
                          mock_log, mock_measurements):
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
                    no_quickack=False, delay=3.5, carriage_return='\n',
                    data=None, data_size=None, sigs=None, priv_key=None,
                    key_type=None, frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_measurements.assert_not_called()

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_no_quickack(self, mock_parse, mock_write, mock_write_pkt,
                          mock_log, mock_measurements):
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
                    no_quickack=True, delay=None, carriage_return=None,
                    data=None, data_size=None, sigs=None, priv_key=None,
                    key_type=None, frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_measurements.assert_not_called()

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_raw_times(self, mock_parse, mock_write, mock_write_pkt, mock_log,
                       mock_measurements):
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
                    no_quickack=False, delay=None, carriage_return=None,
                    data=None, data_size=None, sigs=None, priv_key=None,
                    key_type=None, frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_measurements.assert_not_called()

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_raw_binary_times(self, mock_parse, mock_write, mock_write_pkt,
                        mock_log, mock_measurements):
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
                    no_quickack=False, delay=None, carriage_return=None,
                    data=None, data_size=None, sigs=None, priv_key=None,
                    key_type=None, frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_measurements.assert_not_called()

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

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_raw_times_with_column_name(self, mock_parse, mock_write,
            mock_write_pkt, mock_log, mock_measurements):
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
                    no_quickack=False, delay=None, carriage_return=None,
                    data=None, data_size=None, sigs=None, priv_key=None,
                    key_type=None, frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_measurements.assert_not_called()

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

    @mock.patch('tlsfuzzer.extract.Extract.process_rsa_keys')
    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_rsa_keys_options(self, mock_parse, mock_write, mock_process,
                                 mock_write_pkt, mock_log, mock_process_rsa):
        output = "/tmp"
        raw_times = "/tmp/times.bin"
        priv_key = "/tmp/keys.pem"
        args = ["extract.py",
                "-o", output,
                "--raw-times", raw_times,
                "--binary", "8",
                "--rsa-keys", priv_key]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=8, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=None, data_size=None, sigs=None,
                    priv_key=None, key_type=None, frequency=None,
                    hash_func=hashlib.sha256, workers=None, verbose=False,
                    rsa_keys=priv_key, sig_format="DER", values=None,
                    value_size=None, value_endianness="big",
                    max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_not_called()
                mock_process_rsa.assert_called_once_with()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_ecdsa_signs_options(self, mock_parse, mock_process, mock_write,
                                 mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--priv-key-ecdsa", priv_key]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec", frequency=None,
                    hash_func=hashlib.sha256, workers=None, verbose=False,
                    rsa_keys=None, sig_format="DER", values=None,
                    value_size=None, value_endianness="big",
                    max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_verbose_option(self, mock_parse, mock_process, mock_write,
                            mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--priv-key-ecdsa", priv_key,
                "--verbose"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec", frequency=None,
                    hash_func=hashlib.sha256, workers=None, verbose=True,
                    rsa_keys=None, sig_format="DER", values=None,
                    value_size=None, value_endianness="big",
                    max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_frequency_option(self, mock_parse, mock_process, mock_write,
                              mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        frequency = 711.45
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--clock-frequency", frequency,
                "--priv-key-ecdsa", priv_key]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec",
                    frequency=frequency * 1e6, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_hash_func_option(self, mock_parse, mock_process, mock_write,
                              mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        hash_name = "sha384"
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--hash-func", hash_name,
                "--priv-key-ecdsa", priv_key]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec",
                    frequency=None, hash_func=hashlib.sha384,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_prehashed_option(self, mock_parse, mock_process, mock_write,
                              mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--prehashed",
                "--priv-key-ecdsa", priv_key]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec",
                    frequency=None, hash_func=None,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_workers_option(self, mock_parse, mock_process, mock_write,
                              mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        workers = 10
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--workers", workers,
                "--priv-key-ecdsa", priv_key]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec",
                    frequency=None, hash_func=hashlib.sha256,
                    workers=workers, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_skip_invert_option(self, mock_parse, mock_process, mock_write,
                              mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--priv-key-ecdsa", priv_key,
                "--skip-invert"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec",
                    frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

                files_passes_in_process = mock_process.call_args[0][0]
                for mode in files_passes_in_process.values():
                    self.assertNotIn("invert", mode)

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_raw_sig_format_option(self, mock_parse, mock_process, mock_write,
                              mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--priv-key-ecdsa", priv_key,
                "--sig-format", "RAW"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec",
                    frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="RAW", values=None, value_size=None,
                    value_endianness="big", max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    def test_specify_to_private_keys(self):
        args = [
            "extract.py", "-o", "/tmp", "--raw-data", "/tmp/data",
            "--data-size", "32", "--raw-sigs", "/tmp/sigs",
            "--raw-times", "/tmp/times", "--priv-key-ecdsa", "/tmp/key",
            "--priv-key-ecdsa", "/tmp/key2"
            ]
        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError) as e:
                main()

            self.assertIn("Can't specify more than one private key.",
                              str(e.exception))

    def test_extra_argument(self):
        args = [
            "extract.py", "-o", "/tmp", "--raw-data", "/tmp/data",
            "--data-size", "32", "--raw-sigs", "/tmp/sigs",
            "--raw-times", "/tmp/times", "--priv-key-ecdsa", "/tmp/key",
            "extra"
            ]
        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError) as e:
                main()

            self.assertIn("Unexpected arguments", str(e.exception))

    def test_specify_sigs_but_not_priv_key(self):
        args = [
            "extract.py", "-o", "/tmp", "--raw-data", "/tmp/data",
            "--data-size", "32", "--raw-sigs", "/tmp/sigs",
            "--raw-times", "/tmp/times"
            ]
        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError) as e:
                main()

            self.assertIn(
                "When doing signature extraction,",
                str(e.exception))

    def test_specify_ecdh_but_not_priv_key(self):
        args = [
            "extract.py", "-o", "/tmp", "--raw-data", "/tmp/data",
            "--data-size", "32", "--raw-values", "/tmp/values",
            "--raw-times", "/tmp/times"
            ]
        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError) as e:
                main()

            self.assertIn(
                "When doing ECDH secret extraction,",
                str(e.exception))

    def test_unsupported_hash_func(self):
        args = [
            "extract.py", "-o", "/tmp", "--raw-data", "/tmp/data",
            "--data-size", "32", "--raw-sigs", "/tmp/sigs",
            "--raw-times", "/tmp/times", "--priv-key-ecdsa", "/tmp/key",
            "--hash-func", "not_a_hash"
            ]
        with mock.patch("sys.argv", args):
            with self.assertRaises(ValueError) as e:
                main()

            self.assertIn("Hash function not_a_hash is not supported.",
                            str(e.exception))

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_ecdh(self, mock_parse, mock_process, mock_write,
                              mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_values = "/tmp/values"
        value_size = 64
        value_endianness = "little"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-values", raw_values,
                "--value-size", value_size,
                "--value-endianness", value_endianness,
                "--raw-times", raw_times,
                "--priv-key-ecdsa", priv_key]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=None,
                    priv_key=priv_key, key_type="ec",
                    frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=raw_values, value_size=value_size,
                    value_endianness=value_endianness, max_bit_size=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_max_bit_size(self, mock_parse, mock_process, mock_write,
                              mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        max_bit_size = 100
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--priv-key-ecdsa", priv_key,
                "--max-bit-size", max_bit_size]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
            with mock.patch("sys.argv", args):
                main()
                mock_init.assert_called_once_with(
                    mock.ANY, None, output, None, None,
                    raw_times, None, binary=None, endian="little",
                    no_quickack=False, delay=None, carriage_return=None,
                    data=raw_data, data_size=data_size, sigs=raw_sigs,
                    priv_key=priv_key, key_type="ec",
                    frequency=None, hash_func=hashlib.sha256,
                    workers=None, verbose=False, rsa_keys=None,
                    sig_format="DER", values=None, value_size=None,
                    value_endianness="big", max_bit_size=max_bit_size)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
class TestTupleCreationRandomeness(unittest.TestCase):
    def setUp(self):
        self.builtin_open = open
        self.max_value = 256
        self._measurements_file = []

        self.very_simple_runs = 1000
        self.very_simple_data = [256, 255, 256]
        self.very_simple_times = [100, 1, 101]
        self.very_simple_expected = {
            "1:100": (422,578), # probability: 1/2
            "1:101": (422,578)  # probability: 1/2
        }

        self.two_non_max_before_and_two_after_runs = 2000
        self.two_non_max_before_and_two_after_data = [
            256, 255, 255, 256, 255, 255, 256
        ]
        self.two_non_max_before_and_two_after_times = [
            100, 1, 2, 101, 3, 4, 102
        ]
        self.two_non_max_before_and_two_after_expected = {
            "1:100,3:101": (28, 104), # probability: 1/32
            "2:100,3:101": (28, 104), # probability: 1/32
            "1:100,4:101": (28, 104), # probability: 1/32
            "2:100,4:101": (28, 104), # probability: 1/32
            "1:100,3:101,4:102": (75, 181), # probability: 1/16
            "2:100,3:101,4:102": (75, 181), # probability: 1/16
            "1:100,4:101,3:102": (75, 181), # probability: 1/16
            "2:100,4:101,3:102": (75, 181), # probability: 1/16
            "1:100,3:102": (8, 62), # probability: 1/64
            "2:100,3:102": (8, 62), # probability: 1/64
            "1:100,4:102": (8, 62), # probability: 1/64
            "2:100,4:102": (8, 62), # probability: 1/64
            "1:100,2:101": (28, 104), # probability: 1/32
            "1:100,2:101,4:102": (75, 181), # probability: 1/16
            "1:100,2:101,3:102": (75, 181), # probability: 1/16
            "2:100,1:101": (28, 104), # probability: 1/32
            "2:100,1:101,4:102": (75, 181), # probability: 1/16
            "2:100,1:101,3:102": (75, 181), # probability: 1/16
            "1:101": (8, 62), # probability: 1/64
            "2:101": (8, 62), # probability: 1/64
            "3:101": (8, 62), # probability: 1/64
            "4:101": (8, 62), # probability: 1/64
            "1:101,4:102": (28, 104), # probability: 1/32
            "2:101,4:102": (28, 104), # probability: 1/32
            "3:101,4:102": (28, 104), # probability: 1/32
            "1:101,3:102": (28, 104), # probability: 1/32
            "2:101,3:102": (28, 104), # probability: 1/32
            "4:101,3:102": (28, 104)  # probability: 1/32
        }

        self.two_non_max_before_and_one_after_runs = 1000
        self.two_non_max_before_and_one_after_data = [
            256, 255, 255, 256, 255, 256
        ]
        self.two_non_max_before_and_one_after_times = [
            100, 1, 2, 101, 3, 102
        ]
        self.two_non_max_before_and_one_after_expected = {
            "1:100,3:101": (76, 179), # probability: 1/8
            "2:100,3:101": (76, 179), # probability: 1/8
            "1:100,3:102": (28, 103), # probability: 1/16
            "2:100,3:102": (28, 103), # probability: 1/16
            "1:100,2:101": (28, 103), # probability: 1/16
            "1:100,2:101,3:102": (76, 179), # probability: 1/8
            "2:100,1:101": (28, 103), # probability: 1/16
            "2:100,1:101,3:102": (76, 179), # probability: 1/8
            "1:101": (8, 62), # probability: 1/32
            "2:101": (8, 62), # probability: 1/32
            "3:101": (28, 103), # probability: 1/16
            "1:101,3:102": (28, 103), # probability: 1/16
            "2:101,3:102": (28, 103)  # probability: 1/16
        }

        self.three_max_two_non_max_before_and_after_runs = 9000
        self.three_max_two_non_max_before_and_after_data = [
            256, 255, 255, 256, 255, 255, 256, 255, 255, 256
        ]
        self.three_max_two_non_max_before_and_after_times = [
            100, 1, 2, 101, 3, 4, 102, 5, 6, 103
        ]
        self.three_max_two_non_max_before_and_after_expected = {
            "1:100,3:101,5:102": (33, 115), # probability: 1/128
            "2:100,3:101,5:102": (33, 115), # probability: 1/128
            "1:100,4:101,5:102": (33, 115), # probability: 1/128
            "2:100,4:101,5:102": (33, 115), # probability: 1/128
            "1:100,3:101,6:102": (33, 115), # probability: 1/128
            "2:100,3:101,6:102": (33, 115), # probability: 1/128
            "1:100,4:101,6:102": (33, 115), # probability: 1/128
            "2:100,4:101,6:102": (33, 115), # probability: 1/128
            "1:100,3:101,5:102,6:103": (86, 202), # probability: 1/64
            "2:100,3:101,5:102,6:103": (86, 202), # probability: 1/64
            "1:100,4:101,5:102,6:103": (86, 202), # probability: 1/64
            "2:100,4:101,5:102,6:103": (86, 202), # probability: 1/64
            "1:100,3:101,6:102,5:103": (86, 202), # probability: 1/64
            "2:100,3:101,6:102,5:103": (86, 202), # probability: 1/64
            "1:100,4:101,6:102,5:103": (86, 202), # probability: 1/64
            "2:100,4:101,6:102,5:103": (86, 202), # probability: 1/64
            "1:100,3:101,5:103": (10, 68), # probability: 1/256
            "2:100,3:101,5:103": (10, 68), # probability: 1/256
            "1:100,4:101,5:103": (10, 68), # probability: 1/256
            "2:100,4:101,5:103": (10, 68), # probability: 1/256
            "1:100,3:101,6:103": (10, 68), # probability: 1/256
            "2:100,3:101,6:103": (10, 68), # probability: 1/256
            "1:100,4:101,6:103": (10, 68), # probability: 1/256
            "2:100,4:101,6:103": (10, 68), # probability: 1/256
            "1:100,3:101,4:102": (33, 115), # probability: 1/128
            "2:100,3:101,4:102": (33, 115), # probability: 1/128
            "1:100,3:101,4:102,6:103": (86, 202), # probability: 1/64
            "2:100,3:101,4:102,6:103": (86, 202), # probability: 1/64
            "1:100,3:101,4:102,5:103": (86, 202), # probability: 1/64
            "2:100,3:101,4:102,5:103": (86, 202), # probability: 1/64
            "1:100,4:101,3:102": (33, 115), # probability: 1/128
            "2:100,4:101,3:102": (33, 115), # probability: 1/128
            "1:100,4:101,3:102,6:103": (86, 202), # probability: 1/64
            "2:100,4:101,3:102,6:103": (86, 202), # probability: 1/64
            "1:100,4:101,3:102,5:103": (86, 202), # probability: 1/64
            "2:100,4:101,3:102,5:103": (86, 202), # probability: 1/64
            "1:100,3:102": (1, 42), # probability: 1/512
            "2:100,3:102": (1, 42), # probability: 1/512
            "1:100,4:102": (1, 42), # probability: 1/512
            "2:100,4:102": (1, 42), # probability: 1/512
            "1:100,5:102": (1, 42), # probability: 1/512
            "2:100,5:102": (1, 42), # probability: 1/512
            "1:100,6:102": (1, 42), # probability: 1/512
            "2:100,6:102": (1, 42), # probability: 1/512
            "1:100,3:102,6:103": (10, 68), # probability: 1/256
            "2:100,3:102,6:103": (10, 68), # probability: 1/256
            "1:100,4:102,6:103": (10, 68), # probability: 1/256
            "2:100,4:102,6:103": (10, 68), # probability: 1/256
            "1:100,5:102,6:103": (10, 68), # probability: 1/256
            "2:100,5:102,6:103": (10, 68), # probability: 1/256
            "1:100,3:102,5:103": (10, 68), # probability: 1/256
            "2:100,3:102,5:103": (10, 68), # probability: 1/256
            "1:100,4:102,5:103": (10, 68), # probability: 1/256
            "2:100,4:102,5:103": (10, 68), # probability: 1/256
            "1:100,6:102,5:103": (10, 68), # probability: 1/256
            "2:100,6:102,5:103": (10, 68), # probability: 1/256
            "1:100,2:101,5:102": (59, 159), # probability: 1/85
            "1:100,2:101,6:102": (59, 159), # probability: 1/85
            "1:100,2:101,5:102,6:103": (144, 285), # probability: 1/42
            "1:100,2:101,6:102,5:103": (144, 285), # probability: 1/42
            "1:100,2:101,5:103": (10, 68), # probability: 1/256
            "1:100,2:101,6:103": (10, 68), # probability: 1/256
            "1:100,2:101,4:102": (33, 115), # probability: 1/128
            "1:100,2:101,4:102,6:103": (86, 202), # probability: 1/64
            "1:100,2:101,4:102,5:103": (86, 202), # probability: 1/64
            "1:100,2:101,3:102": (33, 115), # probability: 1/128
            "1:100,2:101,3:102,6:103": (86, 202), # probability: 1/64
            "1:100,2:101,3:102,5:103": (86, 202), # probability: 1/64
            "2:100,1:101,5:102": (59, 159), # probability: 1/85
            "2:100,1:101,6:102": (59, 159), # probability: 1/85
            "2:100,1:101,5:102,6:103": (144, 285), # probability: 1/42
            "2:100,1:101,6:102,5:103": (144, 285), # probability: 1/42
            "2:100,1:101,5:103": (10, 68), # probability: 1/256
            "2:100,1:101,6:103": (10, 68), # probability: 1/256
            "2:100,1:101,4:102": (33, 115), # probability: 1/128
            "2:100,1:101,4:102,6:103": (86, 202), # probability: 1/64
            "2:100,1:101,4:102,5:103": (86, 202), # probability: 1/64
            "2:100,1:101,3:102": (33, 115), # probability: 1/128
            "2:100,1:101,3:102,6:103": (86, 202), # probability: 1/64
            "2:100,1:101,3:102,5:103": (86, 202), # probability: 1/64
            "1:101,5:102": (21, 92), # probability: 1/170
            "2:101,5:102": (21, 92), # probability: 1/170
            "3:101,5:102": (10, 68), # probability: 1/256
            "4:101,5:102": (10, 68), # probability: 1/256
            "1:101,6:102": (21, 92), # probability: 1/170
            "2:101,6:102": (21, 92), # probability: 1/170
            "3:101,6:102": (10, 68), # probability: 1/256
            "4:101,6:102": (10, 68), # probability: 1/256
            "1:101,5:102,6:103": (59, 159), # probability: 1/85
            "2:101,5:102,6:103": (59, 159), # probability: 1/85
            "3:101,5:102,6:103": (33, 115), # probability: 1/128
            "4:101,5:102,6:103": (33, 115), # probability: 1/128
            "1:101,6:102,5:103": (59, 159), # probability: 1/85
            "2:101,6:102,5:103": (59, 159), # probability: 1/85
            "3:101,6:102,5:103": (33, 115), # probability: 1/128
            "4:101,6:102,5:103": (33, 115), # probability: 1/128
            "1:101,5:103": (1, 42), # probability: 1/512
            "2:101,5:103": (1, 42), # probability: 1/512
            "3:101,5:103": (1, 42), # probability: 1/512
            "4:101,5:103": (1, 42), # probability: 1/512
            "1:101,6:103": (1, 42), # probability: 1/512
            "2:101,6:103": (1, 42), # probability: 1/512
            "3:101,6:103": (1, 42), # probability: 1/512
            "4:101,6:103": (1, 42), # probability: 1/512
            "1:101,4:102": (10, 68), # probability: 1/256
            "2:101,4:102": (10, 68), # probability: 1/256
            "3:101,4:102": (10, 68), # probability: 1/256
            "1:101,4:102,6:103": (33, 115), # probability: 1/128
            "2:101,4:102,6:103": (33, 115), # probability: 1/128
            "3:101,4:102,6:103": (33, 115), # probability: 1/128
            "1:101,4:102,5:103": (33, 115), # probability: 1/128
            "2:101,4:102,5:103": (33, 115), # probability: 1/128
            "3:101,4:102,5:103": (33, 115), # probability: 1/128
            "1:101,3:102": (10, 68), # probability: 1/256
            "2:101,3:102": (10, 68), # probability: 1/256
            "4:101,3:102": (10, 68), # probability: 1/256
            "1:101,3:102,6:103": (33, 115), # probability: 1/128
            "2:101,3:102,6:103": (33, 115), # probability: 1/128
            "4:101,3:102,6:103": (33, 115), # probability: 1/128
            "1:101,3:102,5:103": (33, 115), # probability: 1/128
            "2:101,3:102,5:103": (33, 115), # probability: 1/128
            "4:101,3:102,5:103": (33, 115)  # probability: 1/128
        }

        self.diff_size_non_max_runs = 2000
        self.diff_size_non_max_data = [
            256, 255, 254, 256, 255, 254, 256
        ]
        self.diff_size_non_max_times = [
            100, 1, 10, 101, 2, 20, 102
        ]
        self.diff_size_non_max_expected = {
            "1:100,10:100,2:101,20:101": (75, 181), # probability: 1/16
            "1:100,10:100,2:101,20:102": (75, 181), # probability: 1/16
            "1:100,10:100,20:101,2:102": (75, 181), # probability: 1/16
            "1:100,10:100,2:102,20:102": (75, 181), # probability: 1/16
            "1:100,2:101,10:101": (28, 104), # probability: 1/32
            "1:100,2:101,20:101": (28, 104), # probability: 1/32
            "1:100,2:101,10:101,20:102": (75, 181), # probability: 1/16
            "1:100,10:101,2:102": (28, 104), # probability: 1/32
            "1:100,20:101,2:102": (28, 104), # probability: 1/32
            "1:100,10:101,2:102,20:102": (75, 181), # probability: 1/32
            "10:100,1:101,20:101": (28, 104), # probability: 1/32
            "10:100,2:101,20:101": (28, 104), # probability: 1/32
            "10:100,1:101,20:102": (28, 104), # probability: 1/32
            "10:100,2:101,20:102": (28, 104), # probability: 1/32
            "10:100,1:101,20:101,2:102": (75, 181), # probability: 1/16
            "10:100,1:101,2:102,20:102": (75, 181), # probability: 1/16
            "1:101,10:101": (8, 62), # probability: 1/64
            "1:101,20:101": (8, 62), # probability: 1/64
            "2:101,10:101": (8, 62), # probability: 1/64
            "2:101,20:101": (8, 62), # probability: 1/64
            "1:101,10:101,20:102": (28, 104), # probability: 1/32
            "2:101,10:101,20:102": (28, 104), # probability: 1/32
            "1:101,10:101,2:102": (28, 104), # probability: 1/32
            "1:101,20:101,2:102": (28, 104), # probability: 1/32
            "1:101,10:101,2:102,20:102": (75, 181) # probability: 1/16
        }

    def custom_generator(self, data):
        for item in data:
            yield item

    def file_emulator(self, *args, **kwargs):
        name = args[0]
        try:
            mode = args[1]
        except IndexError:
            mode = 'r'
        if "measurements.csv" in name:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: (
                self._measurements_file.append(s[:-1])
            )
            return r
        if "w" in mode:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = None
            return r
        return self.builtin_open(*args, **kwargs)

    def generate_result(self):
        result = []
        previous_max_value = 0
        for measurement in self._measurements_file:
            _, size, value = [int(x) for x in measurement.split(',')]
            if size == self.max_value:
                previous_max_value = value
            else:
                result.append("{0}:{1}".format(value,previous_max_value))
        self._measurements_file.clear()
        result = sorted(
            result, key=lambda x: (int(x.split(':')[1]), int(x.split(':')[0]))
        )
        return ",".join(result)

    @mock.patch('tlsfuzzer.extract.Extract._get_time_from_file')
    def test_very_simple(self, mock_times):
        results = defaultdict(lambda: 0)
        runs = self.very_simple_runs
        data = self.very_simple_data
        times = self.very_simple_times
        expected = self.very_simple_expected
        extract = Extract(output="/tmp/minerva")

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator
            for _ in range(runs):
                mock_times.return_value = self.custom_generator(times)
                extract.process_measurements_and_create_csv_file(
                    self.custom_generator(data), self.max_value
                )
                results[self.generate_result()] += 1

            for key in results:
                self.assertTrue(
                    key in expected, "unexpected key '{0}'".format(key)
                )
                self.assertGreater(
                    results[key], expected[key][0], "Very unlikely results"
                )
                self.assertLess(
                    results[key], expected[key][1], "Very unlikely results"
                )

    @unittest.skipUnless(TUPLE_RANDOMNESS_TESTS,
                 "Skipping tests for tuple creation because \
TUPLE_RANDOMNESS_TESTS env variable is not defined.")
    @mock.patch('tlsfuzzer.extract.Extract._get_time_from_file')
    def test_two_non_max_before_and_two_after(self, mock_times):
        results = defaultdict(lambda: 0)
        runs = self.two_non_max_before_and_two_after_runs
        data = self.two_non_max_before_and_two_after_data
        times = self.two_non_max_before_and_two_after_times
        expected = self.two_non_max_before_and_two_after_expected
        extract = Extract(output="/tmp/minerva")

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator
            for _ in range(runs):
                mock_times.return_value = self.custom_generator(times)
                extract.process_measurements_and_create_csv_file(
                    self.custom_generator(data), self.max_value
                )
                results[self.generate_result()] += 1

            for key in results:
                self.assertTrue(
                    key in expected, "unexpected key '{0}'".format(key)
                )
                self.assertGreater(
                    results[key], expected[key][0], "Very unlikely results"
                )
                self.assertLess(
                    results[key], expected[key][1], "Very unlikely results"
                )

    @unittest.skipUnless(TUPLE_RANDOMNESS_TESTS,
                 "Skipping tests for tuple creation because \
TUPLE_RANDOMNESS_TESTS env variable is not defined.")
    @mock.patch('tlsfuzzer.extract.Extract._get_time_from_file')
    def test_two_non_max_before_and_one_after(self, mock_times):
        results = defaultdict(lambda: 0)
        runs = self.two_non_max_before_and_one_after_runs
        data = self.two_non_max_before_and_one_after_data
        times = self.two_non_max_before_and_one_after_times
        expected = self.two_non_max_before_and_one_after_expected
        extract = Extract(output="/tmp/minerva")

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator
            for _ in range(runs):
                mock_times.return_value = self.custom_generator(times)
                extract.process_measurements_and_create_csv_file(
                    self.custom_generator(data), self.max_value
                )
                results[self.generate_result()] += 1

            for key in results:
                self.assertTrue(
                    key in expected, "unexpected key '{0}'".format(key)
                )
                self.assertGreater(
                    results[key], expected[key][0], "Very unlikely results"
                )
                self.assertLess(
                    results[key], expected[key][1], "Very unlikely results"
                )

    @unittest.skipUnless(TUPLE_RANDOMNESS_TESTS,
                 "Skipping tests for tuple creation because \
TUPLE_RANDOMNESS_TESTS env variable is not defined.")
    @mock.patch('tlsfuzzer.extract.Extract._get_time_from_file')
    def test_three_max_two_non_max_before_and_after(self, mock_times):
        results = defaultdict(lambda: 0)
        runs = self.three_max_two_non_max_before_and_after_runs
        data = self.three_max_two_non_max_before_and_after_data
        times = self.three_max_two_non_max_before_and_after_times
        expected = self.three_max_two_non_max_before_and_after_expected
        extract = Extract(output="/tmp/minerva")

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator
            for _ in range(runs):
                mock_times.return_value = self.custom_generator(times)
                extract.process_measurements_and_create_csv_file(
                    self.custom_generator(data), self.max_value
                )
                results[self.generate_result()] += 1

            for key in results:
                self.assertTrue(
                    key in expected, "unexpected key '{0}'".format(key)
                )
                self.assertGreater(
                    results[key], expected[key][0], "Very unlikely results"
                )
                self.assertLess(
                    results[key], expected[key][1], "Very unlikely results"
                )

    @unittest.skipUnless(TUPLE_RANDOMNESS_TESTS,
                 "Skipping tests for tuple creation because \
TUPLE_RANDOMNESS_TESTS env variable is not defined.")
    @mock.patch('tlsfuzzer.extract.Extract._get_time_from_file')
    def test_diff_size_non_max(self, mock_times):
        results = defaultdict(lambda: 0)
        runs = self.diff_size_non_max_runs
        data = self.diff_size_non_max_data
        times = self.diff_size_non_max_times
        expected = self.diff_size_non_max_expected
        extract = Extract(output="/tmp/minerva")

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator
            for _ in range(runs):
                mock_times.return_value = self.custom_generator(times)
                extract.process_measurements_and_create_csv_file(
                    self.custom_generator(data), self.max_value
                )
                results[self.generate_result()] += 1

            for key in results:
                self.assertTrue(
                    key in expected, "unexpected key '{0}'".format(key)
                )
                self.assertGreater(
                    results[key], expected[key][0], "Very unlikely results"
                )
                self.assertLess(
                    results[key], expected[key][1], "Very unlikely results"
                )

@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
class TestMeasurementCreation(unittest.TestCase):
    def setUp(self):
        self.builtin_open = open
        self.times_used_write = 0
        self.times_used_write_on_hamming = 0
        self.k_time_map = []

        common_dir = "measurements_test_files"

        out_dir = join(dirname(abspath(__file__)), common_dir)
        raw_times = join(dirname(abspath(__file__)),
                         common_dir, "times.bin")
        raw_sigs = join(dirname(abspath(__file__)),
                         common_dir, "sigs.bin")
        raw_data = join(dirname(abspath(__file__)),
                         common_dir, "data.bin")
        priv_key = join(dirname(abspath(__file__)),
                         common_dir, "priv_key.pem")

        self.extract = Extract(
            output=out_dir, raw_times=raw_times, binary=8,
            sigs=raw_sigs, data=raw_data, data_size=32, priv_key=priv_key,
            key_type="ec"
        )

        out_dir = join(dirname(abspath(__file__)), common_dir)
        raw_times = join(dirname(abspath(__file__)),
                         common_dir, "times_ecdh.bin")
        raw_values = join(dirname(abspath(__file__)),
                         common_dir, "secrets_ecdh.bin")
        raw_data = join(dirname(abspath(__file__)),
                         common_dir, "data_ecdh.bin")
        priv_key = join(dirname(abspath(__file__)),
                         common_dir, "priv_key_ecdh.pem")

        self.extract_ecdh = Extract(
            output=out_dir, raw_times=raw_times, binary=8,
            values=raw_values, data=raw_data, priv_key=priv_key,
            key_type="ec", verbose=True
        )

    def custom_generator(self, data):
        for item in data:
            yield item

    def add_to_times_used_write (self, i, hamming=False):
        if hamming:
            self.times_used_write_on_hamming += i
        else:
            self.times_used_write += i

    def file_emulator(self, *args, **kwargs):
        name = args[0]
        try:
            mode = args[1]
        except IndexError:
            mode = 'r'

        if type(name) == int:
            return self.builtin_open(*args, **kwargs)

        if "tmp-" in name:
            return self.builtin_open(*args, **kwargs)

        if "ecdsa-k-time-map.csv" in name:
            r = mock.mock_open(
                read_data="\n".join(self.k_time_map)
            )(name, mode)
            r.write.side_effect = lambda s: (
                self.k_time_map.append(s[:-1])
            )
            return r

        if "tmp_HWI_values.csv" in name:
            r = mock.mock_open()(name, mode)
            return r

        if "w" in mode and "measurements" in name:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: (
                self.add_to_times_used_write(1, hamming=("hamming" in name))
            )
            return r
        elif "w" in mode:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = None
            return r
        else:
            return self.builtin_open(*args, **kwargs)

    @mock.patch('__main__.__builtins__.open')
    @mock.patch('builtins.print')
    def test_measurement_creation_with_verbose_and_frequency(
            self, mock_print, mock_file
        ):
        self.extract.frequency = 1
        self.extract.verbose = True
        self.k_time_map = []

        mock_file.side_effect = self.file_emulator
        self.times_used_write = 0

        self.extract.process_measurements_and_create_csv_file(
            self.extract.ecdsa_iter(), self.extract.ecdsa_max_value()
        )

        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )

        self.times_used_write = 0
        self.extract.frequency = None
        self.extract.verbose = False
        self.k_time_map = []

    @mock.patch('builtins.print')
    def test_measurement_creation_raw_sigs(self, mock_print):
        self.k_time_map = []
        common_dir = "measurements_test_files"
        out_dir = join(dirname(abspath(__file__)), common_dir)
        raw_times = join(dirname(abspath(__file__)),
                         common_dir, "times_r_and_s.bin")
        raw_sigs = join(dirname(abspath(__file__)),
                         common_dir, "sigs_r_and_s.bin")
        raw_data = join(dirname(abspath(__file__)),
                         common_dir, "data_r_and_s.bin")
        priv_key = join(dirname(abspath(__file__)),
                         common_dir, "priv_key_r_and_s.pem")

        extract = Extract(
            output=out_dir, raw_times=raw_times, binary=8,
            sigs=raw_sigs, data=raw_data, data_size=32, priv_key=priv_key,
            key_type="ec", hash_func=None, sig_format="RAW"
        )

        self.times_used_write = 0

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator
            extract.process_measurements_and_create_csv_file(
                extract.ecdsa_iter(), extract.ecdsa_max_value()
            )

        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )

        self.times_used_write = 0
        self.k_time_map = []

    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_k_size_invert(
            self, mock_file
        ):
        self.extract._temp_HWI_name = "tmp_HWI_values.csv"

        mock_file.side_effect = self.file_emulator
        self.times_used_write = 0

        self.extract.process_measurements_and_create_csv_file(
            self.extract.ecdsa_iter(return_type="k-size-invert"),
            self.extract.ecdsa_max_value()
        )

        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )

        self.times_used_write = 0
        self.extract._temp_HWI_name = None

    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_hamming_weight(
            self, mock_file
        ):
        mock_file.side_effect = self.file_emulator
        self.times_used_write = 0

        self.extract.process_measurements_and_create_hamming_csv_file(
            self.extract.ecdsa_iter(return_type="hamming-weight")
        )

        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )

        self.times_used_write = 0

    @mock.patch('tlsfuzzer.extract.Extract._check_for_iter_left_overs')
    @mock.patch('__main__.__builtins__.print')
    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_hamming_weight_non_exact_multiple(
            self, mock_file, mock_print, mock_left_overs
        ):
        self.extract.verbose = True

        def custom_ecdsa_iter():
            counter = 0
            even_list = [127, 128, 129]
            odd_list = [125, 126, 130, 130]

            while counter < 106:
                if counter % 2 == 0:
                    yield choice(even_list)
                else:
                    yield choice(odd_list)
                counter += 1

        mock_file.side_effect = self.file_emulator
        self.times_used_write = 0

        self.extract.process_measurements_and_create_hamming_csv_file(
            custom_ecdsa_iter())

        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )
        mock_print.assert_called()

        self.times_used_write = 0
        self.extract.verbose = False

    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_hamming_weight_invert(
            self, mock_file
        ):
        mock_file.side_effect = self.file_emulator
        self.times_used_write = 0

        self.extract.process_measurements_and_create_hamming_csv_file(
            self.extract.ecdsa_iter(return_type="hamming-weight-invert")
        )

        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )

        self.times_used_write = 0

    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_invalid_iter_option(
            self, mock_file
        ):
        mock_file.side_effect = self.file_emulator

        with self.assertRaises(ValueError) as e:
            self.extract.process_measurements_and_create_csv_file(
                self.extract.ecdsa_iter(return_type="not-an-option"),
                self.extract.ecdsa_max_value()
            )

        self.assertIn(
            "Iterator return must be k-size[-invert] "
            "or hamming-weight[-invert]",
            str(e.exception)
        )

    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_wrong_hash_func(
            self, mock_file
        ):
        self.extract.hash_func = hashlib.sha384

        mock_file.side_effect = self.file_emulator

        with self.assertRaises(ValueError) as e:
            self.extract.process_measurements_and_create_csv_file(
                self.extract.ecdsa_iter(), self.extract.ecdsa_max_value()
            )

        self.assertIn("Failed to calculate k from given signatures.",
                        str(e.exception))

        self.extract.hash_func = hashlib.sha256

    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_non_existing_data_file(
            self, mock_file
        ):
        self.extract.data = self.extract.data.replace("data", "data2")

        mock_file.side_effect = self.file_emulator

        with self.assertRaises(FileNotFoundError) as e:
            self.extract.process_measurements_and_create_csv_file(
                self.extract.ecdsa_iter(), self.extract.ecdsa_max_value()
            )

        self.assertIn("No such file or directory", str(e.exception))

        self.extract.data = self.extract.data.replace("data2", "data")

    @mock.patch('builtins.print')
    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_incomplete_times(
            self, mock_file, mock_print
        ):
        original_output = self.extract.output
        self.extract.output = "/tmp/minerva"

        mock_file.side_effect = self.file_emulator
        times = self.custom_generator(
            [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 ]
        )

        with self.assertRaises(ValueError) as e:
            self.extract.process_measurements_and_create_csv_file(
                times, self.extract.ecdsa_max_value()
            )

        self.assertIn("There are some extra values that are not used.",
                      str(e.exception))

        self.extract.output = original_output

    @mock.patch('builtins.print')
    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_with_misformated_sigs(
            self, mock_file, mock_print
        ):
        def custom_file_emulator_creator(misformated_sig):
            def custom_file_emulator(*args, **kwargs):
                name = args[0]
                try:
                    mode = args[1]
                except IndexError:
                    mode = 'r'

                if type(name) == int:
                    return self.builtin_open(*args, **kwargs)

                if "w" in mode:
                    r = mock.mock_open()(name, mode)
                    r.write.side_effect = None
                    return r

                r = mock.mock_open(
                    read_data=misformated_sig
                )(name, mode)
                # r.write.side_effect = lambda s: (
                #     self.k_time_map.append(s[:-1])
                # )
                return r

            return custom_file_emulator

        # Test 1: No sequence in the beginning
        mock_file.side_effect = custom_file_emulator_creator(b"\x20")

        with self.assertRaises(ValueError) as e:
            self.extract.process_measurements_and_create_csv_file(
                self.extract.ecdsa_iter(), self.extract.ecdsa_max_value()
            )

        self.assertIn("There was an error in parsing signatures",
                      str(e.exception))

        # Test 2: No length after sequence
        mock_file.side_effect = custom_file_emulator_creator(b"\x30")

        with self.assertRaises(ValueError) as e:
            self.extract.process_measurements_and_create_csv_file(
                self.extract.ecdsa_iter(), self.extract.ecdsa_max_value()
            )

        self.assertIn("Couldn't read size of a signature.", str(e.exception))

        # Test 3: Only sequence and length
        mock_file.side_effect = custom_file_emulator_creator(b"\x30\x23")

        with self.assertRaises(ValueError) as e:
            self.extract.process_measurements_and_create_csv_file(
                self.extract.ecdsa_iter(), self.extract.ecdsa_max_value()
            )

        self.assertIn("Signature file ended unexpectedly.", str(e.exception))

        # Test 4: Sequence and length but not enough data afterwards
        mock_file.side_effect = custom_file_emulator_creator(
            b"\x30\x23" + (b"\x10" * 5))

        with self.assertRaises(ValueError) as e:
            self.extract.process_measurements_and_create_csv_file(
                self.extract.ecdsa_iter(), self.extract.ecdsa_max_value()
            )

        self.assertIn("Signature file ended unexpectedly.", str(e.exception))

        # Test 5: Raw signature not enough bytes
        self.extract.r_or_s_size = 32
        mock_file.side_effect = custom_file_emulator_creator(
            b"\x30\x23\x20" * 10)

        with self.assertRaises(ValueError) as e:
            self.extract.process_measurements_and_create_csv_file(
                self.extract.ecdsa_iter(), self.extract.ecdsa_max_value()
            )

        self.assertIn("Incomplete r or s values in binary file.",
                      str(e.exception))
        self.extract.r_or_s_size = None

    @mock.patch('__main__.__builtins__.print')
    @mock.patch('__main__.__builtins__.open')
    def test_multiple_measurement_creation(
            self, mock_file, mock_print
        ):
        self.extract.verbose = True

        mock_file.side_effect = self.file_emulator
        self.times_used_write = 0

        self.extract.process_and_create_multiple_csv_files({
            "measurements.csv": "k-size"
        })

        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )
        mock_print.assert_called()

        self.times_used_write = 0
        self.extract.verbose = False

    @mock.patch('__main__.__builtins__.print')
    @mock.patch('__main__.__builtins__.open')
    def test_multiple_measurement_creation_hamming_weight(
            self, mock_file, mock_print
        ):
        self.extract.verbose = True

        mock_file.side_effect = self.file_emulator
        self.times_used_write = 0

        self.extract.process_and_create_multiple_csv_files({
            "measurements-hamming.csv": "hamming-weight"
        })

        self.assertGreater(
            self.times_used_write_on_hamming, 0,
            "At least one measurement should have been written."
        )
        mock_print.assert_called()

        self.times_used_write_on_hamming = 0
        self.extract.verbose = False

    @mock.patch('__main__.__builtins__.print')
    @mock.patch('tlsfuzzer.extract.remove')
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_iter')
    @mock.patch('__main__.__builtins__.open')
    def test_multiple_measurement_creation_invert(
            self, mock_file, mock_ecdsa_iter, mock_remove, mock_print
        ):
        def custom_ecdsa_iter(return_type):
            counter = 0

            even_list = None
            odd_list = None
            if return_type == "k-size-invert":
                even_list = [256]
                odd_list = [255, 254, 253, 252]
            elif return_type == "hamming-weight-invert":
                even_list = [127, 128, 129]
                odd_list = [125, 126, 130, 130]

            while counter < 500:
                if counter % 2 == 0:
                    yield choice(even_list)
                else:
                    yield choice(odd_list)
                counter += 1

        mock_file.side_effect = self.file_emulator
        mock_ecdsa_iter.side_effect = custom_ecdsa_iter
        self.times_used_write = 0
        self.times_used_write_on_hamming = 0

        self.extract.process_and_create_multiple_csv_files({
            "measurements-hamming-invert.csv": "hamming-weight-invert",
            "measurements-invert.csv": "k-size-invert",
        })

        mock_print.assert_not_called()
        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )
        self.assertGreater(
            self.times_used_write_on_hamming, 0,
            "At least one measurement should have been written."
        )

        self.extract.verbose = True

        self.extract.process_and_create_multiple_csv_files({
            "measurements-hamming-invert.csv": "hamming-weight-invert",
            "measurements-invert.csv": "k-size-invert",
        })

        mock_print.assert_called()

        self.times_used_write = 0
        self.times_used_write_on_hamming = 0
        self.extract.verbose = False

    @mock.patch('__main__.__builtins__.print')
    @mock.patch('__main__.__builtins__.open')
    def test_multiple_measurement_creation_with_ecdh(
            self, mock_file, mock_print):
        mock_file.side_effect = self.file_emulator
        self.times_used_write = 0

        self.extract_ecdh.process_and_create_multiple_csv_files({
            "measurements.csv": "size"
        }, ecdh=True)

        mock_print.assert_called()
        self.assertGreater(
            self.times_used_write, 0,
            "At least one measurement should have been written."
        )

        self.times_used_write = 0

    @mock.patch('__main__.__builtins__.print')
    @mock.patch('__main__.__builtins__.open')
    def test_multiple_measurement_creation_hamming_weight_with_ecdh(
            self,mock_file, mock_print):
        mock_file.side_effect = self.file_emulator
        self.times_used_write_on_hamming = 0

        self.extract_ecdh.process_and_create_multiple_csv_files({
            "measurements-hamming.csv": "hamming-weight"
        }, ecdh=True)

        mock_print.assert_called()
        self.assertGreater(
            self.times_used_write_on_hamming, 0,
            "At least one measurement should have been written."
        )

        self.times_used_write_on_hamming = 0

    @mock.patch('__main__.__builtins__.print')
    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_unknown_with_ecdh(
            self,mock_file, mock_print):
        mock_file.side_effect = self.file_emulator

        with self.assertRaises(ValueError) as e:
            self.extract_ecdh.process_measurements_and_create_csv_file(
                self.extract.ecdh_iter(return_type="wrong"),
                self.extract.ecdh_max_value()
            )

        self.assertIn("Iterator return must be k-size or hamming-weight",
                      str(e.exception))

    @mock.patch('__main__.__builtins__.print')
    @mock.patch('__main__.__builtins__.open')
    def test_measurement_creation_invert_with_ecdh(
            self,mock_file, mock_print):
        mock_file.side_effect = self.file_emulator

        self.extract_ecdh.process_and_create_multiple_csv_files({
            "measurements-hamming.csv": "size-invert"
        }, ecdh=True)

        mock_print.assert_called()
        self.assertIn(
            mock.call("[w] Invert is not supported in ECDH. Skipping..."),
            mock_print.mock_calls
        )

    def test_k_extractions(self):
        k_value = self.extract._ecdsa_calculate_k((
            b'0F\x02!\x00\xbe.W"U\t9\x88\xe1o\xbbJ_\x03\x91\xf8+F\t\x08\xdc'
            b'\xd3\x99\x14(\x96\xe4\x8f\xb0\xc0\xcc7\x02!\x00\xbcd+\x80\xf7'
            b'\x19\xed\xee&\xdd!\'\xcd3\xb3\x05\xb5\x824q\x05\xcb\x95A\xe9f'
            b'\x8b\x811\xb9\x91\xeb',
            83983651653946891052825435279929518005474143915969857681446019417652752940765
        ))

        self.assertEqual(
            k_value, 71987597947566147878177872172206774464759466237222610742967172613160700915855,
            "The nonce value should be calculated correctly."
        )

@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping tests.")
class TestRSAExtraction(unittest.TestCase):
    def file_emulator(self, *args, **kwargs):
        name = args[0]
        try:
            mode = args[1]
        except IndexError:
            mode = 'r'
        if "measurements" in name:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: (
                self._file_writes[name].append(s[:-1])
            )
            return r
        elif "keys.pem" in name:
            r = mock.mock_open(read_data=self.keys)(name, mode)
            return r
        elif "raw_times" in name:
            r = mock.mock_open(read_data=self.times)(name, mode)
            return r
        if "w" in mode:
            r = mock.mock_open()(name, mode)
            r.write.side_effect = None
            return r
        return self.builtin_open(*args, **kwargs)

    def setUp(self):
        self.builtin_open = open

        self._file_writes = defaultdict(list)

        self.times = \
"""raw_times
0.00020507089741402605
0.0002059934765712842
0.00019222393031043447
0.00019565723238987182
0.0001830923962755899
0.00020832848543018523
0.00021710487200429402
0.0002231827851164632
0.00020670983833812588
0.00019981020196043874
0.00019833458383513867
0.00020809377105346672
0.00018978595578132706
0.00020474540295661384
0.0001886440444905395
0.00018949469432983157
0.00020388111366458653
0.0001818376112599913
0.00021440584928914512
0.0001973387367154229
0.00019065431059477997
0.00020886432585053927
0.00019457421365438348
0.00020016401477401138
0.00020348861155977603
"""

        self.keys = """
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEAwNxYQzxmyIFG3cmBt+c/
nwcUiZCE2V5j2pWZM363VTUCAwEAAQIfDYAosF93LtD4gKMThdxArAzpPbPLNQyW
U8S/w956JwIRAOqt+wJL1pnjFKzTIs6qFtsCEQDSYcTTqvvMyWEB83vlEVkvAhEA
s/Tr6UvcaS7vuMNDCrT1RwIRAJt7fE7/F/dCgXpCq7cguisCEQCINmVeC+/sO0xe
jvyL4LAR
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEAsUDuUPuNW42ra3Pn48tc
XauXg7m2pIhPo/ZUst1VUNsCAwEAAQIgK1tND90AHjFgiUeQJK2lGVI1s3w5gz4P
YlU45eNtH7UCEQDPwzBSgmgZeIkFdWjAvuqtAhEA2mhiamwErJGNMYNoKURipwIR
AK47UlrfYc16d+5L9/0sHkECEGoMsWzXUlWwvwxBsDwJdpUCEQCbho9XfVxq0EGI
lFhYsgjB
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEA6Rvm610ykipYYBdzQo0a
4LG26bCZ0PCR45VUF8wLLtMCAwEAAQIgaERku65KKnrqYMDce04mULRf68h6A82w
n5GBRnR3ZdECEQD3FzqLdUci0vtU5yI7GItNAhEA8YOdZWbxGbygKwowZOZSnwIQ
ZZXnO+67kFWtfvqH2EP/AQIRAKE27QL6Q2idrADu7Tz9LhsCEQDhpEwyMYbFBNQq
2760ChOJ
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHBAgEAMA0GCSqGSIb3DQEBAQUABIGsMIGpAgEAAiEAtho2BgpHzW3UJeuZLkzA
/z+JF2g+g7zKycBAPCuoPwsCAwEAAQIgS28YKfBgRgzU8NBjp/ZLi7zMR6B1yeG/
Qn9+Wmhi2uECEQDByBKpR6er0cTQ33gUJIm9AhEA8JIq1dizLt+OeI35LLNkZwIQ
ROipwiqp9E6nB4PABqGrnQIQLd6w7DV1dOqLb9EiQbOy4QIQUsmVYFEMVhE9yT7O
LK9ZPQ==
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEAmeOJVzlMObTEH6t7+e5e
/Z2nFYd4zgnIZE3HkdU1DxkCAwEAAQIgDkt2VcmfBMo/oKB9kPMdVCVWjQ6HIw+s
VYayPw5DckECEQDBc34kxtsX3iVDVsqNcd75AhEAy6VbJKkoDb9C1azexAkZIQIR
AJvkg1oFuhdg2GyMq4wSoJkCECLEn3P54Vm/frSmZ/4GI6ECEE9qf1Db06oS2sau
ACOQs70=
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEApnsish8Tt9FHyxT/4WMy
O9CIhiQ7nLY+6alZsbYFRm0CAwEAAQIgFNGWM6cePKDvtO4x13ojqFJ4vMuTbhAg
7gU+nR+EFfECEQDdJaLX3ugMuyhuoKm8WIYFAhEAwLfz3Aswd4FITo3Jw3EDSQIQ
azwLyceyGDJM+c/4XndCjQIRAJ/T75p+bSOvRJhhXwOHpoECECvE7o126Cza6Mhn
0zFn0fI=
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHEAgEAMA0GCSqGSIb3DQEBAQUABIGvMIGsAgEAAiEAu+mgD4HPaHtSpotqKT3E
7XGwMVQjAV0qBZlYGbOq010CAwEAAQIgBHE+z3RfgDYqJgsgX16Odo7cv3J3zttY
fcqVaRMP3gECEQDgEF8tti6N4/QKECSUs/yxAhEA1rIqZ1G6DfMLUtPpJWr8bQIR
AIulCHzH13ntQTJoXzQifPECEQC+/Odz2eQlHJxqJlE1FCNRAhEArMhDHBYz9RPD
hY+6ErAr+A==
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEA0Lsw8vwwaTbVtdnF+Iy5
fcu7xZ4JHN8KM0SjZdwKVrkCAwEAAQIgNjMdQ0MT6QYpmSZavy7/bQAtOcp7gkT/
KMJLXgsOLjcCEQDfBHIpv2hSNbvrWOgDPvi7AhEA75ndNeI1+bMcfNvrAKIhGwIQ
L3zf3lnemdrNSADnboGDLwIQLFX9X/4m3Liu+c+78ZcOpwIRANGqDkELt8xIop6o
xDT7nfo=
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEAs72I9nMGyImQFc3dOArU
jILn5xhe8RizpUOEp1plw8kCAwEAAQIgFqTjuuy954jRIrYXTyaqJT2Qn7gdrvsp
YzfRd+cDZosCEQDTWQKVm3FZH6tW48zcBvnPAhEA2bcBYqUEaWqyF8RpDyiG5wIR
AMoBWacFW+GDk5EJStVDFaECEG+5AOX9JoFuNkwKB5u2wVsCEAGM4+wba392NOeB
VT6D4pE=
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEAv4YDOSWbOX4MDVsHwnJn
3moNv6q+05qJDqmTA3rN5zUCAwEAAQIgUGx17glcpUfIx9Lx7zUbaA+DPsZBXJ4X
Z0AQTCB4SgECEQDLqRY6wSFRhpau9eYUALLTAhEA8L5tOAblybdnr62r1OZo1wIR
AMZrBDdV9gohoCjxdalDTPUCEQCHxc3RGErGPdKTSK4tLxkXAhBuClqMBeJp7B9d
qP/amhAE
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHBAgEAMA0GCSqGSIb3DQEBAQUABIGsMIGpAgEAAiEAsZ5K0/lTaXhCxx0yyqv9
t2OVUq2IUGyeZjV0bkKVubUCAwEAAQIgUQqvDLnpr6liGrS9XJEOIXDU495j2/GI
WOT/zzQofi8CEQDVFHvnmDQUgTfFHoiHxWuzAhEA1WU4DR0KhVKuQhlpO9Hw9wIQ
ZQYxOLyQ9KfPKUYwtS6EwQIQeTBhs7jRd8Pr6OgLhoiFIwIQY63yG1Pu0xrJ+DnF
lFv60Q==
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEA2m6BrBOSyXjKUEiMbfMo
hNLEsgCoGwiNSlsKAplgnlMCAwEAAQIgWU0ri5fW/7J3+Bmo+/yY9+8Oeqp7rxKc
kHJ3NF9bb3kCEQD3HHQuDwCfH5JisWsT6AXJAhEA4kn0e3PPqyJLXjI46pWBOwIR
APOuEHd2/eLsrFs8n94SeNkCEGSwNYnM8UWbn9+NB0hSN8sCEGrps8Pv1E24JTnb
iVPfSz0=
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEAzMN9F2rElLYzJmSBmv+R
9fPv2PKEZdUca+A+EMZdSC8CAwEAAQIgTHlsdDz7e2EK/HlIEHgH7kyguxPWfCa+
WEhxgKiffakCEQD8Phl+RuFAgY/bR9U6Qbd5AhEAz9BVRgFuVO+LuPgKe5YK5wIR
AMu1XyNDHODagZJG1eYhcokCEA8X+pmTEQhqPaO5oElJpJECEQCbqw4EeSsb5W1p
vXD8C4rO
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEAo7mnTgf8ImbB+GqiUEHa
yvltssVB/zeNv3t3/HhkQzMCAwEAAQIgD+POTX/v5ATWEX6D50ck7UNO2tFHOcy6
+NnT1UrAF+UCEQDY3VOZG5zxs9M/GnsD3N/vAhEAwUVncCsCYf58NmGGlWBM/QIQ
D03nRWnWdJQ9NznWLpqazwIRAJLx1edui+09s+sU02KXSXECEQDO5yqMgT2G/RKr
W8q8IMoC
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEA9nzZjObA/uHWCAmnDNvR
rEf/kG9WEx4tcypUpfA8qqkCAwEAAQIgBX0/TQuAhcyauyAX58nnb+8USLPmUPoM
qcWbwIJ6lGcCEQD7cuFKtLw7/Qrwd4Pgrtz/AhEA+vL7aTWTgjgn+yc4S+BwVwIR
AJ7Bv6DNT/OIJnoA25Dmlr0CEHTH0lt5hTWaMHDeJYKZ5W0CEQCVfpgW8DksM8ux
V2BTEi0a
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEAsHTa7p5fr+INRWtl1E3n
ghPlk3vp/4fJzLXJ5WQ29xMCAwEAAQIgUChVR+5j01ch5jYaZO4ayufpTTfHLqtr
wTvRNzIautECEQDhJH/BAP40kKxCGZaoV87ZAhEAyKQfi18iTjk3OcVQkkDZywIQ
FEIdgLdfKEmwRk5ZIRKtmQIRAMM/8/KNAbVduIBfo6ivs0ECEFHgSrPELdshgtVO
JoUm9oc=
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEAxzSTx8MlwU71rsFZdX17
UQbkC2IxCjfkcmywVxb7lDMCAwEAAQIgErJNmHcpaP5HMtK02cEgPK0HBLFYaH5+
oIypgg8FwZECEQDMlqlYSTkkfOXbMcKsSkErAhEA+UOdNMTnozGmfC7ZUPAlGQIQ
KEbI0+6mZz6Had2j+5MqvQIQbFzrnAQ6G2U7VmNbkGdGCQIRAKO5eO7BcnpR8qps
04FVsxs=
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEA1beX4vHuP+VhehJTBNAK
lwG2RT3jY51Xgd2igtWOpzECAwEAAQIgAgtK/xyG8FfZJP9BibAUYdU4i8tNe4Q6
XAEEo+Ick2ECEQD2P1K5mhe1FrzFjd/jH7Z5AhEA3i5zKDb+BUzb8lAH/eKoeQIQ
WzXbW3ozO9VfOMGzYzp06QIRAMLhY0jG05C6lcG4yQm8IaECEQDbmWztdUEWMOxL
dVTsYWUE
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEA1xiXMETBJHH/V2HzBhcN
3j8K2pvXB66NLNcidFn8w40CAwEAAQIgNNoMujZGrAUby/WcIKS1CfHAf1nTWZdI
CU/yUqM3fPECEQD3rT+lRYfILr2NNs2D8rRRAhEA3lMNQaYNZIhe3/xn/zk4fQIR
AJxQmYSjd2jeJv/DAL4wJaECEFq0Y6ovBzPG935Gyl80hzkCEQCQ7JvOAjze8shH
BjWC5YKz
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEAxe2u/y61/CPOWJxFVrsB
398posSJE1PRXlV4T5zbILUCAwEAAQIgC8qe2/msF9WzlliA/QDDxLf94dKUEzIN
iUZoW37AT+UCEQD0ECHQIpVOwnJW9R/Sayq7AhEAz5vovaLDpQ/tdlRgnC5DTwIQ
eptcES4+aYl/XTXZHaDenwIQRKzPRYPE8iIdrAnnV2KaUwIRALO/Qs06+JQHOVLc
7J/uxe8=
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHEAgEAMA0GCSqGSIb3DQEBAQUABIGvMIGsAgEAAiEA1pRujWqi0zEXToeDYaeF
mnKiLQFHKzxLFSUNqgdXqbECAwEAAQIgCUx1Xft5At3lvKlysBCqYWq1/dMd52o5
NVoxe43s2uECEQDpIJlymnPPfn5UmE1keKNTAhEA66H6lBuKtCJxAlI6y/BCawIR
AIAtFVFGjIA8Gzdl2b9w+NMCEQDP1xVetJh44XRK9tsz7d23AhEAp/aa7VdWWGdj
t786CMm8tA==
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHBAgEAMA0GCSqGSIb3DQEBAQUABIGsMIGpAgEAAiEAxsSMurJW6Z8ItWN1jI4o
JdjE7TwturP1STnwgN37mMECAwEAAQIgFzUzyUixZS2wcp1eSD8A6NVJhVayN7Po
ssPoku0QctECEQDHwFg28klzIdgD+SIykakzAhEA/r1NJrPNHgTd2nRl11P+OwIQ
Su1MabfyczxjsgHWoQ9gXwIQMGGFqKcXeu8Tr6zRts7GBwIQb+GPFSFyYO6+c9Cn
bdOrEA==
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHBAgEAMA0GCSqGSIb3DQEBAQUABIGsMIGpAgEAAiEAnipyLixuBVfAuO0dGX1k
C2+Pk8nLVkgh/Z0hKocdDEsCAwEAAQIgAYpZbuiMcJ+9BxAMtIEiayYsJyMBP99f
xqJsNfcskgECEQDQLNXFgjv+uYFVpQwAIFMLAhEAwoB4OU04SgHr7Wt2UqHzwQIQ
SeTQUNaEs0tnxF3cn6LZtwIQF7T48mMLHVomm4WhomjDAQIQT5A+TnSq9rVFAaFf
fvOJEA==
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHEAgEAMA0GCSqGSIb3DQEBAQUABIGvMIGsAgEAAiEAqaJStAuPDuNPynt1l0Ys
05DUrU+Cbku3eiZB8JWqs5MCAwEAAQIgFAMR1aq9bEi1y5HoC/ob5IJjEXVOeDBR
LKNNcpZnbL0CEQDdAUBBwBwBWSYM3TcnGjN9AhEAxH6uyKh+qq1d3ieOC2EQTwIR
AKTwPROVG5GKBhLNuk6tiEUCEQCD+RYJfWm91r0SBX0Y1XNvAhEAhOV6/AXlP+Lh
fBqzd7VvBQ==
-----END PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
MIHCAgEAMA0GCSqGSIb3DQEBAQUABIGtMIGqAgEAAiEAuAF/KqesbaDxKA6mEpNN
o7oXC8A+m+ZC+J+Cxjk03ysCAwEAAQIgNMdJIIUDslZNlb3N6NoTlHwrpk1V+M21
rfRhRKMf9vECEQDkO/7qz2S37vmCkNkhIn6tAhEAzmQSnyy6cKu0POeP8DdINwIR
AIIlQBCvoLRN/lOYu2fsnqUCEAX/Akt9kS0Uz/e1AomIEaECEEyiaxJo9SJdnlkl
F4sOO3w=
-----END PRIVATE KEY-----
"""

    def test_rsa_extractions(self):
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            extract = Extract(output="/tmp/", rsa_keys="/tmp/keys.pem",
                              raw_times="/tmp/raw_times.csv")
            extract.process_rsa_keys()

        file_name = '/tmp/measurements-d.csv'
        values = [
            [(0, 114, 0.00020388111366458653)],
            [(0, 115, 0.0001818376112599913)],
            [(0, 116, 0.00019981020196043874)],
            [(0, 119, 0.00020507089741402605)],
            [(0, 120, 0.0001830923962755899)],
            [(0, 123, 0.0002059934765712842)],
            [(0, 125, 0.00019222393031043447),
             (0, 125, 0.0002231827851164632)],
            [(0, 126, 0.00021440584928914512)],
            [(0, 127, 0.0001886440444905395),
             (0, 127, 0.00018978595578132706),
             (0, 127, 0.00020832848543018523)],
            [(0, 129, 0.00019565723238987182),
             (0, 129, 0.0001973387367154229)],
            [(0, 133, 0.00018949469432983157),
             (0, 133, 0.00019833458383513867),
             (0, 133, 0.00021710487200429402)],
            [(0, 136, 0.00020670983833812588)],
            [(0, 138, 0.00020474540295661384)],
            [(0, 152, 0.00020809377105346672)],
            [(1, 116, 0.00019457421365438348)],
            [(1, 121, 0.00020016401477401138)],
            [(1, 122, 0.00020886432585053927)],
            [(1, 130, 0.00020348861155977603)],
            [(1, 137, 0.00019065431059477997)],
        ]
        for i, j in zip(self._file_writes[file_name], values):
            self.assertIn(
                i,
                ["{0},{1},{2}".format(x, y, z) for x, y, z in j]
            )

        file_name = '/tmp/measurements-p.csv'
        values = [
            [(0, 58, 0.00019981020196043874),
             (0, 58, 0.0002059934765712842)],
            [(0, 59, 0.00018949469432983157),
             (0, 59, 0.00020388111366458653)],
            [(0, 60, 0.00019565723238987182),
             (0, 60, 0.00021710487200429402)],
            [(0, 61, 0.0001973387367154229),
             (0, 61, 0.00020809377105346672)],
            [(0, 62, 0.00019833458383513867),
             (0, 62, 0.00020832848543018523)],
            [(0, 67, 0.00018978595578132706),
             (0, 67, 0.00019222393031043447),
             (0, 67, 0.00020507089741402605)],
            [(0, 69, 0.00020670983833812588),
             (0, 69, 0.0002231827851164632)],
            [(0, 70, 0.0001830923962755899),
             (0, 70, 0.00021440584928914512)],
            [(0, 75, 0.0001886440444905395)],
            [(0, 76, 0.0001818376112599913)],
            [(0, 77, 0.00020474540295661384)],
            [(1, 53, 0.00020016401477401138)],
            [(1, 54, 0.00019457421365438348)],
            [(1, 57, 0.00020886432585053927)],
            [(1, 66, 0.00019065431059477997)],
            [(1, 72, 0.00020348861155977603)],
        ]

        for i, j in zip(self._file_writes[file_name], values):
            self.assertIn(
                i,
                ["{0},{1},{2}".format(x, y, z) for x, y, z in j]
            )

    def test_rsa_extractions_with_broken_file(self):

        self.keys = """
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEAwNxYQzxmyIFG3cmBt+c/
nwcUiZCE2V5j2pWZM363VTUCAwEAAQIfDYAosF93LtD4gKMThdxArAzpPbPLNQyW
U8S/w956JwIRAOqt+wJL1pnjFKzTIs6qFtsCEQDSYcTTqvvMyWEB83vlEVkvAhEA
s/Tr6UvcaS7vuMNDCrT1RwIRAJt7fE7/F/dCgXpCq7cguisCEQCINmVeC+/sO0xe
jvyL4LAR
"""
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            extract = Extract(output="/tmp/", rsa_keys="/tmp/keys.pem",
                              raw_times="/tmp/raw_times.csv")
            with self.assertRaises(ValueError) as e:
                extract.process_rsa_keys()

            self.assertIn("Truncated private key", str(e.exception))


    def test_rsa_extractions_with_inconsistent_file(self):

        self.keys = """
-----BEGIN PRIVATE KEY-----
MIHDAgEAMA0GCSqGSIb3DQEBAQUABIGuMIGrAgEAAiEAwNxYQzxmyIFG3cmBt+c/
nwcUiZCE2V5j2pWZM363VTUCAwEAAQIfDYAosF93LtD4gKMThdxArAzpPbPLNQyW
U8S/w956JwIRAOqt+wJL1pnjFKzTIs6qFtsCEQDSYcTTqvvMyWEB83vlEVkvAhEA
s/Tr6UvcaS7vuMNDCrT1RwIRAJt7fE7/F/dCgXpCq7cguisCEQCINmVeC+/sO0xe
jvyL4LAR
-----BEGIN PRIVATE KEY-----
"""
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            extract = Extract(output="/tmp/", rsa_keys="/tmp/keys.pem",
                              raw_times="/tmp/raw_times.csv")
            with self.assertRaises(ValueError) as e:
                extract.process_rsa_keys()

            self.assertIn("Inconsistent private key", str(e.exception))
