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
    from tlsfuzzer.extract import Extract, main, help_msg, \
        LongFormatCSVBlocker
    import multiprocessing as mp
except ImportError:
    failed_import = True

ml_kem_available = False
try:
    from kyber_py.ml_kem.default_parameters import ML_KEM_512, ML_KEM_768, \
        ML_KEM_1024
    from kyber_py.ml_kem.ml_kem import ML_KEM
    from kyber_py.ml_kem.pkcs import ek_from_pem, dk_from_pem
    ml_kem_available = True
except ImportError:
    pass

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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    max_bit_size=None, ml_kem_keys=None)
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
                    max_bit_size=None, ml_kem_keys=None)
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
                    max_bit_size=None, ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness=value_endianness, max_bit_size=None,
                    ml_kem_keys=None)
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
                    value_endianness="big", max_bit_size=max_bit_size,
                    ml_kem_keys=None)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()
                mock_process.assert_called_once()

    @mock.patch('tlsfuzzer.extract.Extract.process_ml_kem_keys')
    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_and_create_multiple_csv_files'
    )
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_ml_kem_keys_options(self, mock_parse, mock_write, mock_process,
                                  mock_write_pkt, mock_log, mock_process_mlkem):
        output = "/tmp"
        raw_times = "/tmp/times.bin"
        ciphertexts = "/tmp/ciphertexts.bin"
        priv_key = "/tmp/keys.pem"
        log_file = "/tmp/log.csv"
        args = ["extract.py",
                "-o", output,
                "--raw-times", raw_times,
                "--raw-values", ciphertexts,
                "-l", log_file,
                "--binary", "8",
                "--ml-kem-keys", priv_key]
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
                    rsa_keys=None, sig_format="DER", values=ciphertexts,
                    value_size=None, value_endianness="big",
                    max_bit_size=None, ml_kem_keys=priv_key)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_called_once_with(log_file)
                mock_process.assert_not_called()
                mock_process_mlkem.assert_called_once_with()


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


@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
class TestLongFormatCSVBlocker(unittest.TestCase):
    def setUp(self):
        self.builtin_open = open
        self._measurements_file = []

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

    def test_no_input(self):
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            writer.close()

        mock_file.assert_called()
        self.assertEqual(self._measurements_file, [])
        self.assertEqual(writer.data_points_dropped, 0)

    def test_with_too_few_values(self):
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            writer.add(128, 0.25)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(self._measurements_file, [])
        self.assertEqual(writer.data_points_dropped, 1)

    def test_with_duplicated_group(self):
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            writer.add(128, 0.25)
            writer.add(128, 0.5)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(self._measurements_file, [])
        self.assertEqual(writer.data_points_dropped, 2)

    def test_with_just_two_values(self):
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            writer.add(128, 0.25)
            writer.add(129, 0.5)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 2)
        # order doesn't matter
        self.assertIn('0,128,0.25', self._measurements_file)
        self.assertIn('0,129,0.5', self._measurements_file)
        self.assertEqual(writer.data_points_dropped, 0)

    def test_with_two_groups_and_multiple_values_per_group(self):
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            writer.add(128, 1)
            writer.add(128, 2)
            writer.add(128, 3)
            writer.add(129, 0.5)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 2)
        # order doesn't matter
        self.assertIn('0,129,0.5', self._measurements_file)
        for i in self._measurements_file:
            if i == '0,129,0.5':
                continue
            self.assertIn(i, ['0,128,1', '0,128,2', '0,128,3'])
        self.assertEqual(writer.data_points_dropped, 2)

    def test_with_with_enough_data_to_fill_a_block(self):
        data = [(128 + i, 1 + i) for i in range(10)]

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 10)
        # order doesn't matter
        for g, v in data:
            self.assertIn('0,{0},{1}'.format(g, v), self._measurements_file)
        self.assertEqual(writer.data_points_dropped, 0)

    def test_with_with_enough_data_to_fill_a_block_and_not_start_new(self):
        data = [(128 + i, 1 + i) for i in range(11)]

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 10)
        # order doesn't matter
        for g, v in data[:10]:
            self.assertIn('0,{0},{1}'.format(g, v), self._measurements_file)

        self.assertIn('0,137,10', self._measurements_file)
        self.assertNotIn('0,138,11', self._measurements_file)
        self.assertNotIn('1,138,11', self._measurements_file)
        self.assertEqual(writer.data_points_dropped, 1)

    def test_with_with_enough_data_to_fill_a_block_and_start_new(self):
        data = [(128 + i, 1 + i) for i in range(12)]

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 12)
        # order within block doesn't matter, but block numbers need to be
        # monotonic
        self.assertEqual(set(self._measurements_file[:10]),
                         set("0,{0},{1}".format(g, v) for g, v in data[:10]))
        self.assertEqual(set(self._measurements_file[10:]),
                         set("1,{0},{1}".format(g, v) for g, v in data[10:]))
        self.assertEqual(writer.data_points_dropped, 0)

    def test_with_three_blocks(self):
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv")
            writer.add(128, 1)
            for _ in range(9):
                writer.add(129, 2)
            writer.add(128, 3)
            for _ in range(9):
                writer.add(129, 4)
            writer.add(128, 5)
            writer.add(129, 6)

            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 6)
        # order within block doesn't matter, but block numbers need to be
        # monotonic
        self.assertIn('0,128,1', self._measurements_file[:2])
        self.assertIn('0,129,2', self._measurements_file[:2])
        self.assertIn('1,128,3', self._measurements_file[2:4])
        self.assertIn('1,129,4', self._measurements_file[2:4])
        self.assertIn('2,128,5', self._measurements_file[4:])
        self.assertIn('2,129,6', self._measurements_file[4:])
        self.assertEqual(writer.data_points_dropped, 8 + 8)

    def test_with_different_window_size(self):
        data = [(128 + i, 1 + i) for i in range(12)]

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv", window=12)
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 12)
        # order within block doesn't matter
        self.assertEqual(set(self._measurements_file),
                         set("0,{0},{1}".format(g, v) for g, v in data))
        self.assertEqual(writer.data_points_dropped, 0)

    def test_duplicate_set(self):
        data = [(256, 1), (255, 2)]
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv", duplicate=256)
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 2)
        # order within block doesn't matter
        self.assertEqual(set(self._measurements_file),
                         set("0,{0},{1}".format(g, v) for g, v in data))
        self.assertEqual(writer.data_points_dropped, 0)

    def test_duplicate_with_duplicated_baseline_value(self):
        data = [(255, 1), (256, 2), (256, 3)]
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv", duplicate=256)
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 3)
        # order within block doesn't matter
        self.assertEqual(set(self._measurements_file),
                         set("0,{0},{1}".format(g, v) for g, v in data))
        # but the baseline has to be first
        self.assertIn(self._measurements_file[0],
                      set("0,{0},{1}".format(g, v) for g, v in data[1:]))
        self.assertEqual(writer.data_points_dropped, 0)

    def test_duplicate_with_triplicated_baseline_value(self):
        data = [(255, 1), (256, 2), (256, 3), (256, 4)]
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv", duplicate=256)
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 3)
        # the baseline has to be first
        self.assertIn(self._measurements_file[0],
                      set("0,{0},{1}".format(g, v) for g, v in data[1:]))
        self.assertIn(self._measurements_file[1],
                      set("0,{0},{1}".format(g, v) for g, v in data[1:]))
        self.assertNotEqual(self._measurements_file[0],
                            self._measurements_file[1])
        self.assertEqual(self._measurements_file[2], "0,255,1")
        self.assertEqual(writer.data_points_dropped, 1)

    def test_duplicate_with_one_group_in_window(self):
        data = [(255, 1), (255, 1), (255, 1), (255, 2), (256, 3)]
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv",
                                          duplicate=256,
                                          window=3)
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 2)
        # the baseline has to be first
        self.assertEqual(self._measurements_file[0], "0,256,3")
        self.assertEqual(self._measurements_file[1], "0,255,2")
        self.assertEqual(writer.data_points_dropped, 3)

    def test_duplicate_with_no_baseline_in_window(self):
        data = [(255, 1), (254, 1), (253, 1), (255, 2), (256, 3)]
        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_emulator

            writer = LongFormatCSVBlocker("measurements.csv",
                                          duplicate=256,
                                          window=3)
            for g, v in data:
                writer.add(g, v)
            writer.close()

        mock_file.assert_called()
        self.assertEqual(len(self._measurements_file), 2)
        # the baseline has to be first
        self.assertEqual(self._measurements_file[0], "0,256,3")
        self.assertEqual(self._measurements_file[1], "0,255,2")
        self.assertEqual(writer.data_points_dropped, 3)


@unittest.skipIf(failed_import or not ml_kem_available,
                 "Could not import extraction or kyber_py. "
                 "Skipping related tests.")
class TestMLKEM512IntermediatesExtractor(unittest.TestCase):
    def setUp(self):
        self.dk_pem = """-----BEGIN PRIVATE KEY-----
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
YEQ=
-----END PRIVATE KEY-----"""
        self.kem, self.dk, _, self.ek = dk_from_pem(self.dk_pem)
        self.assertEqual(ML_KEM_512, self.kem)

        self.key_p = (
            b'fE&\xbc\xda\xf8E~\x11\xdb\x12j\xcb\xa1Mj\x94`/m\xe3(\x0eJ'
            b'\xd5\xaa\xb1\xd3x\xd9 \xe1')
        self.ciphertext = (
            b'\xa1\xd5\xb7/T\x97CN`\x86\xbf\xf5!\x8d\x82I0b\rF\xc0'
            b'\xce\x11\xc9y\x86\xaf\x8b\xdb4\x1a\x18k#\x9f\xa8\xd2W?K0\xbf'
            b'\x9c\xd0\x04\xa7]\x9e\x11~\x99\x8dH>\xef\xfb\x1e-\xb3\xf0\xc83'
            b'\xa8\xb4\xca\xb3D 3\x18m\xa2X~}k\xa0\x8c\xe1%^\x03Z\xf5\xa6\xdb'
            b'E\xd5\x13\xad\x86\xc9\xa9\x0e8\x1f\xdd_\xf3;\x10G\xe5\xda\xb9'
            b'\xc2{\x1f\xeb\x86#\xc6\xfewv\xacp\xee\x12\x00\x15\xb0\xed+\x93e'
            b'P,b\x02\x93(\xfc\xcc|\xb0\x136\xbcm\xc0-\x8434"\xb6\x0f\xe3C\x15'
            b'\x15\x9d\xb5\x8a\xe3\xdc4j\xa3,C\xc0I\xac\x97\xc5\x85\x9d\xf7'
            b'\xad:\xdf\x89Bp\x806\x91I\xec\xf6\x16c~\xad7\x90\x9fD\x9a\t\xe0'
            b'\xa30N\xad=\xd42o(\xc7\xef1\x9bL"\x8c\x00[\xcc\x11\xc1\x1c\x19'
            b'\x02\xe9#\xfc\x18!G8\xea\x83\x97\xb2fh\xf0\rD\x85C;,\xeb\xf5\xcc'
            b'\x1dS\x8eK{\xf7\x08OBY\xd6<j\xc8\x986C \xdd\x92\x83L\xc6\x1a'
            b'\xdf\xbc\x82\xe1\\\x95*\xdc\xcd!\x82]fE\x9a\x8b.7\'\xf7\tlB\xa4'
            b'D>.\x8f\xe7Z\xdf+#k\x1er\x90R\x029\xf9!=\xe8\x10\xefT\xbc\x9f'
            b'\x8f\xeeU\xb3\xf8i\xa8\x0bl\xa2B8z\x10\xe9hM\xcb\xde\xab\x07'
            b'\xf8!y\x03\x85\xd9\xd68\xa2q\xe9\x82*CM&)T`7-\'^\x8bP\x03\xfd!'
            b'\xaf\xb9\rk\x82\x93\xf7uE\xf5&\xdeN\xba\xa5`\xe9\x06\x16"\xa4'
            b'\xda\xcdQ\x9f->\x9d\xd9]\x9e\x9eX4\xe6YS\xf3\x1e\x80[U,\n\xcc'
            b'\xe7\xd1\xb3Kt?Eh\xcft\xa1\xdc\x11\x10\xe9\xef\xd5\xd9\xcd\t'
            b'\x08\x03\xcd\xaf\x82\xc0~QzP]\x93{!\x01\xf7O\xca\xa7P\n\x10D'
            b'\x8c\xb4\xf9\xf4\x90s9\x9a\x8b\x81\x0f\x1av@_\xd1\xbaXt\xc86'
            b'\x0bX\x8c\xfb\x93@\x1d\xd9\x1a\x00\xcd\xa3?f9\xaa\xe9\xf7\xca'
            b'\xf9\xd1m\x13\xb0\t\xd5v8l\xd5\xefg\xd7\xc2\xfc!\x00"\xae >\x92'
            b':\x84Z\xb0{L\'\xc7\x18\xc9\x94\xe3\xac\xd9\xd0h\xf1\xf1"\xa2\xb6'
            b'<\x04\x0f(\x03\x92\x0bi\x94\xe4u\xa3\xc6\x1d\xf3\xa2\xdc\x17\xc3'
            b'm\x17=\xc6\xc8\x1e)\xa9vm\xb7\xe9\x8a\xee\xd7\t\x98wq\x89-\xa7'
            b'\x8b\x8a\x94\x8f\xddQ:\x18^VP\xdcz\xcf\xb6\x08\x02\xbdsB\x95^'
            b'\xc7\xe2f\x14n\x0c`\xedv\xab5-j\xee\x9a\xeec?I\xe2\xd7\x1a\x11'
            b'\x92\xd5\x0ca\xce}\x92\xc4\x02 \xe2\xc8\x0fY\xb3UB;\x1d\x04\xf7'
            b'\xfe\x1e\xbf\xefk\x05\xd4\xaaJ\xf1\x05\xd0\xf4=\xf8\xbf\xa1)?8'
            b'\xbf\xd5Q\xfbj\xcd\xa8h)\xe2h\xf4\xd4EwY\xdb\x9b \xe5sMJFuO\xe8'
            b' Z\xd4\x18\xf4\xf1p\xc6\x1ar=\x08\x86c\xc5\xbf-\xe4+\x1d\x7f'
            b'\xc5\x82A\x96\x160\xa4r\x1c\xfd\xb00\x84T\x98;w\xc0KHv\x1aU\x7f'
            b'\xcf\x13TGs\xbf.\x01N\xc3J,\xa6\x82\xea\xa2A\xfe\x11\x05R\x92'
            b'\xec\x91\xe4\x0b\x8f\xb18\x06\'\xc0\xb5\n\x9b')

    def test_extract_intermediates(self):
        extract = Extract()
        key, values = extract._ml_kem_decaps_with_intermediates(
            self.kem, self.dk, self.ciphertext)

        self.assertEqual(self.key_p, key)
        self.assertEqual(values,
            {'bit-size-min-w': 1,
             'bit-size-s-hat-dot-u-hat': 2741,
             'bit-size-w': 2602,
             'first-diff-c-c-prime': -1,
             'hd-c-c-prime': 0,
             'hw-c-prime': 2999,
             'hw-m-prime': 137,
             'hw-r-prime': 122,
             'hw-s-hat-dot-u-hat': 1427,
             'hw-w': 1444,
             'last-diff-c-c-prime': -1})

    def test_extract_intermediates_with_bad_ciphertext(self):
        extract = Extract()
        key, values = extract._ml_kem_decaps_with_intermediates(
            self.kem, self.dk, self.ciphertext[:-1] + b'\x00')

        self.assertNotEqual(self.key_p, key)
        self.assertEqual(key,
            b'\xd9WX\x92U_&\xcc\xea\x10\xb8g\xfb=\xba\xbe\x0c\x1e\xd6Q'
            b'\xff\xe5\x9a\r\xe8M\t\xe0]\x01n\x00')
        self.assertEqual(values,
            {'bit-size-min-w': 1,
             'bit-size-s-hat-dot-u-hat': 2741,
             'bit-size-w': 2608,
             'first-diff-c-c-prime': 0,
             'hd-c-c-prime': 3094,
             'hw-c-prime': 3068,
             'hw-m-prime': 137,
             'hw-r-prime': 123,
             'hw-s-hat-dot-u-hat': 1427,
             'hw-w': 1446,
             'last-diff-c-c-prime': 767})

    def test_extract_with_wrong_key_length(self):
        extract = Extract()

        with self.assertRaises(ValueError) as e:
            key, values = extract._ml_kem_decaps_with_intermediates(
                self.kem, self.dk + b'X', self.ciphertext)

        self.assertIn("wrong decapsulation key length", str(e.exception))

    def test_extract_with_wrong_ciphertext_length(self):
        extract = Extract()

        with self.assertRaises(ValueError) as e:
            key, values = extract._ml_kem_decaps_with_intermediates(
                self.kem, self.dk, self.ciphertext + b'X')

        self.assertIn("wrong ciphertext length", str(e.exception))

    def test_extract_compare_with_kyber_py(self):
        key_prime, ciphertext = self.kem.encaps(self.ek)

        extract = Extract()
        key, values = extract._ml_kem_decaps_with_intermediates(
            self.kem, self.dk, ciphertext)

        self.assertEqual(key_prime, key)
        self.assertEqual(values.keys(),
            set(['hw-s-hat-dot-u-hat', 'bit-size-s-hat-dot-u-hat', 'hw-w',
             'bit-size-w', 'bit-size-min-w', 'hw-m-prime', 'hw-r-prime',
             'hw-c-prime', 'hd-c-c-prime', 'first-diff-c-c-prime',
             'last-diff-c-c-prime']))

        self.assertEqual(values['hd-c-c-prime'], 0)
        self.assertEqual(values['first-diff-c-c-prime'], -1)
        self.assertEqual(values['last-diff-c-c-prime'], -1)

    def test_extract_compare_with_kyber_py_malformed(self):
        key_prime, ciphertext = self.kem.encaps(self.ek)

        ciphertext = ciphertext[:-1] + bytes([ciphertext[-1] ^ 0xff])

        extract = Extract()
        key, values = extract._ml_kem_decaps_with_intermediates(
            self.kem, self.dk, ciphertext)

        self.assertNotEqual(key_prime, key)
        self.assertEqual(values.keys(),
            set(['hw-s-hat-dot-u-hat', 'bit-size-s-hat-dot-u-hat', 'hw-w',
             'bit-size-w', 'bit-size-min-w', 'hw-m-prime', 'hw-r-prime',
             'hw-c-prime', 'hd-c-c-prime', 'first-diff-c-c-prime',
             'last-diff-c-c-prime']))
        self.assertNotEqual(values['hd-c-c-prime'], 0)
        self.assertNotEqual(values['first-diff-c-c-prime'], -1)
        self.assertNotEqual(values['last-diff-c-c-prime'], -1)

    def test_reading_mlkem_from_file(self):
        mock_file = mock.mock_open(read_data=self.dk_pem)()

        extract = Extract()
        kem, key = extract._read_ml_kem_key(mock_file)

        self.assertEqual(self.kem, kem)
        self.assertEqual(self.dk, key)

    def test_reading_mlkem_from_file_with_whitespace(self):
        mock_file = mock.mock_open(
            read_data="\n \n" + self.dk_pem +"\n\t\n")()

        extract = Extract()
        kem, key = extract._read_ml_kem_key(mock_file)

        self.assertEqual(self.kem, kem)
        self.assertEqual(self.dk, key)

    def test_reading_from_empty_file(self):
        mock_file = mock.mock_open(read_data="\n")()

        extract = Extract()
        ret = extract._read_ml_kem_key(mock_file)

        self.assertIsNone(ret)

    def test_reading_with_truncated_file(self):
        mock_file = mock.mock_open(read_data=self.dk_pem[:-25])()

        extract = Extract()
        with self.assertRaises(ValueError) as e:
            ret = extract._read_ml_kem_key(mock_file)

        self.assertIn("Truncated", str(e.exception))

    def test_reading_with_truncated_and_doubled_key(self):
        mock_file = mock.mock_open(
            read_data=self.dk_pem[:-25] +
            "-----BEGIN PRIVATE KEY-----")()

        extract = Extract()
        with self.assertRaises(ValueError) as e:
            ret = extract._read_ml_kem_key(mock_file)

        self.assertIn("Inconsistent private key", str(e.exception))


@unittest.skipIf(failed_import or not ml_kem_available,
                 "Could not import extraction or kyber_py. "
                 "Skipping related tests.")
class TestMLKEM768IntermediatesExtractor(unittest.TestCase):
    def setUp(self):
        self.kem, self.dk, _, self.ek = dk_from_pem("""
-----BEGIN PRIVATE KEY-----
MIIJvgIBADALBglghkgBZQMEBAIEggmqMIIJpgRAuhXl7FiyDIrP1nx21fe7TgSP
TQIk+scB15LiPi1cPuP6h/ZJL8hIPnz8l5LLRJ5YnxQvEeeUPVBAJZvV24tq0wSC
CWC3oS5tRiuP4j1KCq2vipdrd7k3Iknp3APxWXeaFkc2ulnFtDxmoxC9WFkjOa7o
XCO4Bzf6FXFbkGIjHH5LYS4tJaTzhh3pSBssyqWEZG3HkqL4TBhFqEaEonsaRYK4
uxaecUwFCMPRsYBAa8bCWkRrsDybs5nfxDFv934nxZNKR79XWg2xNZocZBCEuCYB
hIwWSmpkWpTp+bEFCQSs5yfkSXpJM0rGHE9coB/+0C1lNz34hzFcGcpzUUT9A7I6
w7NCxysCcxkgITOVAiGf+6WXyzLmMM34VDORq2f121fgYE1qe4pF7HagtXvVdgGx
twPJOSfuqb0ekgWZ/LYFCVWIcjb2Spyzqz2JhH7w2zxT0HhHxh6pQlX4VkKt+Fss
5RwlGGfZKgkifJxAU8U8osJwRQ6780+oYSxbuwIUJGD/anqemj/G+cs3klUUtYSL
4qs1Q5PlpAnBGmiMaSniCW1Hy4ZxhgFHxGPOuFpiYBh/ZB0gYHmbu2TGQYBCimXX
0E62yCa9LLqFhDyugcqb3CcApHXqilu/JQ4QKiDZOisDuYoVfA7NtKeJtRJNhIkb
GVo5yh0rIkx6DMgSNa+79lc/MK1FRbG6JrKTBDRUt4yDCLZIi8IqB7QVExzz5mu+
iUbqEBdwEZx05hnJiL0BUlHcQWPF0cUj0qoG8rtE4xVxIiQRGqRv06t0eiXRdmUU
o2QAcgPhuYbd6KwTVCv3xCPEkmVMs7MdtVkf1F0tVwB6h0ul64YlTAn9qZgvO7SN
FMXGK8vIC6hOo6JZdhgJocCwAYTxtyodzDMgsh/+608fVGFPMW6plY2H584vkJYh
AIxnlLPT2FzH2bP2XJp0wHSe08UIA7TDMiVzNqTjdq+oYUk/QqDfIza7IF5WSh0x
YAuhkGz0BCfgl8Dr9TQYlB+ziiLKmXARFXeVUjyg0J69k5TS8GIPKbvvKr87JKz0
+DaXmgpRNgOMu4p6m4mLGEusaQ/LsIV7w1QbFCtb9V/ONT5eYM8JyRseJc/ZKjCc
Ohu1QzaKp8Xol28LYofjyc/EJYwBpQvOA5xn/M+7EUWdcpgszEptWBQokHoNJm1p
yDqFlCJHk1wiWCrFKstqEnDrqrDYGMQdyzArlXRwYsjii4sp8T0H9xZ8shTAyh0l
cVjGeZSao2EZ9VJSol0gwDFMakumx73vwEp+uzehoK7UxJjsxAqiAky8upQjpoAf
eJe85DSOA05OyMFV5Ig2fHcHhj1H8F5B26xdbDjhEXeEwJCSHLonh1IkFwAUg1vI
TJUqEAD2zJtLwmhmpig3kyKZY3i74AteklBeqHgnyBsDMQoQZBYg9VSZ2Q14QARs
7KRtk5xxus4WESAM5izxmE6A7D0LBJ32ObXZ6gRelz+e5iu81AX/2AZ7lk32VniE
M4h+yIl1hBVnu6a49aLa4FHC8AV6qoMcwlyyQs89hAJBGDErZTlslJeyyxcrk0V9
RYPR0WOtZmkodDIksb/Q/BZpoi5YFcWpArIjg64iAhJjqHFSiJkWgaW+yMqJ5EXz
gafrEXS7tcHwl5rl8yKYo7QQG456tnwD8EGBtRTVpLzz+5TIO5HJqXVa+ZJuYLD+
iqh3WgbuxotkFU0c6pc4SHiSDJXd6J7jPHYqDDI2+8pqKCxG1Bb3JplNPI3cU1zR
5wFHN7tE9nSXwaVPR2i1wWBkpkUeOWfqOUfy9zy00Twh41KqYU2cJWOPO5Jx4719
em10FxIBG7thJSulRFSCRTIcagYjcjnoVxgwCJNeSq8AlwThYRAmu3BYobdERUqn
ZQ5wg1RA6rmW/EpBZhdGnJ3hiiIj4ZHDZ2IRwpHIAXM62GBzFghViwjVk8Kn2raK
NTbdVYn8Qpz50Jdn3GV/DHy+E0fZSZhzhBouKMFI8UqBIgiJkcCbSap0cSuOeV5R
0jkRYiQX4p8PazOaHCSbuWtelAKV8ACJGgBZ8FGiakiUWXFz1DSH1qkJGGJziRYn
0L1+s1vzQjBlvGfDG3ovIkA5KH9ma4hemEYM416GYEu36Mn1MlcM+wNXBTlSxgXg
lSgV65EEJMCEdjJnWHlaBs4CcMAU9LDnyUI+ED6lk360l3aohmhGAVYclaTkUcX7
R6Ly6Lxt6AlaF45mMbv0w19hvHtQEWP0cmsJOciHwiorxxw2WqNHAH/ZO5IXSbx1
zKy0uQeJIyx2CJX3OCQpgqcCKLv5t5QF/M2OF4Hp9as42m5yRHdRl7xfx82ewyFQ
SBKqh6dpTA9TBp8n9aQDF7KSgmtHVYIrMEeL5aT8QYdK5Xm54rGoykqD8pUc4cuO
1MMshkHNt2BlV2Q/oz1mA1Da96kPwRbSQQn/0M+e9z8n0ibL8wBDg3e/WqtOtQmQ
BJLFSQeCQZZcUxZD8KDih7fTQpTm+shQ16BZJ79dg2odXGDRcJ+fgwgi8wcVW6Xb
xUbeon1QwXmhWLS+HIRvRmiuN8bMmWQqKm55oIUcxBTv+SAibC4zNpUtEQQremyf
ao92q8L7B3aegAXwM1Oqas5R11ab4aeFsYBbo059uwbp414UlTrrkkMhalD29MOM
q8RPw81tIC8xbACa2MNyEUiqJhpNdzPK4q+GIoYrwLskoYph/DbAoG4H4ibrglL8
oqJ644uuu7e1aaWhKasfFznK9r4ByC7NZz3NBSH2iYsPNw1RqFDfWbfoOnq6CmZQ
ZBoHmZ7LYV3K2hFYSXOIJCciW0FALFKlsSluyk2Fxra/GkQ+ykFzRx+264JlJkVq
NDl1CxeW5w1TAjf4x0VvchJsAysCh1yUVMMViC5gLCM/c7M9ugYo5XqT8snrQif9
1lPlMr/NAlrn1VFwWKvVyLk8iTG7sJ8DVRIOerPO2x7iYr1eaZulJLVxxy58c71d
EqxVU7Tkxk7garJlMrNnKC2ONxpUesNU5o4cmoDf2hKIs5NlhX5/KIEAshyI28+R
CQeaNsqOy7trsCBp0WIDQQuBkouz5INkBMBLWGjV8g0Cm5bZimBSgA+ahIIRaXvo
cgk6t0piNB9edK7A8az6BYBN9LcmUbKCZ0pZbE5v60XLhCHps12qUs6yqgUxwYEO
esmxELxpSYF4uoS/fOq74LUYxrbErzQR/9eD3B1oWtf9pBvxvRysTeMLtFE8JpBb
1px0sN6psUnRIqnsWfsBinmf+of2SS/ISD58/JeSy0SeWJ8ULxHnlD1QQCWb1duL
atM=
-----END PRIVATE KEY-----""")
        self.assertEqual(ML_KEM_768, self.kem)

        self.key_p = (
            b'\x86\x04\x1e^\xa1\x0ec\xc15P2F\x12\xba\xaa\xd9Q\xe4\xca-\x9b'
            b'\xbe;\xee\xf8\x10\xa6\xa8\xdd\xef@\xd1')
        self.ciphertext = (
            b'^\x05\xc4\xfa>\x8b\xaf\xb9\xd8\x9dd\xb4\x18Z_\n3hj\x13\xfe\xfa'
            b'w\x1c-b3\x16\x82\xf8b&$sE\x98O\x1a\xee\xbdL\\\xc8c\xa9\xa8!\x1a'
            b'O\\\xc3\x04n\x86\x17y}\xe1Z;\xfe\x12\x90t\x1f\xb67\x83\xec\xf8'
            b'\xdc\xe5\xc9\xea\xe7\xebV\x04\xb6\xcc&\x88\x02~\xcfv\xb9_\xfc'
            b'\xc7\x87e\xd5\x12>!V\x18\xce\xee\xb5\xf0\xd5\xd3;\xfa"\'\xbc'
            b'\x1a\x91\xb8\xaf\xfb\xc8\xf1\xb73h\x17\xdd\x83\x13\x17j\xf6'
            b'\xac+A\xb6,\xb6\xa5z]\x91\x8c\xad\x81\xc9\xca\xb1\xd7\x01!5\x12'
            b'U\xcd\xbd\x85\xdf 8\x87DJ\xaf\x97y]2l\x9c\x1c{\xdap\xf82Q4\xf3I'
            b'\xb7\xd53`\x19\xf0\xb8\x00c\x0b\xe5\r\x9c\xda\x94\x06\xd0R\xa9'
            b'\x04\xbe\xed\x8a\x9c\xd7g!\x8a\xda\xd1\xf5a\x8f\xdc`L\xa3,q!'
            b'\x9cS\xb3\xe7{J\x98: \x9e\xb0\x0e\xd7\xbf\xc2x\xd2W\xb8\x0b\xe3'
            b'c\xd3PR\x1d\xb7\x9a\xa1<\xa6\x1aZ\xb7,6TF\x94\xc6\xd7\xc1\xbf'
            b'\xb1\xfc\xa35MW\x14n\xe9\xb0\x00\xcb\x921r&\x1b\xc6q\x0c\x100'
            b'\xf4\xfe\x91\xa9\xea\xa7\x1a-\xe5J)\xc2N\xcd?\xfcP\xbf2\xb6'
            b'\xa2]L\x1f\xd2\xe7d\x91"\xc3/\x92\xbe\xd6T\xbc\x0b\xb3\xe4\xa4'
            b'\xc9r\xae\xbd\xf9\x8f\x9a\x13\xf5A$VV\xab?!\xc5>\xc31\x9e\xd1`'
            b'\x07g`\xc3\x85&?\xb5y:jy#i\xc8\xa5U\xf2T\xe9\x95Q\x1a\xf0Ny\xd8'
            b',dP\xdbV>J\xc9\xa0\x9c\n\xed2\xc8m\x0bp\xce\xdf`\xd3\x18\xb9\xfd'
            b'+\x8c\xa6_\x1b\x94\xcf`e_\xd1\x1c\xf3S\xdbz\xa2\x0e\x16\x10\xcd'
            b'\xdf\xbd|\xaao\xe7O~\xe2(\x03\xcb\x85S\x0c`\xf7/n\xf6\x81@>tj=@/'
            b'\x8e"\x06(b\r\x98\xb4\xd7\x0fm9N\x81\x80[Lu\xf6\xecs1\xbd\nJ\x10'
            b'T>oU\x1f\x8f\xf5\x00\xc6\xb4s4\xbe\x8a\xa4s\xc9\x1d\x9dj\xa8'
            b'\xd7\xeeL\xf7^\xe6\xceU*\xe3Ie\xfc\xbb\xda\xc47\xd8\xba\x824'
            b'\xf4\xb4\xb6i&\xe5\x8c\x87\xfd\xc8\xacl\xfe\xb3\xff\xd5\xb8'
            b'\xc2\x08\xceEL\xd99\x97\xa4\x06\xf3y\xa76\xab\xc0\xbag\x1a\\H'
            b'\x80\xd6I)\x169o.o\xd1\xf0v\xab\x9e?\xd7U\xaf-b\xba8\xe0$\xf7'
            b'\xa8\xb8\xb7\xc1\xd3\xc1\xbf\xed\x12:\xbf\x01\x80nd\xf6\t\xde5H'
            b'qs\x82CpG\x87\xfa]\x80a=\xbc\xc0\\\xdb\x9d!u\x94E\xf8<_Z\x81\xcd'
            b'\xaf\xf6\xc7X\xe0fZO\xf1\x81%\xffG$\x8e\xc6\x1b\xee\x0e}V\x1c'
            b'\x05\xc5O(\x0f\x9d\xa1\xabS\x17F\x91wP\xd7\x90\xa3c\\\x9dW\xae'
            b'\xb5ci\xc0Q"\xd9\x99\xce|\x9d-_\x98\xccDV\x1f\xfb\xcd\x99\xa4'
            b'\xf8b[\x18\xe2\xbb\x9c\x19\xbf#\x12\xba\xea\x89\xf0\xf98\xb1'
            b'\x90\xb3\xecT\xf0\xe7\xe3;\xe0k\xb8\xa1V\xf1!\x967\xdb`\x8f\r'
            b'\xade\xa5\x03\x9fNb\xb3A6\xce\xc8\x0e\x97(j<\xb9\xb92<\x04\xd4'
            b'\xde\xf0\xe0\xa2R&\x04\xf1\n\x90\xb1q\x8c\xbe\xed\x94\xbf/\x82'
            b'\xbbsI\xaf\x96Yv\xf0t!\'YJ\x8f\xd3\x0e\xb06\xfd\x99\xa0\x87\xf6'
            b'nPRh\x9e\xc8\x18\x88h\x00\xa4\x89/aj\xb3\x00\xc7y\x15\xc3\xb0['
            b'\xf7\xa0;>\xc2Y2\xbb\xb6\x0b\x02DN\xe55\x08\x7f\xa9`spx\xa6\x95'
            b'YZ\xdeE\xe1k0\x89\xd3aV\x17\xd3\x89p\tH\x1f\xf8\x96/\xab\x1c\x14'
            b'K\xde<Eh-\xa5\xd9J:\x04\xa6\xfe\xbd*\x80\xbf\x01\x1f\x87\xa4'
            b'\xd3\xb0\x92\xae^\x86\xdf\x14\xc4\x10\xbb\xd7\xbd\xfe\xad,\x8c'
            b'\x99\xd1\xa1(\xaf\xc7Z\x08\x8c\x95\xf6=\xe7\x1e\xf9F\x03\xbd'
            b'\xbf\x98Rl\xed\x8dDTm\xfc\xc8\x8c\xf6\xc7\x83)\xf9\x8360\xb8B7:'
            b'\x88\xf3\x80\xe4\xf1\xee\xa2\xb4\xb5`t;\x16\xd4v\x0e\xad\x80?'
            b'\x91\x86\xd3\xe3\xef\xef\x93v\xf9\xe3L\x9bB\xb6\xdf\xd8\x80\x7f'
            b'NI\xaa\x0f\xd2j\x1c\xa5\x89\xfa+\x13\t\x01?\x854\x9c\x0b\xd1\xcc'
            b'\x1d\xc7/\xa4\x1e2\xf3\xf3\x8d{\xdd\xd4\xd4\xf9\x1e\xe2+\x80*'
            b'\xc2+\x05\x7f\xd9\x87i\xae\x07W\xec\x85\x86\xdf\x85\xb1\xbcwe'
            b'\' \x9a\xee\x0f\xda\x0f\x19.\xf1=jU\xdf\xaf{w\xb8^\xf5\xa5\xd88>'
            b'\r\x1dV\xfeD\xaf\x96O\tS\tan(]0-\'\x95\xd8>\xce9d\x1c\xc8\x0f')

    def test_extract_intermediates(self):
        extract = Extract()
        key, values = extract._ml_kem_decaps_with_intermediates(
            self.kem, self.dk, self.ciphertext)

        self.assertEqual(self.key_p, key)
        self.assertEqual(values,
            {'hw-s-hat-dot-u-hat': 1483,
             'bit-size-s-hat-dot-u-hat': 2716,
             'hw-w': 1413,
             'bit-size-w': 2541,
             'bit-size-min-w': 1,
             'hw-m-prime': 123,
             'hw-r-prime': 117,
             'hw-c-prime': 4393,
             'hd-c-c-prime': 0,
             'first-diff-c-c-prime': -1,
             'last-diff-c-c-prime': -1})

    def test_extract_intermediates_with_malformed_ciphertext(self):
        extract = Extract()
        key, values = extract._ml_kem_decaps_with_intermediates(
            self.kem, self.dk, b'X' + self.ciphertext[1:])

        self.assertNotEqual(self.key_p, key)
        self.assertEqual(values.keys(),
            set(['hw-s-hat-dot-u-hat', 'bit-size-s-hat-dot-u-hat', 'hw-w',
             'bit-size-w', 'bit-size-min-w', 'hw-m-prime', 'hw-r-prime',
             'hw-c-prime', 'hd-c-c-prime', 'first-diff-c-c-prime',
             'last-diff-c-c-prime']))
        self.assertNotEqual(values['hd-c-c-prime'], 0)
        self.assertNotEqual(values['first-diff-c-c-prime'], -1)
        self.assertNotEqual(values['last-diff-c-c-prime'], -1)


@unittest.skipIf(failed_import or not ml_kem_available,
                 "Could not import extraction or kyber_py. "
                 "Skipping related tests.")
class TestMLKEM1024IntermediatesExtractor(unittest.TestCase):
    def setUp(self):
        self.kem, self.dk, _, self.ek = dk_from_pem("""
-----BEGIN PRIVATE KEY-----
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
7q8=
-----END PRIVATE KEY-----""")
        self.assertEqual(ML_KEM_1024, self.kem)

        self.key_p = (
            b'\xf0\xa6\xf2Y;\xad\xc2\xf6\xd2\x88\xec\xe3\xc3\xa1\xfe~\x1b'
            b'!\xe0\x10\xf7\x14G~\x94p\xbf\xfe\x1b\xa1M\xaa')
        self.ciphertext = (
            b'f\x1ba\xfb9Q\x95b\xa1 h\xf4q>\xbb\x9d\xc3\x87\xb9u\xb0\xbc'
            b'\xce\x8e\xe0\xea\xab\x80\xcb\xda\xc3\x91\x93\xcb\xa0J>\xa6l'
            b'\x84\xf6\xb4\xbc0\xde\x8eC\x8a\xce\xb2\xe2\x9e\x14\xd9\xd7S'
            b'\xbd(r\xbc\x8e:\xaa\xa3g\xec\xcd\xfc\x97\xeb\xdf\x06T\x9d\xb1'
            b'\xa7^\xac6\xb0\x031u\xf8\xe1e\x90\x14\xd8\x9bsKk^\xbc\x83\x11'
            b'\xd8\x91%\xa9[ \xf2\xfc\x12:\xb2}O\x18\x12\xf7T\x07Y\xe4\xde7'
            b'\xc1\xff\t\xec\x86\xf0\x92\xfa4\xef?;xM_\x07\xe7\x87x\xa62\xed'
            b'~\xc6\x1b\x9f\xc8\xc7\r\xee\xc4\x16\xb5\xb7u@\x87\xbc\xec\x04'
            b'\xf7\xe5\xed\xb9p\xf2z\xac\x0f\x03\xf5\x13\xe3?5\xc8\xcbd\xa2'
            b'w$\\\x7f\x86%\xe1\xd0\xab7;d\x84\xba(G7%\xf3K-\xc27\rBQ\xb3\xff'
            b'\x03\xd3\xf9\tY\xe58\xf1E\xdd\xf0\xbe\x15Uy\xd3Y\xfc\x19o\xfa'
            b'\x84\xb4\x8e\n\x99\xcd\x1d\xc9\x12\x92\xa1\xa1ALa\xb6\xaf\x08'
            b'\x7f\xb6\x1e\x9a\x95\xd5\xcb\xad\xdce\xb3\xf5\x07\xe7\xc3!\x18'
            b'\x96\xf3\x8f*\xec\xa7\x95}\x02N\x8bp\x86Qoe~%\x94g\xbf*\xde!'
            b'\x7f\xc0\xd3\xcf\xedod\xd7-\x10\x90)+P\xaa\x1dt\xb9KH\x90-\xc4'
            b'\x85\xa6o\x96\x0e&yX.\xae\xb3\xf4-\xb0\xfc\x1f\xef\x9c\x83h'
            b'\x9eR\xac\x96@\x10\xe5\xfe\x99_\xdb\xc7\xe3k\xdf[.\xbd\x15\x87'
            b'\tg\xc5\xd4\xa5j\x8f\x92\xc2\xf6\x85\x88\rq\xad\xf84\xe3%J\xfc'
            b'\xc8L$Zn\x9b\x9b\x17P\xc7J\x0eG\xe3kN\xf2\xf0%\xa4\xd2\x94\x97'
            b'\x95\xb15\x85\xb7\xf5\xd0\xfbDdp\xe5\x14\xb4\x1f<k/f\xf5\xb98'
            b'\x8dfy\x94\xe0xPx|l\xc6\xeaZu \x1b\x01\x1b\xa0M\x85\xfd\xb7'
            b'\xc1\xd9\xbf\x02\xa5B\xc9\xd7\x06\xa6\xa3_s\xfdK\xa2\xb3M\x1a'
            b'\x1b\xa3{\xe6\xd1\x82q\xa5\xdf\xdd\xda\xca\xf8\x97\xec3r,F\x98'
            b'\xb4\xe68\xa9\xf8\x83EF\xf4\xa0\x0f\x04\x0fQ\xa6\x8c\xcd\xfb'
            b'\x15\xd5><\xcd\xe0\xd0\x93\xd2\x00\x96)\x8b\xf7\xf2\xee$\xa4'
            b'\x89\xd2\xe3\xd4\x91\x0c\xbf\x90\xb8`\xe1\x14\xdb\xd5\x93\x8a'
            b'\x16S\xe7,N\x1eh\xc5i\xef\x1d\xed\x10\xbeh\xcd\x8eg\xb1j#[\xec'
            b'}+\x85\xafg\x95\xf43\xc0\x83)\'\x10\xb4\xf8\xd2\x14\xcc^5\xfa'
            b'\xf8\x1a\xba\xf6\xfe\xecV\xcd\xf5\xb6V\xb4\x13GP_\xd7\xac\x1e'
            b'\xab\xe9\xca\xd7a.\xb2d\x05\x8a\xb2\x88\xf8\x8a\x81\xf7\x00\x15'
            b'\xa2\xaeUU\xba\xa8\x0b~\x89NX2\x0eXB\xc06\xfc&\xf0\x0c\xc7\xdf'
            b'\x9a\x9d\xae\x9b\xc8\xc1j\x1dm}\xb5P4 !\xdb\xf0\xcaJ\xd4 \xb0-'
            b'\x02\xbe\x8d\x1b\\\x98c]rbs\xfdh.`\xaf\xe9\xf2U\x1ar\xc6\xe0SX'
            b'_o\x08&\x98\x9bS\x88d\xe3\xb6\xc0\x9a\x1f\xee\nV\xd3\x9f\xd5-'
            b'\xb7mi\xf0 \x1b\xea\x82h\xb0\xe5=\x1c\xaf\x81\x12izy\xb7\xbdS'
            b'\x81\xfd\xbd\x9a2U\x0c\xee\xf6\x0c\xff\xc4\xf0\x14~>X\x7f\x9b'
            b'\xf2?5\x8f*\xe4H\x05\x08m\xb7\xbaP\xb0\x9f\x08g\xccz\x0c\xccE'
            b'\xdc$\xe5\x18eH6\xdc\x9fH\xdc\n-\x95\x18\x92)\xee\xe4\xe1G\x13'
            b'\t\x848An\xee\x98i\x80\xc7y\n)m\xda\x16SD\x12(\x91\xab;\x96j^'
            b'\x888"\xe2\x10\x83\x9fm\x93/kj/\xf0;N\x8aO\x87\x06+\xd2\xe6Q'
            b'\xa3\'\x91\xa5\x06Y\xa0\x86\xb8\xcc/\xe9w\xf8C\x8chm\xb8\xd3'
            b'\xf1\xf0\xa5\xd2\xf8\x9aE\xa7{\xfb;\xa8\xc6\x87\xf2Y\xe8g\t'
            b'\xf7\xe5z\xe7\xcc\xeaw\x8c\xeb\x18\x0c\xde\x16\x94\xd1\x12\xa1'
            b'_\xec\x02N\x00\xfb\xeaTG\x0b\xbd\xe4\xa1\xb8Y\x0e\xf3\n\xbf\xb1'
            b'na\x86#G\x91\xd8z\xc1\xafw\x19\xc9\xc3\xfd\xbe3\x0f\xf0x?\x90'
            b'\xbc\xee\xe1\'BY0\xa2\x1c\xddJ/\xe9\x00\xb3\x8f\x8f\xbb\xebh'
            b'\x83\x18"\xb69\xf9Id\x91x\x98\x85x)\x07&\xb0\x86\x88\xf7\x8a'
            b'\xd7\xa54\x1a\x10\xbf#\x9d\xd4\x16}\x19-\x87x\x1b\xc8\xcc\xf4tx'
            b'\x8f\xaaE\x02)\xb6\xf6\xef\xce\xd8\xa2\xf6V,\x9c\x9c_5\xab\xd4'
            b'SW\xf0\x98\xa3\xa1\x9d4\x9f\x02\xcb\xe4R[\x02\xac6\xa2\xc3\x04'
            b'\x92\xd5 \x92\x1b\xacQX\x98e\xaf#\xd5\'\x0c\x078.\xbc\xf0*\x05t'
            b'\xfd\xc0o\x8b\xc2\xf2\x13\xb0\xa2\xf2\x12\xd1\x98\x02\x82\xb3d'
            b'\xb4@\xa5\xe4\x00=\x84\x1eaM\x13\nN\xc7!b\xa0\x9b\x10e\xf0xP'
            b'\x81\xef\xf0\x1e\x82\x12qW\xd3\xf7k\x89\xa5\xf7\x94t0`f\xe4'
            b'\x03\xed\xb2RD\xe4\xb7\xe1\x0b}D\xe0\xd3\xca\tf\x93\xb75(\x00'
            b'H?\x10\xacq\xf84\xaf\x86\x19\xfc\xd3\x16\xa1\x17\xf7\xb2\x8a'
            b'\xc3\xa64o!\x87\xfdz\x95"\x8b\x0e\x1e\x87O\xc5\xa61\x9b\xbfw'
            b'\xf9\x11\x93m\xa5\x94\xac\xbc\xc0\x10u!2\xfc\x131\xae\xb0\x1f'
            b'{u\xf3\x9e+_\xceMbrn\xb7\x83+\xb4\xf0bH\x18HH\xbb!/\xc0\xa9\x0e'
            b'\x90\x14\x89\xd1\xa9s\xb2\x94G\xc1\x16\xfbL\xa6\xcfV\x0e)\x7f'
            b'\xcf\xa6;g\x87|\xaf\x8e\xa6=l\x93\x19\x8chX\x03\x1b9[vv\xec\xb4'
            b'\x80\x85\xden\xfc\x04n\x16.\xfb\xf2H\x01\x8aU\xf8\x85\xe4\x0eG'
            b'\xb0\xe6&\xd1\x04\x12\x87\xfd`=\xec\x17\x9a\xfb\xd4^\xaeK\x022'
            b'\xd5\xcd\xcb\xdcY\xc7g\xc50\x9e\'F\xcf_\x8f\xf4\x8f\xb7\xfc\x85'
            b'3\x04C\xb5zl\x1b\x01\xd0h\x1d80\x9d)]\xce\x81:o\xf94l\xa3A\x884'
            b'\x92\x80\xe9T\x18w\x9f\xe8\x0e\x1e\x07\xe1\xf6;\xdfP\\\xea]\x06'
            b'f\x8e\xf2\xc4\xefc\x91j\xcc\x88\xf8Y\x06\x1a\xed\x0c\xae\xf2\x7f'
            b'M\n\x84\xde\x0fl%\xe5\xbf^\x99\x91\xff)\x038\x97\xfa\x15\x19iFz'
            b'R\\\x9b\x08\x1e\xc9\xa1\xc2\x9f0\x1f\x9f1\x01\xd8\x9e\xf0<\xf9'
            b'\x86q\x7f\xd3\t\xf7~\xd4Z\xfd\x81me\xc5\xa1\xe3\xd4\xe7\x8ax'
            b'\xeb\xf7]\xa0\xe8\xb1bE\xa6\xd7\x88|\x93\x0bqS\xa7\x8e\xf4\x8e'
            b'\xcbI\xb9\xabi*#RAW \x0co-e\xa5\x96\x1b#\xe7@\xfdK9\x7f\x05\x19'
            b'\xbauGw\xd2\xf9,\xbeDT\xadA\xb8\x0f\x14C\xffv\xddb\xf9\xdd\xc7h'
            b'?\x1bhB\xe4\xb5,\x19z@uQ\x80\xf6`\xee\xeb:v1\xd5\xcaq2*\xc8\x02'
            b'Bn\xeb\xf0\xaa7\x0e\xb8,\xe4\x84(\x11')

    def test_extract_intermediates(self):
        extract = Extract()
        key, values = extract._ml_kem_decaps_with_intermediates(
            self.kem, self.dk, self.ciphertext)

        self.assertEqual(self.key_p, key)
        self.assertEqual(values,
            {'bit-size-min-w': 1,
             'bit-size-s-hat-dot-u-hat': 2789,
             'bit-size-w': 2529,
             'first-diff-c-c-prime': -1,
             'hd-c-c-prime': 0,
             'hw-c-prime': 6272,
             'hw-m-prime': 127,
             'hw-r-prime': 131,
             'hw-s-hat-dot-u-hat': 1457,
             'hw-w': 1411,
             'last-diff-c-c-prime': -1})

    def test_extract_intermediates_with_malformed_ciphertext(self):
        extract = Extract()
        key, values = extract._ml_kem_decaps_with_intermediates(
            self.kem, self.dk, b'X' + self.ciphertext[1:])

        self.assertNotEqual(self.key_p, key)
        self.assertEqual(values.keys(),
            set(['hw-s-hat-dot-u-hat', 'bit-size-s-hat-dot-u-hat', 'hw-w',
             'bit-size-w', 'bit-size-min-w', 'hw-m-prime', 'hw-r-prime',
             'hw-c-prime', 'hd-c-c-prime', 'first-diff-c-c-prime',
             'last-diff-c-c-prime']))
        self.assertNotEqual(values['hd-c-c-prime'], 0)
        self.assertNotEqual(values['first-diff-c-c-prime'], -1)
        self.assertNotEqual(values['last-diff-c-c-prime'], -1)


@unittest.skipIf(failed_import or not ml_kem_available,
                 "Could not import extraction or kyber_py, skipping")
class TestFullExtraction(unittest.TestCase):
    def setUp(self):
        self.builtin_open = open
        self.outputs = defaultdict(list)

    def file_selector(self, *args, **kwargs):
        name = args[0]
        mode = args[1]

        if "w" in mode or "a" in mode:
            self.assertIn("/tmp", name)
            r = mock.mock_open()(name, mode)
            r.write.side_effect = lambda s: self.outputs[name].append(s)
            return r
        return self.builtin_open(*args, **kwargs)

    @mock.patch('builtins.print')
    def test_extract_verbose(self, mock_print):
        common_dir = "mlkem512_test_files"
        out_dir = join(dirname(abspath(__file__)), common_dir)
        out_dir = "/tmp/a"
        raw_times = join(dirname(abspath(__file__)), common_dir,
                         "raw_times.csv")
        raw_ciphertexts = join(dirname(abspath(__file__)), common_dir,
                               "ciphers.bin")
        log_file = join(dirname(abspath(__file__)), common_dir,
                        "log.csv")
        key_file = join(dirname(abspath(__file__)), common_dir,
                        "dk.pem")

        log = Log(log_file)
        log.read_log()

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_selector
            extract = Extract(log, output=out_dir, raw_times=raw_times,
                              values=raw_ciphertexts, ml_kem_keys=key_file,
                              verbose=True, delay=1)

            extract.parse()

            extract.process_ml_kem_keys()

        self.assertEqual(mock_print.mock_calls[0],
                         mock.call('Writing to /tmp/a/timing.csv\n'))
        for c in mock_print.mock_calls[1:]:
            if c != mock.call():
                self.assertIn('Done: ', str(c))

    @mock.patch('builtins.print')
    def test_extract(self, mock_print):
        common_dir = "mlkem512_test_files"
        out_dir = join(dirname(abspath(__file__)), common_dir)
        out_dir = "/tmp/a"
        raw_times = join(dirname(abspath(__file__)), common_dir,
                         "raw_times.csv")
        raw_ciphertexts = join(dirname(abspath(__file__)), common_dir,
                               "ciphers.bin")
        log_file = join(dirname(abspath(__file__)), common_dir,
                        "log.csv")
        key_file = join(dirname(abspath(__file__)), common_dir,
                        "dk.pem")

        log = Log(log_file)
        log.read_log()

        with mock.patch('__main__.__builtins__.open') as mock_file:
            mock_file.side_effect = self.file_selector
            extract = Extract(log, output=out_dir, raw_times=raw_times,
                              values=raw_ciphertexts, ml_kem_keys=key_file)

            extract.parse()

            extract.process_ml_kem_keys()

        self.assertEqual(set([
            '/tmp/a/timing.csv',
            '/tmp/a/measurements-bit-size-min-w.csv',
            '/tmp/a/measurements-first-diff-c-c-prime.csv',
            '/tmp/a/measurements-last-diff-c-c-prime.csv',
            '/tmp/a/measurements-hw-m-prime.csv',
            '/tmp/a/measurements-hw-r-prime.csv',
            '/tmp/a/measurements-hd-c-c-prime.csv',
            '/tmp/a/measurements-hw-s-hat-dot-u-hat.csv',
            '/tmp/a/measurements-bit-size-s-hat-dot-u-hat.csv',
            '/tmp/a/measurements-hw-w.csv',
            '/tmp/a/measurements-bit-size-w.csv',
            '/tmp/a/measurements-hw-c-prime.csv']), self.outputs.keys())

        file = '/tmp/a/timing.csv'
        self.assertEqual(self.outputs[file],
            ['one_u_remain_0,one_u_remain_1,one_v_remain_0,one_v_remain_-1,random_0,random_1,valid_0,valid_1,valid_2,xor_u_coefficient_0_1,xor_u_coefficient_-1_1,xor_v_coefficient_0_1,xor_v_coefficient_-1_1\r\n',
             '2.572230000e+06,2.539137000e+06,2.656580000e+06,2.674955000e+06,2.656605000e+06,2.674829000e+06,2.690352000e+06,2.666550000e+06,2.614733000e+06,2.658934000e+06,2.664320000e+06,2.635011000e+06,2.672320000e+06\r\n',
             '2.590677000e+06,2.583684000e+06,2.624952000e+06,2.653114000e+06,2.706152000e+06,2.672175000e+06,2.687308000e+06,2.704215000e+06,2.717891000e+06,2.676333000e+06,2.751911000e+06,2.671540000e+06,2.646080000e+06\r\n',
             '2.659281000e+06,2.654878000e+06,2.675695000e+06,3.581513000e+06,2.698066000e+06,2.791494000e+06,2.696919000e+06,2.729882000e+06,2.768880000e+06,2.623325000e+06,2.748901000e+06,2.729885000e+06,2.722352000e+06\r\n',
             '2.641593000e+06,2.642752000e+06,2.705510000e+06,2.706439000e+06,2.763182000e+06,2.713622000e+06,2.711581000e+06,2.688373000e+06,2.745355000e+06,2.756074000e+06,2.741499000e+06,2.734472000e+06,2.723980000e+06\r\n',
             '2.648782000e+06,2.663268000e+06,2.770663000e+06,2.739362000e+06,2.777486000e+06,2.767834000e+06,2.720834000e+06,2.737402000e+06,2.740656000e+06,2.735921000e+06,2.740835000e+06,2.734270000e+06,2.739939000e+06\r\n',
             '3.124822000e+06,2.655880000e+06,2.743632000e+06,3.304483000e+06,2.770717000e+06,3.541447000e+06,3.341956000e+06,2.908643000e+06,3.217506000e+06,3.216138000e+06,2.933603000e+06,2.786638000e+06,2.738585000e+06\r\n',
             '2.786364000e+06,2.755239000e+06,2.850841000e+06,2.934163000e+06,2.827179000e+06,2.871078000e+06,2.908413000e+06,2.872655000e+06,2.856293000e+06,2.833760000e+06,2.878577000e+06,2.879560000e+06,2.837547000e+06\r\n',
             '2.859223000e+06,2.735037000e+06,2.772793000e+06,2.828338000e+06,2.802157000e+06,2.810243000e+06,3.433362000e+06,2.762381000e+06,2.842058000e+06,2.841991000e+06,3.351845000e+06,2.917893000e+06,3.423473000e+06\r\n',
             '3.190742000e+06,3.005240000e+06,3.072507000e+06,2.891758000e+06,3.067056000e+06,2.881629000e+06,3.227947000e+06,2.994336000e+06,2.869151000e+06,3.005836000e+06,3.084320000e+06,3.100945000e+06,3.442762000e+06\r\n',
             '2.756092000e+06,2.748371000e+06,2.781808000e+06,2.960446000e+06,2.852706000e+06,2.877404000e+06,2.820347000e+06,2.948172000e+06,2.841697000e+06,2.843591000e+06,2.854258000e+06,2.978798000e+06,2.890212000e+06\r\n',
             '2.765088000e+06,2.697088000e+06,2.791742000e+06,2.809755000e+06,2.804332000e+06,2.816708000e+06,2.801115000e+06,2.795346000e+06,2.814629000e+06,2.814142000e+06,2.778207000e+06,2.876003000e+06,2.823811000e+06\r\n',
             '2.684130000e+06,2.719657000e+06,2.750889000e+06,2.811323000e+06,2.816287000e+06,2.795115000e+06,2.799193000e+06,2.846137000e+06,2.812452000e+06,2.813432000e+06,2.804510000e+06,2.820829000e+06,2.782602000e+06\r\n',
             '2.696997000e+06,2.723556000e+06,2.777127000e+06,2.794831000e+06,2.817826000e+06,2.770422000e+06,2.764272000e+06,2.827870000e+06,2.833299000e+06,2.896012000e+06,2.809983000e+06,2.800712000e+06,2.809013000e+06\r\n',
             '2.701380000e+06,2.717912000e+06,2.776701000e+06,2.811292000e+06,2.790875000e+06,2.799023000e+06,2.834446000e+06,2.795074000e+06,2.771604000e+06,2.803210000e+06,2.783898000e+06,2.801718000e+06,2.789133000e+06\r\n',
             '2.711023000e+06,2.704018000e+06,2.774304000e+06,2.784363000e+06,2.785108000e+06,2.815381000e+06,2.778631000e+06,2.816000000e+06,2.813170000e+06,2.760370000e+06,2.816559000e+06,2.792629000e+06,2.817598000e+06\r\n',
             '2.708738000e+06,2.730276000e+06,2.772447000e+06,2.783604000e+06,2.756647000e+06,2.787260000e+06,2.798221000e+06,2.800018000e+06,2.877947000e+06,2.763520000e+06,2.812582000e+06,2.799340000e+06,2.806605000e+06\r\n',
             '2.689384000e+06,2.700321000e+06,2.777137000e+06,2.786992000e+06,2.794991000e+06,2.809944000e+06,2.791107000e+06,2.758542000e+06,2.825234000e+06,2.826249000e+06,2.763352000e+06,2.776540000e+06,2.802626000e+06\r\n',
             '2.686514000e+06,2.725750000e+06,2.750459000e+06,2.788483000e+06,2.819103000e+06,2.805215000e+06,2.809930000e+06,2.757718000e+06,2.781780000e+06,2.827473000e+06,2.802392000e+06,2.814223000e+06,2.805529000e+06\r\n',
             '2.700336000e+06,2.681396000e+06,2.772463000e+06,2.776506000e+06,2.792328000e+06,2.787726000e+06,2.737963000e+06,2.788824000e+06,2.787959000e+06,2.748083000e+06,2.791562000e+06,2.821158000e+06,3.187148000e+06\r\n',
             '2.698854000e+06,2.685893000e+06,2.756865000e+06,2.791965000e+06,2.763223000e+06,2.783552000e+06,2.762609000e+06,2.826866000e+06,2.761837000e+06,2.821408000e+06,2.769735000e+06,2.773473000e+06,2.795917000e+06\r\n',
             '2.695711000e+06,2.685215000e+06,2.790532000e+06,2.796162000e+06,2.784972000e+06,2.758635000e+06,2.793543000e+06,2.804230000e+06,2.838838000e+06,2.783282000e+06,2.763466000e+06,2.901240000e+06,2.820575000e+06\r\n',
             '2.194092000e+06,2.666475000e+06,2.929719000e+06,2.799468000e+06,5.091971000e+06,2.576191000e+06,2.742707000e+06,2.496774000e+06,2.397017000e+06,2.732538000e+06,2.263720000e+06,2.813752000e+06,2.813234000e+06\r\n',
             '2.559889000e+06,2.495434000e+06,2.717675000e+06,2.718163000e+06,2.677578000e+06,2.705773000e+06,2.668929000e+06,2.700598000e+06,2.724140000e+06,2.681932000e+06,2.713144000e+06,2.610770000e+06,2.663192000e+06\r\n',
             '2.653542000e+06,2.663698000e+06,2.701039000e+06,2.712339000e+06,2.773274000e+06,2.731750000e+06,2.735094000e+06,2.728166000e+06,2.735284000e+06,2.700910000e+06,2.724852000e+06,2.740931000e+06,2.752070000e+06\r\n',
             '2.904858000e+06,2.624228000e+06,2.707859000e+06,2.781345000e+06,2.771292000e+06,2.745362000e+06,2.780931000e+06,2.770167000e+06,2.765083000e+06,2.735497000e+06,2.772022000e+06,2.750777000e+06,2.736476000e+06\r\n',
             '2.720670000e+06,2.701805000e+06,2.730738000e+06,2.790359000e+06,2.780604000e+06,2.817485000e+06,2.808541000e+06,2.814247000e+06,2.786495000e+06,2.776676000e+06,2.792465000e+06,2.793528000e+06,2.764339000e+06\r\n',
             '2.669518000e+06,2.663886000e+06,2.811316000e+06,2.770822000e+06,2.800608000e+06,2.807728000e+06,2.803005000e+06,2.839349000e+06,2.841855000e+06,2.773391000e+06,2.846973000e+06,2.748178000e+06,2.793392000e+06\r\n',
             '2.717150000e+06,2.689604000e+06,2.778848000e+06,2.775789000e+06,2.778202000e+06,2.808522000e+06,2.796464000e+06,2.805407000e+06,2.778683000e+06,2.810381000e+06,2.792809000e+06,2.799400000e+06,2.866992000e+06\r\n',
             '2.700918000e+06,2.703050000e+06,2.836313000e+06,2.791022000e+06,2.798520000e+06,2.803956000e+06,2.824437000e+06,2.775316000e+06,2.831991000e+06,2.813211000e+06,2.790672000e+06,2.836003000e+06,2.782021000e+06\r\n',
             '2.735040000e+06,2.709845000e+06,2.749616000e+06,2.762941000e+06,2.837907000e+06,2.827838000e+06,2.809134000e+06,2.822137000e+06,2.808263000e+06,2.818860000e+06,2.789109000e+06,2.812528000e+06,2.816486000e+06\r\n',
             '2.780255000e+06,2.726475000e+06,2.785017000e+06,2.784842000e+06,2.775503000e+06,2.790499000e+06,2.795441000e+06,2.808169000e+06,2.777816000e+06,2.787499000e+06,2.817461000e+06,2.816753000e+06,3.127248000e+06\r\n',
             '2.708226000e+06,2.716293000e+06,2.827461000e+06,2.789650000e+06,2.793284000e+06,2.826770000e+06,2.818464000e+06,2.850188000e+06,2.824999000e+06,2.782662000e+06,2.778032000e+06,2.833960000e+06,2.832242000e+06\r\n',
             '2.717125000e+06,2.733272000e+06,2.799662000e+06,2.801511000e+06,2.848954000e+06,2.768944000e+06,2.806477000e+06,2.804353000e+06,2.810200000e+06,2.800792000e+06,2.794705000e+06,2.833714000e+06,2.805942000e+06\r\n',
             '2.709014000e+06,2.738645000e+06,3.044498000e+06,2.834852000e+06,2.831300000e+06,2.825362000e+06,2.764948000e+06,2.733619000e+06,2.800412000e+06,2.847463000e+06,2.812836000e+06,2.824113000e+06,2.806710000e+06\r\n',
             '2.703545000e+06,2.703287000e+06,2.769727000e+06,2.773068000e+06,3.024705000e+06,2.803746000e+06,2.787976000e+06,2.799205000e+06,2.814536000e+06,2.799415000e+06,2.796276000e+06,2.798286000e+06,2.801405000e+06\r\n',
             '2.714528000e+06,2.679689000e+06,2.760758000e+06,2.803761000e+06,2.769376000e+06,2.816339000e+06,2.827674000e+06,2.847376000e+06,2.803459000e+06,2.820196000e+06,2.805301000e+06,2.799047000e+06,2.828614000e+06\r\n',
             '2.725654000e+06,2.863613000e+06,3.347308000e+06,2.980255000e+06,2.919609000e+06,2.982949000e+06,2.816876000e+06,3.042228000e+06,2.863814000e+06,2.950160000e+06,3.090746000e+06,2.816989000e+06,2.974773000e+06\r\n',
             '2.862930000e+06,3.403212000e+06,3.593056000e+06,3.014363000e+06,3.030002000e+06,3.186475000e+06,3.047822000e+06,3.364158000e+06,3.084208000e+06,3.447368000e+06,3.046161000e+06,3.664542000e+06,3.400597000e+06\r\n',
             '2.959023000e+06,3.021788000e+06,3.077686000e+06,3.006585000e+06,2.942449000e+06,3.182813000e+06,2.965627000e+06,3.028775000e+06,2.903878000e+06,3.109377000e+06,3.047479000e+06,3.079459000e+06,3.053340000e+06\r\n',
             '2.986616000e+06,2.774974000e+06,3.169540000e+06,2.910753000e+06,2.891751000e+06,3.090321000e+06,2.964355000e+06,3.119323000e+06,2.965541000e+06,2.928101000e+06,2.934025000e+06,2.963911000e+06,2.912077000e+06\r\n',
             '4.195615000e+06,2.777965000e+06,2.838710000e+06,2.804378000e+06,2.885424000e+06,2.793306000e+06,2.910929000e+06,2.811782000e+06,2.932779000e+06,2.850346000e+06,2.807106000e+06,2.804100000e+06,2.955593000e+06\r\n',
             '2.891865000e+06,3.436874000e+06,2.872695000e+06,2.860240000e+06,2.845683000e+06,2.981166000e+06,3.340413000e+06,3.546538000e+06,2.762922000e+06,2.560185000e+06,3.128096000e+06,2.809481000e+06,2.869655000e+06\r\n',
             '2.694089000e+06,2.831107000e+06,2.770571000e+06,2.872435000e+06,2.830507000e+06,2.941309000e+06,2.966371000e+06,2.866713000e+06,3.127749000e+06,2.817272000e+06,2.825719000e+06,2.928612000e+06,2.819591000e+06\r\n',
             '2.729372000e+06,2.894303000e+06,2.818246000e+06,2.813086000e+06,2.782988000e+06,2.836979000e+06,2.800187000e+06,2.810860000e+06,2.828343000e+06,2.845889000e+06,2.802742000e+06,2.882664000e+06,2.831120000e+06\r\n',
             '2.799888000e+06,2.695335000e+06,2.872335000e+06,2.861776000e+06,2.981983000e+06,2.902221000e+06,2.806787000e+06,2.836621000e+06,2.844417000e+06,2.863254000e+06,2.804428000e+06,2.941791000e+06,2.917902000e+06\r\n',
             '2.930570000e+06,2.806625000e+06,2.822822000e+06,2.843650000e+06,3.170775000e+06,2.869919000e+06,2.827247000e+06,2.837320000e+06,3.234042000e+06,3.028785000e+06,2.821637000e+06,2.840395000e+06,2.822427000e+06\r\n',
             '2.711820000e+06,2.707712000e+06,2.787411000e+06,2.859147000e+06,2.854505000e+06,2.826262000e+06,2.809364000e+06,2.811082000e+06,2.865974000e+06,2.882337000e+06,2.813373000e+06,2.873042000e+06,2.789262000e+06\r\n',
             '2.712025000e+06,2.735011000e+06,2.830406000e+06,2.794619000e+06,2.838427000e+06,2.852528000e+06,2.808623000e+06,2.817257000e+06,2.810003000e+06,2.817172000e+06,2.818400000e+06,2.798703000e+06,2.810428000e+06\r\n',
             '2.674005000e+06,2.696488000e+06,2.770171000e+06,2.808643000e+06,2.818076000e+06,2.807992000e+06,2.812205000e+06,2.814529000e+06,2.830373000e+06,2.852529000e+06,2.840067000e+06,2.804107000e+06,3.065319000e+06\r\n',
             '2.721891000e+06,2.711746000e+06,2.854555000e+06,2.811399000e+06,2.853789000e+06,2.820944000e+06,2.874700000e+06,2.788269000e+06,2.819923000e+06,2.833031000e+06,2.827690000e+06,2.800409000e+06,2.804366000e+06\r\n'])

        file = "/tmp/a/measurements-bit-size-min-w.csv"
        self.assertEqual(len(self.outputs[file]), 462)
        self.assertIn(self.outputs[file][:3],
            [['0,0,2635011.0\n', '0,2,2658934.0\n', '0,1,2614733.0\n'],
             ['0,0,2635011.0\n', '0,2,2658934.0\n', '0,1,2690352.0\n'],
             ['0,0,2635011.0\n', '0,2,2664320.0\n', '0,1,2690352.0\n'],
             ['0,0,2635011.0\n', '0,2,2664320.0\n', '0,1,2614733.0\n']])
        self.assertIn(self.outputs[file][-5:],
            [['109,0,2711746.0\n', '109,0,2800409.0\n', '109,6,2820944.0\n', '109,1,2833031.0\n', '109,4,2853789.0\n'],
             ['109,0,2800409.0\n', '109,0,2711746.0\n', '109,6,2820944.0\n', '109,1,2833031.0\n', '109,4,2853789.0\n']])

        file = "/tmp/a/measurements-first-diff-c-c-prime.csv"
        self.assertEqual(len(self.outputs[file]), 475)
        self.assertIn(self.outputs[file][:4],
            [['0,0,2658934.0\n', '0,638,2664320.0\n', '0,-1,2614733.0\n', '0,640,2635011.0\n'],
             ['0,0,2658934.0\n', '0,638,2664320.0\n', '0,-1,2690352.0\n', '0,640,2635011.0\n'],
             ])
        self.assertIn(self.outputs[file][-3:],
            [['123,0,2833031.0\n', '123,0,2820944.0\n', '123,640,2800409.0\n'],
             ['123,0,2833031.0\n', '123,0,2711746.0\n', '123,640,2800409.0\n'],
             ['123,0,2833031.0\n', '123,0,2853789.0\n', '123,640,2800409.0\n'],
             ['123,0,2820944.0\n', '123,0,2833031.0\n', '123,640,2800409.0\n'],
             ['123,0,2820944.0\n', '123,0,2853789.0\n', '123,640,2800409.0\n'],
             ['123,0,2820944.0\n', '123,0,2711746.0\n', '123,640,2800409.0\n'],
             ['123,0,2711746.0\n', '123,0,2833031.0\n', '123,640,2800409.0\n'],
             ['123,0,2711746.0\n', '123,0,2820944.0\n', '123,640,2800409.0\n'],
             ['123,0,2711746.0\n', '123,0,2853789.0\n', '123,640,2800409.0\n'],
             ['123,0,2853789.0\n', '123,0,2711746.0\n', '123,640,2800409.0\n'],
             ['123,0,2853789.0\n', '123,0,2833031.0\n', '123,640,2800409.0\n'],
             ['123,0,2853789.0\n', '123,0,2820944.0\n', '123,640,2800409.0\n']])

        file = "/tmp/a/measurements-last-diff-c-c-prime.csv"
        self.assertEqual(len(self.outputs[file]), 478)
        self.assertIn(self.outputs[file][:3],
            [['0,767,2646080.0\n', '0,767,2672320.0\n', '0,-1,2666550.0\n'],
             ['0,767,2646080.0\n', '0,767,2656605.0\n', '0,-1,2666550.0\n'],
             ['0,767,2646080.0\n', '0,767,2624952.0\n', '0,-1,2666550.0\n'],
             ['0,767,2624952.0\n', '0,767,2646080.0\n', '0,-1,2666550.0\n'],
             ['0,767,2624952.0\n', '0,767,2656605.0\n', '0,-1,2666550.0\n'],
             ['0,767,2624952.0\n', '0,767,2672320.0\n', '0,-1,2666550.0\n'],
             ['0,767,2672320.0\n', '0,767,2646080.0\n', '0,-1,2666550.0\n'],
             ['0,767,2672320.0\n', '0,767,2624952.0\n', '0,-1,2666550.0\n'],
             ['0,767,2672320.0\n', '0,767,2656605.0\n', '0,-1,2666550.0\n'],
             ['0,767,2656605.0\n', '0,767,2646080.0\n', '0,-1,2666550.0\n'],
             ['0,767,2656605.0\n', '0,767,2672320.0\n', '0,-1,2666550.0\n'],
             ['0,767,2656605.0\n', '0,767,2624952.0\n', '0,-1,2666550.0\n'],
             ])
        self.assertIn(self.outputs[file][-4:],
            [['126,767,2711746.0\n', '126,767,2853789.0\n', '126,640,2800409.0\n', '126,0,2833031.0\n'],
             ['126,767,2711746.0\n', '126,767,2820944.0\n', '126,640,2800409.0\n', '126,0,2833031.0\n'],
             ['126,767,2853789.0\n', '126,767,2711746.0\n', '126,640,2800409.0\n', '126,0,2833031.0\n'],
             ['126,767,2853789.0\n', '126,767,2820944.0\n', '126,640,2800409.0\n', '126,0,2833031.0\n'],
             ['126,767,2820944.0\n', '126,767,2711746.0\n', '126,640,2800409.0\n', '126,0,2833031.0\n'],
             ['126,767,2820944.0\n', '126,767,2853789.0\n', '126,640,2800409.0\n', '126,0,2833031.0\n'],
            ])

        file = "/tmp/a/measurements-hw-m-prime.csv"
        self.assertEqual(len(self.outputs[file]), 495)
        # since for HW test files we won't get duplicates, we don't need to
        # look at the whole group, just at individual elements
        self.assertEqual(self.outputs[file][0], '0,119,2656580.0\n')
        self.assertEqual(self.outputs[file][1], '0,123,2674955.0\n')
        self.assertIn(self.outputs[file][2], ['0,128,2656605.0\n', '0,128,2674829.0\n'])
        self.assertEqual(self.outputs[file][3], '0,130,2572230.0\n')
        self.assertIn(self.outputs[file][4], ['0,129,2539137.0\n', '0,129,2672320.0\n'])
        self.assertIn(self.outputs[file][5], ['0,136,2664320.0\n', '0,136,2624952.0\n'])
        self.assertEqual(self.outputs[file][6], '0,120,2614733.0\n')
        self.assertEqual(self.outputs[file][7], '0,121,2690352.0\n')
        self.assertEqual(self.outputs[file][8], '0,117,2658934.0\n')
        self.assertEqual(self.outputs[file][9], '0,133,2635011.0\n')
        self.assertEqual(self.outputs[file][10], '0,118,2666550.0\n')
        self.assertIn(self.outputs[file][11], ['0,127,2646080.0\n', '0,127,2687308.0\n'])
        self.assertEqual(self.outputs[file][12], '0,138,2671540.0\n')
        self.assertIn(self.outputs[file][13], ['1,131,2729882.0\n', '1,131,2672175.0\n'])

        self.assertEqual(self.outputs[file][-5], '37,139,2804366.0\n')
        self.assertEqual(self.outputs[file][-4], '38,141,2711746.0\n')
        self.assertEqual(self.outputs[file][-3], '38,143,2820944.0\n')
        self.assertEqual(self.outputs[file][-2], '38,115,2833031.0\n')
        self.assertEqual(self.outputs[file][-1], '38,124,2853789.0\n')

        file = "/tmp/a/measurements-hw-r-prime.csv"
        self.assertEqual(len(self.outputs[file]), 497)
        # since for HW test files we won't get duplicates, we don't need to
        # look at the whole group, just at individual elements
        self.assertIn(self.outputs[file][0], ['0,121,2656580.0\n', '0,121,2690352.0\n', '0,121,2687308.0\n'])
        self.assertEqual(self.outputs[file][1], '0,113,2674955.0\n')
        self.assertEqual(self.outputs[file][2], '0,140,2674829.0\n')
        self.assertEqual(self.outputs[file][3], '0,127,2572230.0\n')
        self.assertEqual(self.outputs[file][4], '0,117,2539137.0\n')
        self.assertEqual(self.outputs[file][5], '0,131,2664320.0\n')
        self.assertEqual(self.outputs[file][6], '0,123,2614733.0\n')
        self.assertEqual(self.outputs[file][7], '0,139,2658934.0\n')
        self.assertEqual(self.outputs[file][8], '0,151,2635011.0\n')
        self.assertEqual(self.outputs[file][9], '0,126,2666550.0\n')
        self.assertEqual(self.outputs[file][10], '0,138,2672320.0\n')
        self.assertIn(self.outputs[file][11], ['0,128,2656605.0\n', '0,128,2671540.0\n'])
        self.assertEqual(self.outputs[file][12], '0,120,2646080.0\n')
        self.assertEqual(self.outputs[file][13], '0,137,2624952.0\n')
        self.assertEqual(self.outputs[file][14], '1,134,2672175.0\n')

        self.assertEqual(self.outputs[file][-4], '37,136,2804366.0\n')
        self.assertIn(self.outputs[file][-3], ['38,121,2711746.0\n', '38,121,2833031.0\n'])
        self.assertEqual(self.outputs[file][-2], '38,115,2820944.0\n')
        self.assertEqual(self.outputs[file][-1], '38,126,2853789.0\n')

        file = "/tmp/a/measurements-hd-c-c-prime.csv"
        self.assertEqual(len(self.outputs[file]), 369)
        # since for HW test files we won't get duplicates, we don't need to
        # look at the whole group, just at individual elements
        self.assertEqual(self.outputs[file][0], '0,3056,2656580.0\n')
        self.assertEqual(self.outputs[file][1], '0,3090,2674955.0\n')
        self.assertEqual(self.outputs[file][2], '0,3123,2674829.0\n')
        self.assertEqual(self.outputs[file][3], '0,3105,2572230.0\n')
        self.assertEqual(self.outputs[file][4], '0,3074,2539137.0\n')
        self.assertIn(self.outputs[file][5], ['0,1,2671540.0\n', '0,1,2658934.0\n', '0,1,2672320.0\n', '0,1,2646080.0\n', '0,1,2664320.0\n', '0,1,2635011.0\n'])
        self.assertIn(self.outputs[file][6], ['0,0,2690352.0\n', '0,0,2666550.0\n', '0,0,2614733.0\n', '0,0,2687308.0\n'])
        self.assertEqual(self.outputs[file][7], '0,3145,2656605.0\n')
        self.assertEqual(self.outputs[file][8], '0,3071,2624952.0\n')
        self.assertEqual(self.outputs[file][9], '1,3062,2672175.0\n')

        self.assertEqual(self.outputs[file][-5],'37,3038,2721891.0\n')
        self.assertEqual(self.outputs[file][-4],'38,3064,2711746.0\n')
        self.assertEqual(self.outputs[file][-3],'38,3074,2820944.0\n')
        self.assertEqual(self.outputs[file][-2],'38,1,2833031.0\n')
        self.assertEqual(self.outputs[file][-1],'38,3121,2853789.0\n')

        file = "/tmp/a/measurements-hw-s-hat-dot-u-hat.csv"
        self.assertEqual(len(self.outputs[file]), 579)
        # since for HW test files we won't get duplicates, we don't need to
        # look at the whole group, just at individual elements
        self.assertEqual(self.outputs[file][0], '0,1497,2656580.0\n')
        self.assertEqual(self.outputs[file][1], '0,1487,2674955.0\n')
        self.assertEqual(self.outputs[file][2], '0,1483,2674829.0\n')
        self.assertEqual(self.outputs[file][3], '0,1490,2572230.0\n')
        self.assertEqual(self.outputs[file][4], '0,1492,2539137.0\n')
        self.assertEqual(self.outputs[file][5], '0,1485,2664320.0\n')
        self.assertEqual(self.outputs[file][6], '0,1486,2614733.0\n')
        self.assertEqual(self.outputs[file][7], '0,1421,2690352.0\n')
        self.assertEqual(self.outputs[file][8], '0,1481,2658934.0\n')
        self.assertEqual(self.outputs[file][9], '0,1458,2635011.0\n')
        self.assertEqual(self.outputs[file][10], '0,1489,2666550.0\n')
        self.assertEqual(self.outputs[file][11], '0,1434,2672320.0\n')
        self.assertIn(self.outputs[file][12], ['0,1447,2656605.0\n', '0,1447,2748901.0\n'])
        self.assertEqual(self.outputs[file][13], '0,1440,2646080.0\n')
        self.assertEqual(self.outputs[file][14], '0,1455,2624952.0\n')
        self.assertIn(self.outputs[file][15], ['0,1450,2583684.0\n', '0,1450,2671540.0\n'])
        self.assertEqual(self.outputs[file][16], '0,1511,2687308.0\n')
        self.assertEqual(self.outputs[file][17], '0,1449,2672175.0\n')
        self.assertEqual(self.outputs[file][18], '0,1448,2706152.0\n')
        self.assertEqual(self.outputs[file][19], '0,1417,2653114.0\n')
        self.assertEqual(self.outputs[file][20], '0,1452,2717891.0\n')
        self.assertEqual(self.outputs[file][21], '0,1445,2751911.0\n')
        self.assertEqual(self.outputs[file][22], '0,1529,2704215.0\n')
        self.assertEqual(self.outputs[file][23], '0,1498,2590677.0\n')
        self.assertEqual(self.outputs[file][24], '0,1444,2676333.0\n')
        self.assertEqual(self.outputs[file][25], '0,1478,2698066.0\n')
        self.assertEqual(self.outputs[file][26], '0,1469,2791494.0\n')
        self.assertEqual(self.outputs[file][27], '0,1510,2722352.0\n')
        self.assertEqual(self.outputs[file][28], '1,1463,2768880.0\n')

        self.assertEqual(self.outputs[file][-21], '20,1472,2840067.0\n')
        self.assertEqual(self.outputs[file][-20], '21,1472,2808643.0\n')
        self.assertEqual(self.outputs[file][-19], '21,1456,2812205.0\n')
        self.assertEqual(self.outputs[file][-18], '21,1440,2674005.0\n')
        self.assertEqual(self.outputs[file][-17], '21,1471,2804107.0\n')
        self.assertEqual(self.outputs[file][-16], '21,1475,3065319.0\n')
        self.assertEqual(self.outputs[file][-15], '21,1450,2807992.0\n')
        self.assertEqual(self.outputs[file][-14], '21,1493,2696488.0\n')
        self.assertEqual(self.outputs[file][-13], '21,1522,2819923.0\n')
        self.assertEqual(self.outputs[file][-12], '21,1476,2788269.0\n')
        self.assertEqual(self.outputs[file][-11], '21,1503,2874700.0\n')
        self.assertEqual(self.outputs[file][-10], '21,1453,2811399.0\n')
        self.assertEqual(self.outputs[file][-9], '21,1445,2854555.0\n')
        self.assertEqual(self.outputs[file][-8], '21,1523,2721891.0\n')
        self.assertEqual(self.outputs[file][-7], '21,1478,2827690.0\n')
        self.assertEqual(self.outputs[file][-6], '21,1405,2804366.0\n')
        self.assertEqual(self.outputs[file][-5], '21,1477,2800409.0\n')
        self.assertEqual(self.outputs[file][-4], '21,1421,2711746.0\n')
        self.assertEqual(self.outputs[file][-3], '21,1474,2820944.0\n')
        self.assertEqual(self.outputs[file][-2], '21,1442,2833031.0\n')
        self.assertEqual(self.outputs[file][-1], '21,1447,2853789.0\n')

        file = "/tmp/a/measurements-bit-size-s-hat-dot-u-hat.csv"
        self.assertEqual(len(self.outputs[file]), 551)
        # since for HW test files we won't get duplicates, we don't need to
        # look at the whole group, just at individual elements
        self.assertEqual(self.outputs[file][0], '0,2775,2656580.0\n')
        self.assertEqual(self.outputs[file][1], '0,2785,2674955.0\n')
        self.assertIn(self.outputs[file][2], ['0,2786,2674829.0\n', '0,2786,2658934.0\n'])
        self.assertEqual(self.outputs[file][3], '0,2758,2572230.0\n')
        self.assertEqual(self.outputs[file][4], '0,2788,2539137.0\n')
        self.assertEqual(self.outputs[file][5], '0,2750,2664320.0\n')
        self.assertIn(self.outputs[file][6], ['0,2776,2722352.0\n', '0,2776,2614733.0\n'])
        self.assertEqual(self.outputs[file][7], '0,2735,2690352.0\n')
        self.assertEqual(self.outputs[file][8], '0,2747,2635011.0\n')
        self.assertIn(self.outputs[file][9], ['0,2761,2717891.0\n', '0,2761,2666550.0\n'])
        self.assertEqual(self.outputs[file][10], '0,2762,2672320.0\n')
        self.assertEqual(self.outputs[file][11], '0,2769,2656605.0\n')
        self.assertIn(self.outputs[file][12], ['0,2741,2646080.0\n', '0,2741,2676333.0\n'])
        self.assertEqual(self.outputs[file][13], '0,2794,2624952.0\n')
        self.assertEqual(self.outputs[file][14], '0,2737,2671540.0\n')
        self.assertEqual(self.outputs[file][15], '0,2793,2687308.0\n')
        self.assertIn(self.outputs[file][16], ['0,2772,2672175.0\n', '0,2772,2751911.0\n', '0,2772,2590677.0\n'])
        self.assertEqual(self.outputs[file][17], '0,2744,2706152.0\n')
        self.assertEqual(self.outputs[file][18], '0,2782,2653114.0\n')
        self.assertEqual(self.outputs[file][19], '0,2724,2583684.0\n')
        self.assertEqual(self.outputs[file][20], '0,2765,2704215.0\n')
        self.assertEqual(self.outputs[file][21], '0,2742,2698066.0\n')
        self.assertEqual(self.outputs[file][22], '0,2748,2791494.0\n')
        self.assertEqual(self.outputs[file][23], '0,2736,2748901.0\n')
        self.assertEqual(self.outputs[file][24], '1,2787,2768880.0\n')

        self.assertEqual(self.outputs[file][-20], '20,2805,2840067.0\n')
        self.assertEqual(self.outputs[file][-19], '21,2792,2808643.0\n')
        self.assertEqual(self.outputs[file][-18], '21,2717,2812205.0\n')
        self.assertEqual(self.outputs[file][-17], '21,2744,2674005.0\n')
        self.assertEqual(self.outputs[file][-16], '21,2746,2804107.0\n')
        self.assertEqual(self.outputs[file][-15], '21,2766,3065319.0\n')
        self.assertEqual(self.outputs[file][-14], '21,2748,2807992.0\n')
        self.assertIn(self.outputs[file][-13], ['21,2758,2800409.0\n', '21,2758,2696488.0\n'])
        self.assertEqual(self.outputs[file][-12], '21,2806,2819923.0\n')
        self.assertEqual(self.outputs[file][-11], '21,2760,2788269.0\n')
        self.assertEqual(self.outputs[file][-10], '21,2763,2874700.0\n')
        self.assertEqual(self.outputs[file][-9], '21,2773,2811399.0\n')
        self.assertEqual(self.outputs[file][-8], '21,2721,2854555.0\n')
        self.assertEqual(self.outputs[file][-7], '21,2762,2721891.0\n')
        self.assertEqual(self.outputs[file][-6], '21,2769,2827690.0\n')
        self.assertEqual(self.outputs[file][-5], '21,2730,2804366.0\n')
        self.assertEqual(self.outputs[file][-4], '21,2733,2711746.0\n')
        self.assertEqual(self.outputs[file][-3], '21,2776,2820944.0\n')
        self.assertEqual(self.outputs[file][-2], '21,2767,2833031.0\n')
        self.assertEqual(self.outputs[file][-1], '21,2738,2853789.0\n')

        file = "/tmp/a/measurements-hw-w.csv"
        self.assertEqual(len(self.outputs[file]), 591)
        # since for HW test files we won't get duplicates, we don't need to
        # look at the whole group, just at individual elements
        self.assertIn(self.outputs[file][0], ['0,1461,2672175.0\n', '0,1461,2656580.0\n'])
        self.assertEqual(self.outputs[file][1], '0,1467,2674955.0\n')
        self.assertEqual(self.outputs[file][2], '0,1455,2674829.0\n')
        self.assertEqual(self.outputs[file][3], '0,1443,2572230.0\n')
        self.assertEqual(self.outputs[file][4], '0,1492,2539137.0\n')
        self.assertEqual(self.outputs[file][5], '0,1389,2664320.0\n')
        self.assertEqual(self.outputs[file][6], '0,1387,2614733.0\n')
        self.assertEqual(self.outputs[file][7], '0,1411,2690352.0\n')
        self.assertEqual(self.outputs[file][8], '0,1421,2658934.0\n')
        self.assertEqual(self.outputs[file][9], '0,1354,2635011.0\n')
        self.assertEqual(self.outputs[file][10], '0,1416,2666550.0\n')
        self.assertIn(self.outputs[file][11], ['0,1398,2748901.0\n', '0,1398,2672320.0\n'])
        self.assertEqual(self.outputs[file][12], '0,1452,2656605.0\n')
        self.assertIn(self.outputs[file][13], ['0,1454,2646080.0\n', '0,1454,2698066.0\n'])
        self.assertIn(self.outputs[file][14], ['0,1481,2590677.0\n', '0,1481,2624952.0\n'])
        self.assertEqual(self.outputs[file][15], '0,1435,2671540.0\n')
        self.assertEqual(self.outputs[file][16], '0,1401,2687308.0\n')
        self.assertEqual(self.outputs[file][17], '0,1472,2706152.0\n')
        self.assertEqual(self.outputs[file][18], '0,1466,2653114.0\n')
        self.assertEqual(self.outputs[file][19], '0,1468,2583684.0\n')
        self.assertEqual(self.outputs[file][20], '0,1446,2717891.0\n')
        self.assertEqual(self.outputs[file][21], '0,1418,2751911.0\n')
        self.assertEqual(self.outputs[file][22], '0,1437,2704215.0\n')
        self.assertEqual(self.outputs[file][23], '0,1380,2676333.0\n')
        self.assertEqual(self.outputs[file][24], '0,1429,2791494.0\n')
        self.assertEqual(self.outputs[file][25], '0,1440,2722352.0\n')
        self.assertEqual(self.outputs[file][26], '1,1417,2768880.0\n')

        self.assertEqual(self.outputs[file][-21], '20,1375,2840067.0\n')
        self.assertEqual(self.outputs[file][-20], '21,1449,2808643.0\n')
        self.assertEqual(self.outputs[file][-19], '21,1399,2812205.0\n')
        self.assertEqual(self.outputs[file][-18], '21,1433,2674005.0\n')
        self.assertEqual(self.outputs[file][-17], '21,1450,2804107.0\n')
        self.assertEqual(self.outputs[file][-16], '21,1420,3065319.0\n')
        self.assertEqual(self.outputs[file][-15], '21,1432,2807992.0\n')
        self.assertEqual(self.outputs[file][-14], '21,1471,2696488.0\n')
        self.assertEqual(self.outputs[file][-13], '21,1424,2819923.0\n')
        self.assertEqual(self.outputs[file][-12], '21,1373,2788269.0\n')
        self.assertEqual(self.outputs[file][-11], '21,1411,2874700.0\n')
        self.assertEqual(self.outputs[file][-10], '21,1440,2811399.0\n')
        self.assertEqual(self.outputs[file][-9], '21,1455,2854555.0\n')
        self.assertEqual(self.outputs[file][-8], '21,1419,2721891.0\n')
        self.assertEqual(self.outputs[file][-7], '21,1368,2827690.0\n')
        self.assertEqual(self.outputs[file][-6], '21,1382,2804366.0\n')
        self.assertEqual(self.outputs[file][-5], '21,1406,2800409.0\n')
        self.assertEqual(self.outputs[file][-4], '21,1474,2711746.0\n')
        self.assertEqual(self.outputs[file][-3], '21,1485,2820944.0\n')
        self.assertEqual(self.outputs[file][-2], '21,1362,2833031.0\n')
        self.assertEqual(self.outputs[file][-1], '21,1446,2853789.0\n')

        file = "/tmp/a/measurements-bit-size-w.csv"
        self.assertEqual(len(self.outputs[file]), 617)
        # since for HW test files we won't get duplicates, we don't need to
        # look at the whole group, just at individual elements
        self.assertEqual(self.outputs[file][0], '0,2786,2656580.0\n')
        self.assertEqual(self.outputs[file][1], '0,2752,2674955.0\n')
        self.assertEqual(self.outputs[file][2], '0,2775,2674829.0\n')
        self.assertEqual(self.outputs[file][3], '0,2756,2572230.0\n')
        self.assertEqual(self.outputs[file][4], '0,2805,2539137.0\n')
        self.assertEqual(self.outputs[file][5], '0,2534,2664320.0\n')
        self.assertEqual(self.outputs[file][6], '0,2509,2614733.0\n')
        self.assertEqual(self.outputs[file][7], '0,2489,2690352.0\n')
        self.assertEqual(self.outputs[file][8], '0,2555,2658934.0\n')
        self.assertEqual(self.outputs[file][9], '0,2547,2635011.0\n')
        self.assertEqual(self.outputs[file][10], '0,2515,2666550.0\n')
        self.assertEqual(self.outputs[file][11], '0,2511,2672320.0\n')
        self.assertEqual(self.outputs[file][12], '0,2770,2656605.0\n')
        self.assertEqual(self.outputs[file][13], '0,2598,2646080.0\n')
        self.assertEqual(self.outputs[file][14], '0,2765,2624952.0\n')
        self.assertEqual(self.outputs[file][15], '0,2562,2671540.0\n')
        self.assertEqual(self.outputs[file][16], '0,2575,2687308.0\n')
        self.assertEqual(self.outputs[file][17], '0,2783,2672175.0\n')
        self.assertEqual(self.outputs[file][18], '0,2758,2706152.0\n')
        self.assertEqual(self.outputs[file][19], '0,2729,2653114.0\n')
        self.assertEqual(self.outputs[file][20], '0,2732,2583684.0\n')
        self.assertIn(self.outputs[file][21], ['0,2585,2717891.0\n', '0,2585,2704215.0\n'])
        self.assertEqual(self.outputs[file][22], '0,2544,2751911.0\n')
        self.assertEqual(self.outputs[file][23], '0,2780,2590677.0\n')
        self.assertEqual(self.outputs[file][24], '0,2503,2676333.0\n')
        self.assertEqual(self.outputs[file][25], '0,2743,2698066.0\n')
        self.assertEqual(self.outputs[file][26], '0,2747,2791494.0\n')
        self.assertEqual(self.outputs[file][27], '0,2530,2748901.0\n')
        self.assertEqual(self.outputs[file][28], '0,2582,2722352.0\n')
        self.assertEqual(self.outputs[file][29], '1,2521,2768880.0\n')

        self.assertEqual(self.outputs[file][-21], '20,2564,2840067.0\n')
        self.assertEqual(self.outputs[file][-20], '21,2760,2808643.0\n')
        self.assertEqual(self.outputs[file][-19], '21,2594,2812205.0\n')
        self.assertEqual(self.outputs[file][-18], '21,2722,2674005.0\n')
        self.assertEqual(self.outputs[file][-17], '21,2593,2804107.0\n')
        self.assertEqual(self.outputs[file][-16], '21,2561,3065319.0\n')
        self.assertEqual(self.outputs[file][-15], '21,2761,2807992.0\n')
        self.assertEqual(self.outputs[file][-14], '21,2754,2696488.0\n')
        self.assertEqual(self.outputs[file][-13], '21,2562,2819923.0\n')
        self.assertEqual(self.outputs[file][-12], '21,2515,2788269.0\n')
        self.assertEqual(self.outputs[file][-11], '21,2552,2874700.0\n')
        self.assertEqual(self.outputs[file][-10], '21,2739,2811399.0\n')
        self.assertEqual(self.outputs[file][-9], '21,2762,2854555.0\n')
        self.assertEqual(self.outputs[file][-8], '21,2744,2721891.0\n')
        self.assertEqual(self.outputs[file][-7], '21,2498,2827690.0\n')
        self.assertEqual(self.outputs[file][-6], '21,2536,2804366.0\n')
        self.assertEqual(self.outputs[file][-5], '21,2523,2800409.0\n')
        self.assertEqual(self.outputs[file][-4], '21,2752,2711746.0\n')
        self.assertEqual(self.outputs[file][-3], '21,2788,2820944.0\n')
        self.assertEqual(self.outputs[file][-2], '21,2509,2833031.0\n')
        self.assertEqual(self.outputs[file][-1], '21,2728,2853789.0\n')

        file = "/tmp/a/measurements-hw-c-prime.csv"
        self.assertEqual(len(self.outputs[file]), 577)
        # since for HW test files we won't get duplicates, we don't need to
        # look at the whole group, just at individual elements
        self.assertEqual(self.outputs[file][0], '0,3054,2656580.0\n')
        self.assertEqual(self.outputs[file][1], '0,3079,2674955.0\n')
        self.assertEqual(self.outputs[file][2], '0,3107,2674829.0\n')
        self.assertEqual(self.outputs[file][3], '0,3077,2572230.0\n')
        self.assertEqual(self.outputs[file][4], '0,3029,2539137.0\n')
        self.assertEqual(self.outputs[file][5], '0,3015,2664320.0\n')
        self.assertEqual(self.outputs[file][6], '0,3042,2614733.0\n')
        self.assertEqual(self.outputs[file][7], '0,3117,2690352.0\n')
        self.assertEqual(self.outputs[file][8], '0,3119,2658934.0\n')
        self.assertEqual(self.outputs[file][9], '0,3100,2635011.0\n')
        self.assertEqual(self.outputs[file][10], '0,2983,2666550.0\n')
        self.assertEqual(self.outputs[file][11], '0,3049,2672320.0\n')
        self.assertEqual(self.outputs[file][12], '0,3000,2656605.0\n')
        self.assertEqual(self.outputs[file][13], '0,3059,2646080.0\n')
        self.assertEqual(self.outputs[file][14], '0,3090,2624952.0\n')
        self.assertEqual(self.outputs[file][15], '0,3056,2671540.0\n')
        self.assertEqual(self.outputs[file][16], '0,3102,2687308.0\n')
        self.assertEqual(self.outputs[file][17], '0,3110,2672175.0\n')
        self.assertEqual(self.outputs[file][18], '0,3031,2706152.0\n')
        self.assertEqual(self.outputs[file][19], '0,3037,2653114.0\n')
        self.assertEqual(self.outputs[file][20], '0,3072,2583684.0\n')
        self.assertIn(self.outputs[file][21], ['0,3087,2717891.0\n', '0,3087,2590677.0\n'])
        self.assertEqual(self.outputs[file][22], '0,3131,2751911.0\n')
        self.assertEqual(self.outputs[file][23], '0,3034,2704215.0\n')
        self.assertEqual(self.outputs[file][24], '0,3101,2676333.0\n')
        self.assertEqual(self.outputs[file][25], '0,3068,2698066.0\n')
        self.assertEqual(self.outputs[file][26], '0,3134,2791494.0\n')
        self.assertEqual(self.outputs[file][27], '0,3073,2748901.0\n')
        self.assertEqual(self.outputs[file][28], '0,3108,2722352.0\n')
        self.assertEqual(self.outputs[file][29], '1,3061,2768880.0\n')

        self.assertEqual(self.outputs[file][-20], '20,3031,2840067.0\n')
        self.assertEqual(self.outputs[file][-19], '21,3080,2808643.0\n')
        self.assertEqual(self.outputs[file][-18], '21,3154,2812205.0\n')
        self.assertEqual(self.outputs[file][-17], '21,3061,2674005.0\n')
        self.assertEqual(self.outputs[file][-16], '21,3023,2804107.0\n')
        self.assertIn(self.outputs[file][-15], ['21,3111,2788269.0\n', '21,3111,3065319.0\n'])
        self.assertEqual(self.outputs[file][-14], '21,3026,2807992.0\n')
        self.assertEqual(self.outputs[file][-13], '21,3079,2696488.0\n')
        self.assertEqual(self.outputs[file][-12], '21,3119,2819923.0\n')
        self.assertEqual(self.outputs[file][-11], '21,3069,2874700.0\n')
        self.assertEqual(self.outputs[file][-10], '21,3113,2811399.0\n')
        self.assertEqual(self.outputs[file][-9], '21,3063,2854555.0\n')
        self.assertEqual(self.outputs[file][-8], '21,3073,2721891.0\n')
        self.assertEqual(self.outputs[file][-7], '21,3038,2827690.0\n')
        self.assertEqual(self.outputs[file][-6], '21,3047,2804366.0\n')
        self.assertEqual(self.outputs[file][-5], '21,3103,2800409.0\n')
        self.assertEqual(self.outputs[file][-4], '21,3088,2711746.0\n')
        self.assertEqual(self.outputs[file][-3], '21,3075,2820944.0\n')
        self.assertEqual(self.outputs[file][-2], '21,3152,2833031.0\n')
        self.assertEqual(self.outputs[file][-1], '21,3065,2853789.0\n')
