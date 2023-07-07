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

from tlsfuzzer.utils.log import Log

failed_import = False
try:
    from tlsfuzzer.extract import Extract, main, help_msg
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

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
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
                    verbose=False)
                mock_measurements.assert_not_called()

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
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
                    verbose=False)
                mock_measurements.assert_not_called()

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
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
                    verbose=False)
                mock_measurements.assert_not_called()

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
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
                    verbose=False)
                mock_measurements.assert_not_called()

    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
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
                    verbose=False)
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
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
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
                    verbose=False)
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

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
    )
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_iter')
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_max_value')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_ecdsa_signs_options(self, mock_parse, mock_max_value, mock_iter,
                          mock_process, mock_write, mock_write_pkt, mock_log):
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
                    priv_key=priv_key, key_type="ecdsa", frequency=None,
                    hash_func=hashlib.sha256, verbose=False)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
    )
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_iter')
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_max_value')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_verbose_option(self, mock_parse, mock_max_value, mock_iter,
                          mock_process, mock_write, mock_write_pkt, mock_log):
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
                    priv_key=priv_key, key_type="ecdsa", frequency=None,
                    hash_func=hashlib.sha256, verbose=True)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
    )
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_iter')
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_max_value')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_frequency_option(self, mock_parse, mock_max_value, mock_iter,
                          mock_process, mock_write, mock_write_pkt, mock_log):
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
                    priv_key=priv_key, key_type="ecdsa",
                    frequency=frequency * 1e6, hash_func=hashlib.sha256,
                    verbose=False)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()

    @mock.patch('tlsfuzzer.extract.Log')
    @mock.patch('tlsfuzzer.extract.Extract._write_pkts')
    @mock.patch('tlsfuzzer.extract.Extract._write_csv')
    @mock.patch(
        'tlsfuzzer.extract.Extract.process_measurements_and_create_csv_file'
    )
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_iter')
    @mock.patch('tlsfuzzer.extract.Extract.ecdsa_max_value')
    @mock.patch('tlsfuzzer.extract.Extract.parse')
    def test_digest_size_option(self, mock_parse, mock_max_value, mock_iter,
                          mock_process, mock_write, mock_write_pkt, mock_log):
        output = "/tmp"
        raw_data = "/tmp/data"
        data_size = 32
        raw_sigs = "/tmp/sigs"
        raw_times = "/tmp/times"
        priv_key = "/tmp/key"
        digest_size = 384
        args = ["extract.py",
                "-o", output,
                "--raw-data", raw_data,
                "--data-size", data_size,
                "--raw-sigs", raw_sigs,
                "--raw-times", raw_times,
                "--digest-size", digest_size,
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
                    priv_key=priv_key, key_type="ecdsa",
                    frequency=None, hash_func=hashlib.sha384,
                    verbose=False)
                mock_write.assert_not_called()
                mock_write_pkt.assert_not_called()
                mock_log.assert_not_called()

@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
@unittest.skipUnless(TUPLE_RANDOMNESS_TESTS,
                 "Skipping tests for tuple creation because \
TUPLE_RANDOMNESS_TESTS env variable is not defined.")
class TestTupleCreationRandomeness(unittest.TestCase):
    def setUp(self):
        self.builtin_open = open
        self.max_value = 256
        self._measurements_file = []

        self.very_simple_runs = 1000
        self.very_simple_data = [256, 255, 256]
        self.very_simple_times = [100, 1, 101]
        self.very_simple_expected = {
            "1:100": (422,578),
            "1:101": (422,578)
        }

        self.two_non_max_before_and_two_after_runs = 2000
        self.two_non_max_before_and_two_after_data = [
            256, 255, 255, 256, 255, 255, 256
        ]
        self.two_non_max_before_and_two_after_times = [
            100, 1, 2, 101, 3, 4, 102
        ]
        self.two_non_max_before_and_two_after_expected = {
            "1:100,3:101": (28, 104),
            "2:100,3:101": (28, 104),
            "1:100,4:101": (28, 104),
            "2:100,4:101": (28, 104),
            "1:100,3:101,4:102": (75, 181),
            "2:100,3:101,4:102": (75, 181),
            "1:100,4:101,3:102": (75, 181),
            "2:100,4:101,3:102": (75, 181),
            "1:100,3:102": (8, 62),
            "2:100,3:102": (8, 62),
            "1:100,4:102": (8, 62),
            "2:100,4:102": (8, 62),
            "1:100,2:101": (28, 104),
            "1:100,2:101,4:102": (75, 181),
            "1:100,2:101,3:102": (75, 181),
            "2:100,1:101": (28, 104),
            "2:100,1:101,4:102": (75, 181),
            "2:100,1:101,3:102": (75, 181),
            "1:101": (8, 62),
            "2:101": (8, 62),
            "3:101": (8, 62),
            "4:101": (8, 62),
            "1:101,4:102": (28, 104),
            "2:101,4:102": (28, 104),
            "3:101,4:102": (28, 104),
            "1:101,3:102": (28, 104),
            "2:101,3:102": (28, 104),
            "4:101,3:102": (28, 104),
        }

        self.two_non_max_before_and_one_after_runs = 1000
        self.two_non_max_before_and_one_after_data = [
            256, 255, 255, 256, 255, 256
        ]
        self.two_non_max_before_and_one_after_times = [
            100, 1, 2, 101, 3, 102
        ]
        self.two_non_max_before_and_one_after_expected = {
            "1:100,3:101": (76, 179),
            "2:100,3:101": (76, 179),
            "1:100,3:102": (28, 103),
            "2:100,3:102": (28, 103),
            "1:100,2:101": (28, 103),
            "1:100,2:101,3:102": (76, 179),
            "2:100,1:101": (28, 103),
            "2:100,1:101,3:102": (76, 179),
            "1:101": (8, 62),
            "2:101": (8, 62),
            "3:101": (28, 103),
            "1:101,3:102": (28, 103),
            "2:101,3:102": (28, 103),
        }

        self.three_max_two_non_max_before_and_after_runs = 9000
        self.three_max_two_non_max_before_and_after_data = [
            256, 255, 255, 256, 255, 255, 256, 255, 255, 256
        ]
        self.three_max_two_non_max_before_and_after_times = [
            100, 1, 2, 101, 3, 4, 102, 5, 6, 103
        ]
        self.three_max_two_non_max_before_and_after_expected = {
            "1:100,3:101,5:102": (33, 115),
            "2:100,3:101,5:102": (33, 115),
            "1:100,4:101,5:102": (33, 115),
            "2:100,4:101,5:102": (33, 115),
            "1:100,3:101,6:102": (33, 115),
            "2:100,3:101,6:102": (33, 115),
            "1:100,4:101,6:102": (33, 115),
            "2:100,4:101,6:102": (33, 115),
            "1:100,3:101,5:102,6:103": (86, 202),
            "2:100,3:101,5:102,6:103": (86, 202),
            "1:100,4:101,5:102,6:103": (86, 202),
            "2:100,4:101,5:102,6:103": (86, 202),
            "1:100,3:101,6:102,5:103": (86, 202),
            "2:100,3:101,6:102,5:103": (86, 202),
            "1:100,4:101,6:102,5:103": (86, 202),
            "2:100,4:101,6:102,5:103": (86, 202),
            "1:100,3:101,5:103": (10, 68),
            "2:100,3:101,5:103": (10, 68),
            "1:100,4:101,5:103": (10, 68),
            "2:100,4:101,5:103": (10, 68),
            "1:100,3:101,6:103": (10, 68),
            "2:100,3:101,6:103": (10, 68),
            "1:100,4:101,6:103": (10, 68),
            "2:100,4:101,6:103": (10, 68),
            "1:100,3:101,4:102": (33, 115),
            "2:100,3:101,4:102": (33, 115),
            "1:100,3:101,4:102,6:103": (86, 202),
            "2:100,3:101,4:102,6:103": (86, 202),
            "1:100,3:101,4:102,5:103": (86, 202),
            "2:100,3:101,4:102,5:103": (86, 202),
            "1:100,4:101,3:102": (33, 115),
            "2:100,4:101,3:102": (33, 115),
            "1:100,4:101,3:102,6:103": (86, 202),
            "2:100,4:101,3:102,6:103": (86, 202),
            "1:100,4:101,3:102,5:103": (86, 202),
            "2:100,4:101,3:102,5:103": (86, 202),
            "1:100,3:102": (1, 42),
            "2:100,3:102": (1, 42),
            "1:100,4:102": (1, 42),
            "2:100,4:102": (1, 42),
            "1:100,5:102": (1, 42),
            "2:100,5:102": (1, 42),
            "1:100,6:102": (1, 42),
            "2:100,6:102": (1, 42),
            "1:100,3:102,6:103": (10, 68),
            "2:100,3:102,6:103": (10, 68),
            "1:100,4:102,6:103": (10, 68),
            "2:100,4:102,6:103": (10, 68),
            "1:100,5:102,6:103": (10, 68),
            "2:100,5:102,6:103": (10, 68),
            "1:100,3:102,5:103": (10, 68),
            "2:100,3:102,5:103": (10, 68),
            "1:100,4:102,5:103": (10, 68),
            "2:100,4:102,5:103": (10, 68),
            "1:100,6:102,5:103": (10, 68),
            "2:100,6:102,5:103": (10, 68),
            "1:100,2:101,5:102": (59, 159),
            "1:100,2:101,6:102": (59, 159),
            "1:100,2:101,5:102,6:103": (144, 285),
            "1:100,2:101,6:102,5:103": (144, 285),
            "1:100,2:101,5:103": (10, 68),
            "1:100,2:101,6:103": (10, 68),
            "1:100,2:101,4:102": (33, 115),
            "1:100,2:101,4:102,6:103": (86, 202),
            "1:100,2:101,4:102,5:103": (86, 202),
            "1:100,2:101,3:102": (33, 115),
            "1:100,2:101,3:102,6:103": (86, 202),
            "1:100,2:101,3:102,5:103": (86, 202),
            "2:100,1:101,5:102": (59, 159),
            "2:100,1:101,6:102": (59, 159),
            "2:100,1:101,5:102,6:103": (144, 285),
            "2:100,1:101,6:102,5:103": (144, 285),
            "2:100,1:101,5:103": (10, 68),
            "2:100,1:101,6:103": (10, 68),
            "2:100,1:101,4:102": (33, 115),
            "2:100,1:101,4:102,6:103": (86, 202),
            "2:100,1:101,4:102,5:103": (86, 202),
            "2:100,1:101,3:102": (33, 115),
            "2:100,1:101,3:102,6:103": (86, 202),
            "2:100,1:101,3:102,5:103": (86, 202),
            "1:101,5:102": (21, 92),
            "2:101,5:102": (21, 92),
            "3:101,5:102": (10, 68),
            "4:101,5:102": (10, 68),
            "1:101,6:102": (21, 92),
            "2:101,6:102": (21, 92),
            "3:101,6:102": (10, 68),
            "4:101,6:102": (10, 68),
            "1:101,5:102,6:103": (59, 159),
            "2:101,5:102,6:103": (59, 159),
            "3:101,5:102,6:103": (33, 115),
            "4:101,5:102,6:103": (33, 115),
            "1:101,6:102,5:103": (59, 159),
            "2:101,6:102,5:103": (59, 159),
            "3:101,6:102,5:103": (33, 115),
            "4:101,6:102,5:103": (33, 115),
            "1:101,5:103": (1, 42),
            "2:101,5:103": (1, 42),
            "3:101,5:103": (1, 42),
            "4:101,5:103": (1, 42),
            "1:101,6:103": (1, 42),
            "2:101,6:103": (1, 42),
            "3:101,6:103": (1, 42),
            "4:101,6:103": (1, 42),
            "1:101,4:102": (10, 68),
            "2:101,4:102": (10, 68),
            "3:101,4:102": (10, 68),
            "1:101,4:102,6:103": (33, 115),
            "2:101,4:102,6:103": (33, 115),
            "3:101,4:102,6:103": (33, 115),
            "1:101,4:102,5:103": (33, 115),
            "2:101,4:102,5:103": (33, 115),
            "3:101,4:102,5:103": (33, 115),
            "1:101,3:102": (10, 68),
            "2:101,3:102": (10, 68),
            "4:101,3:102": (10, 68),
            "1:101,3:102,6:103": (33, 115),
            "2:101,3:102,6:103": (33, 115),
            "4:101,3:102,6:103": (33, 115),
            "1:101,3:102,5:103": (33, 115),
            "2:101,3:102,5:103": (33, 115),
            "4:101,3:102,5:103": (33, 115)
        }

        self.diff_size_non_max_runs = 2000
        self.diff_size_non_max_data = [
            256, 255, 254, 256, 255, 254, 256
        ]
        self.diff_size_non_max_times = [
            100, 1, 10, 101, 2, 20, 102
        ]
        self.diff_size_non_max_expected = {
            "1:100,10:100,2:101,20:101": (75, 181),
            "1:100,10:100,2:101,20:102": (75, 181),
            "1:100,10:100,20:101,2:102": (75, 181),
            "1:100,10:100,2:102,20:102": (75, 181),
            "1:100,2:101,10:101": (28, 104),
            "1:100,2:101,20:101": (28, 104),
            "1:100,2:101,10:101,20:102": (75, 181),
            "1:100,10:101,2:102": (28, 104),
            "1:100,20:101,2:102": (28, 104),
            "1:100,10:101,2:102,20:102": (75, 181),
            "10:100,1:101,20:101": (28, 104),
            "10:100,2:101,20:101": (28, 104),
            "10:100,1:101,20:102": (28, 104),
            "10:100,2:101,20:102": (28, 104),
            "10:100,1:101,20:101,2:102": (75, 181),
            "10:100,1:101,2:102,20:102": (75, 181),
            "1:101,10:101": (8, 62),
            "1:101,20:101": (8, 62),
            "2:101,10:101": (8, 62),
            "2:101,20:101": (8, 62),
            "1:101,10:101,20:102": (28, 104),
            "2:101,10:101,20:102": (28, 104),
            "1:101,10:101,2:102": (28, 104),
            "1:101,20:101,2:102": (28, 104),
            "1:101,10:101,2:102,20:102": (75, 181)
        }

    def custom_generator(self, data):
        for item in data:
            yield item

    def file_emulator(self, *args, **kwargs):
        name = args[0]
        mode = args[1]
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
