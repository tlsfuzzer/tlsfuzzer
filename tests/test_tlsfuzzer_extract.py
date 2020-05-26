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
    from tlsfuzzer.extract import Extract, main
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
        self.logfile = "test.log"
        log_content = "A,B\n1,0\n0,1\n1,0\n0,1\n0,1\n0,1\n0,1\n1,0\n1,0\n1,0\n"
        self.expected = (
            "B,0.000747009,0.000920462,0.001327954,0.000904547,0.000768453,"
            "0.000752226,0.000862102,0.000706491,0.000668237,0.000992733\n"
            "A,0.000758130,0.000696718,0.000980080,0.000988899,0.000875510,"
            "0.000734843,0.000754852,0.000667378,0.000671230,0.000790935\n")
        # fix mock not supporting iterators
        self.mock_log = mock.mock_open(read_data=log_content)
        self.mock_log.return_value.__iter__ = lambda s: iter(s.readline, '')

        with mock.patch('__main__.__builtins__.open', self.mock_log):
            self.log = Log(self.logfile)
            self.log.read_log()

    def test_extraction(self):
        extract = Extract(self.log, join(dirname(abspath(__file__)), "capture.pcap"), "/tmp", "localhost", 4433)
        extract.parse()

        with mock.patch('__main__.__builtins__.open', mock.mock_open()) as mock_file:
            mock_file.return_value.write.side_effect = lambda s: self.assertTrue(
                s.strip() in self.expected.splitlines())
            extract.write_csv('timing.csv')


@unittest.skipIf(failed_import,
                 "Could not import extraction. Skipping related tests.")
class TestCommandLine(unittest.TestCase):
    def test_command_line(self):
        capture = "capture.pcap"
        logfile = "log.csv"
        host = "localhost"
        port = "4433"
        output = "/tmp"
        sys.argv = ["extract.py",
                    "-l", logfile,
                    "-c", capture,
                    "-h", host,
                    "-p", port,
                    "-o", output]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.extract.Extract.parse'):
            with mock.patch('tlsfuzzer.extract.Extract.__init__', mock_init):
                with mock.patch('tlsfuzzer.extract.Extract.write_csv'):
                    with mock.patch('tlsfuzzer.extract.Log') as mock_log:
                        main()
                        mock_log.assert_called_once_with(logfile)
                        mock_init.assert_called_once_with(mock.ANY, capture, output, host, int(port))

    def test_help(self):
        sys.argv = ["extract.py", "--help"]
        with mock.patch('tlsfuzzer.extract.help_msg') as help_mock:
            self.assertRaises(SystemExit, main)
            help_mock.assert_called_once()
