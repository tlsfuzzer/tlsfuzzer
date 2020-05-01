# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Tooling for running tests repeatedly"""

from __future__ import print_function
import traceback
import os
import time
import subprocess
from itertools import cycle

from tlsfuzzer.analysis import Analysis
from tlsfuzzer.runner import Runner


class TimingRunner:
    """Contains tools to repeatedly run tests in order to capture timing information."""

    def __init__(self, log, out_dir, ip_address, port, interface):
        """
        Check if tcpdump is present and setup instance parameters.

        :param Log log: Log class with filled log from normal test run
        :param str out_dir: Directory where results should be stored
        :param str ip_address: Server IP address
        :param int port: Server port
        :param str interface: Network interface to run tcpdump on
        """
        # first check tcpdump presence
        if not self.check_tcpdump():
            raise FileNotFoundError("Could not find tcpdump, aborting timing tests")

        self.out_dir = out_dir
        self.ip_address = ip_address
        self.port = port
        self.interface = interface
        self.log = log

    def run(self, sampled_tests, run_only, run_exclude, repetitions):
        """
        Run test the specified number of times and start analysis

        :param list sampled_tests: List of test tuples (name, conversation) to be run
        :param list run_only: List of tests to be run exclusively
        :param list run_exclude: List of tests to exclude
        :param int repetitions: How many times to repeat each test
        """

        # set up tcpdump
        if os.geteuid() != 0:
            print('Please run this test with root privileges,'
                  'as it requires packet capturing to work.')
            raise SystemExit

        sniffer = self.sniff()
        # sleep for a second to give tcpdump time to start capturing
        time.sleep(2)

        conversations_len = len(sampled_tests)

        # run the conversations
        i = 1
        for c_name, c_test in cycle(sampled_tests):
            if run_only and c_name not in run_only or c_name in run_exclude:
                continue
            if i % conversations_len == 0:
                print("run {0} ...".format(i // conversations_len))

            runner = Runner(c_test)
            res = True
            try:
                runner.run()
            except Exception:
                print("Error while processing")
                print(traceback.format_exc())
                res = False

            if not res:
                raise AssertionError("Test must pass in order to be timed")

            if i >= repetitions * conversations_len:
                break
            i += 1

        # stop sniffing and give tcpdump time to write all buffered packets
        time.sleep(2)
        sniffer.terminate()
        sniffer.wait()

        # start analysis
        analysis = Analysis(self.log.filename,
                            os.path.join(self.out_dir, "capture.pcap"),
                            self.ip_address,
                            self.port)
        analysis.parse()
        analysis.write_csv(os.path.join(self.out_dir, "timing.csv"))

    def sniff(self):
        """Start tcpdump sniffing with filter specifying communication to/from server"""
        packet_filter = "host {0} and port {1} and tcp".format(self.ip_address, self.port)
        flags = ['-i', self.interface, '-U', '-nn', '--time-stamp-precision', 'nano']
        output_file = os.path.join(self.out_dir, "capture.pcap")
        return subprocess.Popen(['tcpdump', packet_filter, '-w', output_file] + flags)

    @staticmethod
    def check_tcpdump():
        """
        Checks if tcpdump is installed.

        :return: boolean value indicating if tcpdump is present
        """
        try:
            subprocess.check_call(['tcpdump', '--version'])
        except subprocess.CalledProcessError:
            return False
        return True

    @staticmethod
    def create_output_directory(path, name):
        """
        Creates a new directory in the specified path to store results in.

        :param str path: Path where the directory should be created
        :param str name: Name of the test being run
        :return: str Path to newly created directory
        """
        test_name = os.path.basename(name)
        out_dir = os.path.join(os.path.abspath(path), "{0}_{1}".format(test_name, int(time.time())))
        os.mkdir(out_dir)
        return out_dir
