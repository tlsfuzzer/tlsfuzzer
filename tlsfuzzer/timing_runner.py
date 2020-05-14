# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Tooling for running tests repeatedly"""

from __future__ import print_function
import traceback
import os
import time
import subprocess
import sys

from tlsfuzzer.utils.log import Log
from tlsfuzzer.runner import Runner


class TimingRunner:
    """Repeatedly runs tests and captures timing information."""

    def __init__(self, name, tests, out_dir, ip_address, port, interface):
        """
        Check if tcpdump is present and setup instance parameters.

        :param str name: Test name
        :param list tests: List of test tuples (name, conversation) to be run
        :param str out_dir: Directory where results should be stored
        :param str ip_address: Server IP address
        :param int port: Server port
        :param str interface: Network interface to run tcpdump on
        """
        # first check tcpdump presence
        if not self.check_tcpdump():
            raise FileNotFoundError(
                "Could not find tcpdump, aborting timing tests")

        self.tests = tests
        self.out_dir = out_dir
        self.out_dir = self.create_output_directory(name)
        self.ip_address = ip_address
        self.port = port
        self.interface = interface
        self.log = Log(os.path.join(self.out_dir, "class.log"))

    def generate_log(self, run_only, run_exclude, repetitions):
        """
        Creates log with number of requested shuffled runs.
        :param set run_only: List of tests to be run exclusively
        :param set run_exclude: List of tests to exclude
        :param int repetitions: How many times to repeat each test
        """

        # first filter out what is really going to be run
        actual_tests = []
        test_dict = {}
        for c_name, c_test in self.tests:
            if run_only and c_name not in run_only or c_name in run_exclude:
                continue
            if c_name != "sanity":
                actual_tests.append(c_name)
                # also convert internal test structure to dict for lookup
                test_dict[c_name] = c_test
        self.tests = test_dict
        self.log.start_log(actual_tests)

        # generate requested number of random order test runs
        for _ in range(0, repetitions):
            self.log.shuffle_new_run()

        self.log.write()

    def run(self):
        """
        Run test the specified number of times and start analysis
        """
        sniffer = self.sniff()

        # run the conversations
        test_classes = self.log.get_classes()
        print("Starting timing info collection. This might take a while...")
        for index in self.log.iterate_log():
            c_name = test_classes[index]
            c_test = self.tests[c_name]

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

        # stop sniffing and give tcpdump time to write all buffered packets
        time.sleep(2)
        sniffer.terminate()
        sniffer.wait()

        # start analysis
        self.start_analysis()

    def start_analysis(self):
        """Starts the analysis if available."""
        if self.check_availability():
            from tlsfuzzer.analysis import Analysis
            self.log.read_log()
            analysis = Analysis(self.log,
                                os.path.join(self.out_dir, "capture.pcap"),
                                self.ip_address,
                                self.port)
            analysis.parse()
            analysis.write_csv(os.path.join(self.out_dir, "timing.csv"))
        else:
            print("Analysis is not available."
                  "Install required packages to enable.")
            print("Exiting.")
            sys.exit(0)

    def sniff(self):
        """Start tcpdump with filter on communication to/from server"""

        # check privileges for tcpdump to work
        if os.geteuid() != 0:
            print('WARNING: Timing tests should run with root privileges,'
                  'as it improves accuracy and might be needed for tcpdump.')

        packet_filter = "host {0} and port {1} and tcp".format(self.ip_address,
                                                               self.port)
        flags = ['-i', self.interface,
                 '-s', '0',
                 '--time-stamp-precision', 'nano']

        output_file = os.path.join(self.out_dir, "capture.pcap")
        cmd = ['tcpdump', packet_filter, '-w', output_file] + flags
        process = subprocess.Popen(cmd, stderr=subprocess.PIPE)

        # detect when tcpdump starts capturing
        for row in iter(process.stderr.readline, b''):
            line = row.rstrip()
            if 'listening' in line.decode():
                # tcpdump is ready
                print("tcpdump ready...")
                break
        return process

    @staticmethod
    def check_tcpdump():
        """
        Checks if tcpdump is installed.

        :return: boolean value indicating if tcpdump is present
        """
        try:
            subprocess.check_call(['tcpdump', '--version'],
                                  stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            return False
        return True

    @staticmethod
    def check_availability():
        """
        Checks if additional packages are installed so analysis can run.

        :return: bool Indicating if it is okay to run
        """
        try:
            from tlsfuzzer.analysis import Analysis
        except ImportError:
            return False
        return True

    def create_output_directory(self, name):
        """
        Creates a new directory in the specified path to store results in.

        :param str name: Name of the test being run
        :return: str Path to newly created directory
        """
        test_name = os.path.basename(name)
        out_dir = os.path.join(os.path.abspath(self.out_dir),
                               "{0}_{1}".format(test_name, int(time.time())))
        os.mkdir(out_dir)
        return out_dir
