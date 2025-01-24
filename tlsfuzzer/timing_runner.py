# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Tooling for running tests repeatedly"""

from __future__ import print_function
import traceback
import os
import time
import subprocess
import sys
import math
from threading import Thread, Event
from itertools import chain, repeat

from tlsfuzzer.utils.log import Log
from tlsfuzzer.runner import Runner
from tlsfuzzer.utils.statics import WARM_UP
from tlsfuzzer.utils.progress_report import progress_report


class TimingRunner:
    """Repeatedly runs tests and captures timing information."""

    def __init__(self, name, tests, out_dir, ip_address, port, interface,
                 affinity=None, skip_extract=False, skip_analysis=False,
                 alpha=None, no_quickack=False, verbose_analysis=False,
                 delay=None, carriage_return=None, summary_only=False):
        """
        Check if tcpdump is present and setup instance parameters.

        :param str name: Test name
        :param list tests: List of test tuples (name, conversation) to be run
        :param str out_dir: Directory where results should be stored
        :param str ip_address: Server IP address
        :param int port: Server port
        :param str interface: Network interface to run tcpdump on
        :param str affinity: The processor IDs to use for affinity of
            the `tcpdump` process. See taskset man page for description
            of --cpu-list option.
        :param bool no_quickack: If True: don't assume QUICKACK to be in use,
            impacts extraction from packet dump.
        :param bool verbose_analysis: If True: run analysis with verbose flag
            set.
        :param float delay: How often to print progress information, in
            seconds.
        :param str carriage_return: What character to use for carriage_return.
        """
        # first check tcpdump presence
        if not self.check_tcpdump():
            raise Exception("Could not find tcpdump, aborting timing tests")

        self.tests = tests
        self.out_dir = out_dir
        self.out_dir = self.create_output_directory(name)
        self.ip_address = ip_address
        self.port = port
        self.interface = interface
        self.log = Log(os.path.join(self.out_dir, "log.csv"))
        self.affinity = affinity
        self.skip_extract = skip_extract
        self.skip_analysis = skip_analysis
        self.alpha = alpha
        self.no_quickack = no_quickack
        self.verbose_analysis = verbose_analysis
        self.delay = delay
        self.carriage_return = carriage_return
        self.summary_only = summary_only

        self.tcpdump_running = True
        self.tcpdump_output = None

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
            if not c_name.startswith("sanity"):
                actual_tests.append(c_name)
                # also convert internal test structure to dict for lookup
                test_dict[c_name] = c_test
        self.tests = test_dict
        self.log.start_log(actual_tests)

        # generate requested number of random order test runs
        for _ in range(repetitions):
            self.log.shuffle_new_run()

        self.log.write()

    def run(self):
        """
        Run test the specified number of times and start analysis

        :return: int 0 for no difference, 1 for difference, 2 if unavailable
        """
        sniffer = self.sniff()
        status_th = Thread(target=self.tcpdump_status, args=(sniffer,))
        status_th.start()

        try:
            # run the conversations
            test_classes = self.log.get_classes()
            # prepend the conversations with few warm-up ones
            exp_len = WARM_UP + sum(1 for _ in self.log.iterate_log())
            status = [0, exp_len, Event()]

            kwargs = {}
            kwargs['unit'] = ' conn'
            kwargs['delay'] = self.delay
            kwargs['end'] = self.carriage_return
            progress = Thread(target=progress_report, args=(status,),
                              kwargs=kwargs)
            progress.start()
            self.log.read_log()
            queries = chain(repeat(0, WARM_UP), self.log.iterate_log())
            print("Starting timing info collection. "
                  "This might take a while...")
            for executed, index in enumerate(queries):
                status[0] = executed
                if self.tcpdump_running:
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
                        raise AssertionError(
                            "Test must pass in order to be timed")
                else:
                    sys.exit(1)
        finally:
            # stop sniffing and give tcpdump time to write all buffered packets
            self.tcpdump_running = False
            status[2].set()
            time.sleep(2)
            sniffer.terminate()
            sniffer.wait()
            progress.join()
            status_th.join()
            print()
            print(self.tcpdump_output)
            if "0 packets dropped by kernel" not in \
                    self.tcpdump_output.split('\n'):
                raise ValueError("Incomplete packet capture. Aborting. "
                    "Try reducing disk load or capture to a RAM disk")

        # start extraction and analysis
        if self.skip_extract:
            return 0
        print("Starting extraction...")
        if self.extract():
            if not self.skip_analysis:
                print("Starting analysis...")
                return self.analyse()
        return 2

    def extract(self, fin_as_resp=False):
        """Starts the extraction if available."""
        if self.check_extraction_availability():
            from tlsfuzzer.extract import Extract
            self.log.read_log()
            extraction = Extract(self.log,
                                 os.path.join(self.out_dir, "capture.pcap"),
                                 self.out_dir,
                                 self.ip_address,
                                 self.port,
                                 no_quickack=self.no_quickack,
                                 delay=self.delay,
                                 carriage_return=self.carriage_return,
                                 fin_as_resp=fin_as_resp)
            extraction.parse()
            return True

        print("Extraction is not available. "
              "Install required packages to enable.")
        return False

    def analyse(self):
        """
        Starts analysis if available

        :return: int 0 for no difference, 1 for difference, 2 unavailable
        """
        if self.check_analysis_availability():
            from tlsfuzzer.analysis import Analysis
            analysis = Analysis(self.out_dir, alpha=self.alpha,
                                verbose=self.verbose_analysis,
                                delay=self.delay,
                                carriage_return=self.carriage_return,
                                summary_only=self.summary_only)
            return analysis.generate_report()

        print("Analysis is not available. "
              "Install required packages to enable.")
        return 2

    def analyse_bit_sizes(self):
        """
        Starts analysis if available

        :return: int 0 for no side channel detected, 1 for side channel
        detected, 2 unavailable
        """
        if self.check_analysis_availability():
            from tlsfuzzer.analysis import Analysis
            analysis = Analysis(self.out_dir, alpha=self.alpha,
                                verbose=self.verbose_analysis,
                                bit_size_analysis=True)
            return analysis.analyze_bit_sizes()

        print("Analysis is not available. "
              "Install required packages to enable.")
        return 2

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
                 '--time-stamp-precision', 'nano',
                 '--buffer-size=102400']  # units are KiB

        output_file = os.path.join(self.out_dir, "capture.pcap")
        cmd = []
        if self.affinity:
            cmd += ['taskset', '--cpu-list', self.affinity]
        cmd += ['tcpdump', packet_filter, '-w', output_file] + flags
        process = subprocess.Popen(cmd, stderr=subprocess.PIPE)

        # detect when tcpdump starts capturing
        self.tcpdump_running = False
        for row in iter(process.stderr.readline, b''):
            print(row.decode())
            line = row.rstrip()
            if 'listening' in line.decode():
                # tcpdump is ready
                print("tcpdump ready...")
                self.tcpdump_running = True
                break
        if not self.tcpdump_running:
            print('tcpdump could not be started.'
                  ' Do you have the correct permissions?')
            sys.exit(1)
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
            # --version is not supported on RHEL-6 version of tcpdump
            # so actually try to do a packet capture to check if we can run it
            try:
                subprocess.check_call(['tcpdump', '-c', '1'],
                                      stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                return False
        return True

    def tcpdump_status(self, process):
        """
        Checks if tcpdump is running. Intended to be run as a separate thread.

        :param Popen process: A process with running tcpdump attached
        """
        _, stderr = process.communicate()
        self.tcpdump_output = stderr.decode()
        if self.tcpdump_running:
            print("tcpdump unexpectedly exited with return code {0}"
                  .format(process.returncode))
            self.tcpdump_running = False

    @staticmethod
    def check_extraction_availability():
        """
        Checks if additional packages are installed so extraction can run.

        :return: bool Indicating if it is okay to run
        """
        try:
            from tlsfuzzer.extract import Extract
        except ImportError:
            return False
        return True

    @staticmethod
    def check_analysis_availability():
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
        if sys.version_info >= (3, 0):
            exc = FileExistsError
        else:
            exc = OSError

        while True:
            test_name = os.path.basename(name)
            out_dir = os.path.join(os.path.abspath(self.out_dir),
                                   "{0}_{1}".format(
                                       test_name,
                                       int(time.time())))
            try:
                os.mkdir(out_dir)
            except exc:
                continue
            break
        return out_dir
