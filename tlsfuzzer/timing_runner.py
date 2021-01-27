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
from threading import Thread
from itertools import chain, repeat

from tlsfuzzer.utils.log import Log
from tlsfuzzer.runner import Runner
from tlsfuzzer.utils.statics import WARM_UP


class TimingRunner:
    """Repeatedly runs tests and captures timing information."""

    def __init__(self, name, tests, out_dir, ip_address, port, interface,
                 affinity=None):
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

        self.tcpdump_running = True

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

    @staticmethod
    def _format_seconds(sec):
        """Format number of seconds into a more readable string."""
        elems = []
        msec, sec = math.modf(sec)
        sec = int(sec)
        days, rem = divmod(sec, 60*60*24)
        if days:
            elems.append("{0}d".format(days))
        hours, rem = divmod(rem, 60*60)
        if hours or elems:
            elems.append("{0}h".format(hours))
        minutes, sec = divmod(rem, 60)
        if minutes or elems:
            elems.append("{0}m".format(minutes))
        elems.append("{0:.2f}s".format(sec+msec))
        return " ".join(elems)

    @staticmethod
    def _report_progress(status):  # pragma: no cover
        """
        Periodically report progress of task in status, thread runner.

        status must be an array with three elements, first two specify a
        fraction of completed work (i.e. 0 <= status[0]/status[1] <= 1),
        third specifies if the reporting process should continue running, a
        False value there will cause the process to finish
        """
        # technically that should be time.monotonic(), but it's not supported
        # on python2.7
        start_exec = time.time()
        delay = 2.0
        while status[2]:
            old_exec = status[0]
            time.sleep(delay)
            elapsed = time.time()-start_exec
            elapsed_str = TimingRunner._format_seconds(elapsed)
            done = status[0]*100.0/status[1]
            remaining = (100-done)*elapsed/done
            remaining_str = TimingRunner._format_seconds(remaining)
            eta = time.strftime("%H:%M:%S %d-%m-%Y",
                                time.localtime(time.time()+remaining))
            print("Done: {0:6.2f}%, elapsed: {1}, speed: {2:.2f}conn/s, "
                  "avg speed: {3:.2f}conn/s, remaining: {4}, ETA: {5}{6}"
                  .format(
                      done, elapsed_str,
                      (status[0] - old_exec)/delay,
                      status[0]/elapsed,
                      remaining_str,
                      eta,
                      " " * 4), end="\r")

    def run(self):
        """
        Run test the specified number of times and start analysis

        :return: int 0 for no difference, 1 for difference, 2 if unavailable
        """
        sniffer = self.sniff()
        status = Thread(target=self.tcpdump_status, args=(sniffer,))
        status.setDaemon(True)
        status.start()

        try:
            # run the conversations
            test_classes = self.log.get_classes()
            # prepend the conversations with few warm-up ones
            exp_len = WARM_UP + sum(1 for _ in self.log.iterate_log())
            status = [0, exp_len, True]
            progress = Thread(target=self._report_progress, args=(status,))
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
            status[2] = False
            time.sleep(2)
            sniffer.terminate()
            sniffer.wait()
            progress.join()

        # start extraction and analysis
        print("Starting extraction...")
        if self.extract():
            print("Starting analysis...")
            return self.analyse()
        return 2

    def extract(self):
        """Starts the extraction if available."""
        if self.check_extraction_availability():
            from tlsfuzzer.extract import Extract
            self.log.read_log()
            extraction = Extract(self.log,
                                 os.path.join(self.out_dir, "capture.pcap"),
                                 self.out_dir,
                                 self.ip_address,
                                 self.port)
            extraction.parse()
            extraction.write_csv(os.path.join(self.out_dir, "timing.csv"))
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
            analysis = Analysis(self.out_dir)
            return analysis.generate_report()

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
                 '--time-stamp-precision', 'nano']

        output_file = os.path.join(self.out_dir, "capture.pcap")
        cmd = []
        if self.affinity:
            cmd += ['taskset', '--cpu-list', self.affinity]
        cmd += ['tcpdump', packet_filter, '-w', output_file] + flags
        process = subprocess.Popen(cmd, stderr=subprocess.PIPE)

        # detect when tcpdump starts capturing
        self.tcpdump_running = False
        for row in iter(process.stderr.readline, b''):
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
        if self.tcpdump_running:
            self.tcpdump_running = False
            print("tcpdump unexpectedly exited with return code {0}"
                  .format(process.returncode))
            if stderr:
                print(stderr.decode())

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
        test_name = os.path.basename(name)
        out_dir = os.path.join(os.path.abspath(self.out_dir),
                               "{0}_{1}".format(test_name, int(time.time())))
        os.mkdir(out_dir)
        return out_dir
