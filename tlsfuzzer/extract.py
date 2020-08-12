# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Extraction and analysis of timing information from a packet capture."""

from __future__ import print_function

import getopt
import sys
import csv
from os.path import join
from collections import defaultdict
from socket import inet_aton, gethostbyname, gaierror, error

import dpkt

from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.statics import WARM_UP
from tlsfuzzer.utils.lists import natural_sort_keys


def help_msg():
    """Print help message."""
    print("Usage: extract [-l logfile] [-c capture] [[-o output] ...]")
    print(" -l logfile     Filename of the timing log (required)")
    print(" -c capture     Packet capture of the test run")
    print(" -o output      Directory where to place results (required)")
    print(" -h host        TLS server host or ip")
    print(" -p port        TLS server port")
    print(" --raw-times FILE Read the timings from an external file, not")
    print("                the packet capture")
    print(" --help         Display this message")
    print("")
    print("When extracting data from a capture file, specifying the capture")
    print("file, host and port is necessary.")
    print("When using the external timing source, only it, and the always")
    print("required options: logfile and output dir are necessary.")


def main():
    """Process arguments and start extraction."""
    logfile = None
    capture = None
    output = None
    ip_address = None
    port = None
    raw_times = None


    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "l:c:h:p:o:t:", ["help", "raw-times="])
    for opt, arg in opts:
        if opt == '-l':
            logfile = arg
        elif opt == '-c':
            capture = arg
        elif opt == '-o':
            output = arg
        elif opt == '-h':
            ip_address = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == "--raw-times":
            raw_times = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)

    if raw_times and capture:
        raise ValueError(
            "Can't specify both a capture file and external timing log")

    if not all([logfile, output]):
        raise ValueError(
            "Specifying logfile and output is mandatory")

    if capture and not all([logfile, output, ip_address, port]):
        raise ValueError("Some arguments are missing!")

    log = Log(logfile)
    log.read_log()
    analysis = Extract(log, capture, output, ip_address, port, raw_times)
    analysis.parse()
    analysis.write_csv('timing.csv')


class Extract:
    """Extract timing information from packet capture."""

    def __init__(self, log, capture=None, output=None, ip_address=None,
                 port=None, raw_times=None):
        """
        Initialises instance and sets up class name generator from log.

        :param Log log: Log class instance
        :param str capture: Packet capture filename
        :param str output: Directory where to output results
        :param str ip_address: TLS server ip address
        :param int port: TLS server port
        """
        self.capture = capture
        self.output = output
        self.ip_address = ip_address and self.hostname_to_ip(ip_address)
        self.port = port
        self.timings = defaultdict(list)
        self.client_message = None
        self.server_message = None
        self.warm_up_messages_left = WARM_UP
        self.raw_times = raw_times

        # set up class names generator
        self.log = log
        self.class_generator = log.iterate_log()
        self.class_names = log.get_classes()

    def parse(self):
        """
        Extract timing information from capture file
        and associate it with class from log file.
        """
        if self.capture:
            return self._parse_pcap()
        return self._parse_raw_times()

    def _parse_raw_times(self):
        """Classify already extracted times."""
        # as unlike with capture file, we don't know how many sanity tests,
        # manual checks, etc. were performed to the server before the
        # timing tests were started, we don't know how many measurements to
        # skip. Count the probes, the times, and then use the last len(probes)
        # of times for classification

        # do counting in memory efficient way
        probe_count = sum(1 for _ in self.class_generator)
        self.log.read_log()
        self.class_generator = self.log.iterate_log()
        with open(self.raw_times, 'r') as raw_times:
            # skip the header line
            raw_times.readline()
            times_count = 0
            for times_count, _ in enumerate(raw_times, 1):
                pass
        if probe_count > times_count:
            raise ValueError(
                "Insufficient number of times for provided log file")

        self.warm_up_messages_left = times_count - probe_count

        with open(self.raw_times, 'r') as raw_times:
            # skip the header line
            raw_times.readline()

            for _ in range(self.warm_up_messages_left):
                raw_times.readline()

            for line in raw_times:
                class_index = next(self.class_generator)
                class_name = self.class_names[class_index]
                self.timings[class_name].append(line.strip())

    def _parse_pcap(self):
        """Process capture file."""
        with open(self.capture, 'rb') as pcap:
            capture = dpkt.pcap.Reader(pcap)

            for timestamp, pkt in capture:
                link_packet = dpkt.ethernet.Ethernet(pkt)
                ip_pkt = link_packet.data
                tcp_pkt = ip_pkt.data

                if tcp_pkt.data:
                    if (tcp_pkt.sport == self.port and
                            ip_pkt.src == self.ip_address):
                        # message from the server
                        self.server_message = timestamp
                    else:
                        # message from the client
                        self.client_message = timestamp
                if (tcp_pkt.flags & 0x02) != 0:
                    # a SYN packet was found - new connection
                    self.add_timing()

                    # reset timestamps
                    self.server_message = None
                    self.client_message = None
            # deal with the last connection
            self.add_timing()

    def add_timing(self):
        """Associate the timing information with its class"""
        if self.client_message and self.server_message:
            if self.warm_up_messages_left == 0:
                class_index = next(self.class_generator)
                class_name = self.class_names[class_index]
                time_diff = abs(self.server_message - self.client_message)
                self.timings[class_name].append(time_diff)
            else:
                self.warm_up_messages_left -= 1

    def write_csv(self, filename):
        """
        Write timing information into a csv file. Each row starts with a class
        name and the rest of the row are individual timing measurements.

        :param str filename: Target filename
        """
        filename = join(self.output, filename)
        with open(filename, 'w') as csvfile:
            print("Writing to {0}".format(filename))
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            class_names = sorted(self.timings, key=natural_sort_keys)
            writer.writerow(class_names)
            for values in zip(*[self.timings[i] for i in class_names]):
                writer.writerow(values)

    @staticmethod
    def hostname_to_ip(hostname):
        """
        Converts hostname to IPv4 address, if needed.
        :param str hostname: hostname or an IPv4 address
        :return: str IPv4 address
        """
        # first check if it is not already IPv4
        try:
            ip = inet_aton(hostname)
            return ip
        except error:
            pass

        # not an IPv4, try a hostname
        try:
            ip = gethostbyname(hostname)
            return inet_aton(ip)
        except gaierror:
            raise Exception("Hostname is not an IPv4 or a reachable hostname")


if __name__ == '__main__':
    main()
