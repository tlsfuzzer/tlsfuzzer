# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Extraction and analysis of timing information from a packet capture."""

import getopt
import sys
import csv
from os.path import join
from collections import defaultdict
from socket import inet_aton, gethostbyname, gaierror, error

import dpkt
from tlsfuzzer.utils.log import Log

WARM_UP = 250


def help_msg():
    """Print help message."""
    print("Usage: analysis [-l logfile] [-c capture] [[-o output] ...]")
    print(" -l logfile     Filename of the timing log (required)")
    print(" -c capture     Packet capture of the test run (required)")
    print(" -o output      Directory where to place results (required)")
    print(" -h host        TLS server host or ip (required)")
    print(" -p port        TLS server port (required)")


def main():
    """Process arguments and start extraction."""
    logfile = None
    capture = None
    output = None
    ip_address = None
    port = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "l:c:h:p:o:", ["help"])
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
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if not all([logfile, capture, output, ip_address, port]):
        raise ValueError("All arguments need to be entered!")

    log = Log(logfile)
    log.read_log()
    analysis = Analysis(log, capture, ip_address, port)
    analysis.parse()
    analysis.write_csv(join(output, 'timing.csv'))


class Analysis:
    """
    Extract and analyse timing information from packet capture.
    """

    def __init__(self, log, capture, ip_address, port):
        """
        Initialises instance and sets up class name generator from log.

        :param Log log: Log class instance
        :param str capture: Packet capture filename
        :param str ip_address: TLS server ip address
        :param int port: TLS server port
        """
        self.capture = capture
        self.ip_address = self.hostname_to_ip(ip_address)
        self.port = port
        self.timings = defaultdict(list)
        self.client_message = None
        self.server_message = None
        self.warm_up_messages_left = WARM_UP

        # set up class names generator
        self.log = log
        self.class_generator = log.iterate_log()
        self.class_names = log.get_classes()

    def parse(self):
        """
        Extract timing information from capture file
        and associate it with class from log file.
        """
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
        """Associate the timing information with it's class"""
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
        with open("{0}".format(filename), 'w') as csvfile:
            print("Writing to {0}".format(filename))
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            for class_name in self.timings:
                row = [class_name]
                row.extend(self.timings[class_name])
                writer.writerow(row)

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
