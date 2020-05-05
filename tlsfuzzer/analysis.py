# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Extraction and analysis of timing information from a packet capture."""

import getopt
import sys
import os
import csv
from collections import defaultdict
from socket import inet_aton

import dpkt
from tlsfuzzer.utils.log import Log


def help_msg():
    """Print help message."""
    print("Usage: analysis [-l logfile] [-c capture] [[-o output] ...]")
    print(" -l logfile     Filename of the timing log (required)")
    print(" -c capture     Packet capture of the test run (required)")
    print(" -o output      Where to output the resulting csv (required)")
    print(" -i ip          TLS server ip (required)")
    print(" -p port        TLS server port (required)")


def main():
    """Process arguments and start extraction."""
    logfile = None
    capture = None
    output = None
    ip_address = None
    port = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "l:c:i:p:", ["help"])
    for opt, arg in opts:
        if opt == '-l':
            logfile = arg
        elif opt == '-c':
            capture = arg
        elif opt == '-o':
            output = arg
        elif opt == '-i':
            ip_address = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if not logfile or not capture or not output or not ip_address or not port:
        raise ValueError("All arguments need to be entered!")

    log = Log(logfile)
    log.read_log()
    analysis = Analysis(log, capture, ip_address, port)
    analysis.parse()
    analysis.write_csv(os.path.join("timing.csv"))


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
        self.ip_address = ip_address
        self.port = port
        self.timings = defaultdict(list)
        self.client_message = None
        self.server_message = None

        if self.ip_address == "localhost":
            self.ip_address = "127.0.0.1"

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
                            ip_pkt.src == inet_aton(self.ip_address)):
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
            class_index = next(self.class_generator)
            class_name = self.class_names[class_index]
            time_diff = abs(self.server_message - self.client_message)
            self.timings[class_name].append(time_diff)

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


if __name__ == '__main__':
    main()
