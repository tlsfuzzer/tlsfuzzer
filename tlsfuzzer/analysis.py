# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Tool for extraction and analysis of timing information from packet capture"""

import argparse
from collections import defaultdict
import csv
import dpkt
from tlsfuzzer.utils.log import Log


def main():
    """Process arguments and start extraction"""
    parser = argparse.ArgumentParser(description="Timing analysis from packet capture")
    parser.add_argument('-l', help="logfile", dest="log", required=True)
    parser.add_argument('-c', help="capture file", dest="capture", required=True)
    parser.add_argument('-i', help="server ip", dest="ip", required=True)
    parser.add_argument('-p', help="server port", dest="port", required=True, type=int)

    args = parser.parse_args()
    analysis = Analysis(args.log, args.capture, args.ip, args.port)
    analysis.parse()


class Analysis:
    """Class to provide tools to extract and analyse timing information from packet capture"""

    def __init__(self, logfile, capture, ip_address, port):
        """
        Initialises instance and sets up class name generator from log.

        :param str logfile: Log filename
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

        # set up class names generator
        log = Log(logfile)
        log.read_log()
        self.class_generator = log.iterate_log()

    def parse(self):
        """Extract timing information from capture file and associate it with class from log file"""
        with open(self.capture, 'rb') as pcap:
            capture = dpkt.pcap.Reader(pcap)

            for timestamp, pkt in capture:
                link_packet = dpkt.ethernet.Ethernet(pkt)
                ip_pkt = link_packet.data
                tcp_pkt = ip_pkt.data

                if tcp_pkt.data:
                    if tcp_pkt.sport == self.port:
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
            class_name = self.class_generator.__next__()
            time_diff = abs(self.server_message - self.client_message)
            self.timings[class_name].append(time_diff)

    def write_csv(self, filename):
        """
        Write timing information into a csv file. Each row starts with a class name and
        the rest of the row are individual timing measurements.

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
