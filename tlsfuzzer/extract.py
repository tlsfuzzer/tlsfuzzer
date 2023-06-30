# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Extraction and analysis of timing information from a packet capture."""

from __future__ import print_function

import getopt
import sys
import csv
import time
import math
from os.path import join, splitext
from collections import defaultdict
from socket import inet_aton, gethostbyname, gaierror, error
from threading import Thread, Event
import pandas as pd
import numpy as np

import dpkt

from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.statics import WARM_UP
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.utils.progress_report import progress_report
from tlslite.utils.cryptomath import bytesToNumber


def help_msg():
    """Print help message."""
    print("Usage: extract [-l logfile] [-c capture] [[-o output] ...]")
    print(" -l logfile     Filename of the timing log (required)")
    print(" -c capture     Packet capture of the test run")
    print(" -o output      Directory where to place results (required)")
    print(" -h host        TLS server host or ip")
    print(" -p port        TLS server port")
    print(" -n name        column name to use from the raw-times file")
    print(" --raw-times FILE Read the timings from an external file, not")
    print("                the packet capture.")
    print(" --binary num   Expect the raw-times file to store binary numbers")
    print("                'num' bytes each. Note: using it will overwrite")
    print("                the csv counterpart to FILE (if FILE is 'data.bin'")
    print("                it will overwrite 'data.csv'")
    print(" --endian endian What endianness to use, 'little' or 'big', with")
    print("                little being the default")
    print(" --no-quickack  Don't assume QUICKACK to be in use (affects capture")
    print("                file parsing only)")
    print(" --status-delay num How often to print the status line.")
    print(" --status-newline Use newline instead of carriage return for status.")
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
    col_name = None
    binary = None
    endian = 'little'
    no_quickack = False
    delay = None
    carriage_return = None

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "l:c:h:p:o:t:n:",
                               ["help", "raw-times=", "binary=", "endian=",
                                "no-quickack", "status-delay=",
                                "status-newline"])
    for opt, arg in opts:
        if opt == '-l':
            logfile = arg
        elif opt == '-c':
            capture = arg
        elif opt == '-o':
            output = arg
        elif opt == '-h':
            ip_address = arg
        elif opt == "-n":
            col_name = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == "--raw-times":
            raw_times = arg
        elif opt == "--binary":
            binary = int(arg)
        elif opt == "--endian":
            endian = arg
        elif opt == "--no-quickack":
            no_quickack = True
        elif opt == "--status-delay":
            delay = float(arg)
        elif opt == "--status-newline":
            carriage_return = '\n'
        elif opt == "--help":
            help_msg()
            sys.exit(0)

    if args:
        raise ValueError(
            "Unexpected arguments: {0}".format(args))

    if raw_times and capture:
        raise ValueError(
            "Can't specify both a capture file and external timing log")

    if binary and col_name:
        raise ValueError(
            "Binary format doesn't support column names")

    if binary and not raw_times:
        raise ValueError(
            "Can't specify binary number size without raw-times file")

    if endian not in ('little', 'big'):
        raise ValueError(
            "Only 'little' and 'big' endianess supported")

    if not all([logfile, output]):
        raise ValueError(
            "Specifying logfile and output is mandatory")

    if capture and not all([logfile, output, ip_address, port]):
        raise ValueError("Some arguments are missing!")

    log = Log(logfile)
    log.read_log()
    analysis = Extract(
        log, capture, output, ip_address, port, raw_times, col_name,
        binary=binary, endian=endian, no_quickack=no_quickack,
        delay=delay, carriage_return=carriage_return,
    )
    analysis.parse()


class Extract:
    """Extract timing information from packet capture."""

    def __init__(self, log, capture=None, output=None, ip_address=None,
                 port=None, raw_times=None, col_name=None,
                 write_csv='timing.csv', write_pkt_csv='raw_times_detail.csv',
                 binary=None, endian='little', no_quickack=False, delay=None,
                 carriage_return=None):
        """
        Initialises instance and sets up class name generator from log.

        :param Log log: Log class instance
        :param str capture: Packet capture filename
        :param str output: Directory where to output results
        :param str ip_address: TLS server ip address
        :param int port: TLS server port
        :param int binary: number of bytes per timing from raw times file
        :param str endian: endianess of the read numbers
        :param bool no_quickack: If True, don't expect QUICKACK to be in use
        :param float delay: How often to print the status line.
        :param str carriage_return: What chacarter to use as status line end.
        """
        self.capture = capture
        self.output = output
        self.ip_address = ip_address and self.hostname_to_ip(ip_address)
        self.port = port
        self.timings = defaultdict(list)
        self.client_message = None
        self.server_message = None
        self.client_msgs = []
        self.server_msgs = []
        self.initial_syn = None
        self.initial_syn_ack = None
        self.initial_ack = None
        self.warm_up_messages_left = WARM_UP
        self.raw_times = raw_times
        self.binary = binary
        self.endian = endian
        self.pckt_times = []
        self.col_name = col_name
        self.write_csv = write_csv
        self.write_pkt_csv = write_pkt_csv
        self._exp_clnt = None
        self._exp_srv = None
        self._previous_lst_msg = None
        self._write_class_names = None
        self.no_quickack = no_quickack
        self.delay = delay
        self.carriage_return = carriage_return

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

    def _convert_binary_file(self, raw_times_name):
        """Convert the binary file format to csv before further processing."""
        with open(self.raw_times, 'rb') as raw_times_bin:
            with open(raw_times_name, 'w') as raw_times:
                raw_times.write("raw times\n")
                while True:
                    val = raw_times_bin.read(self.binary)
                    if not val:
                        break
                    raw_times.write(
                        str(bytesToNumber(val, endian=self.endian)) + '\n')

    def _parse_raw_times(self):
        """Classify already extracted times."""
        # as unlike with capture file, we don't know how many sanity tests,
        # manual checks, etc. were performed to the server before the
        # timing tests were started, we don't know how many measurements to
        # skip. Count the probes, the times, and then use the last len(probes)
        # of times for classification

        raw_times_name = self.raw_times

        # if we got a binary file on input, first transform it into a csv file
        if self.binary:
            raw_times_name = splitext(self.raw_times)[0] + ".csv"
            self._convert_binary_file(raw_times_name)

        # do counting in memory efficient way
        probe_count = sum(1 for _ in self.class_generator)
        self.log.read_log()
        self.class_generator = self.log.iterate_log()
        with open(raw_times_name, 'r') as raw_times:
            # skip the header line
            raw_times.readline()
            times_count = 0
            for times_count, _ in enumerate(raw_times, 1):
                pass
        if probe_count > times_count:
            raise ValueError(
                "Insufficient number of times for provided log file "
                "(expected: {0}, found: {1})".format(probe_count, times_count))

        self.warm_up_messages_left = times_count - probe_count

        data = pd.read_csv(raw_times_name, dtype=np.float64)

        data.drop(range(self.warm_up_messages_left), inplace=True)

        if len(data.columns) > 1 and self.col_name is None:
            raise ValueError("Multiple columns in raw_times file and "
                "no column name specified!")

        if self.col_name:
            data = data[self.col_name]
        else:
            data = data.iloc[:, 0]

        for line in data:
            class_index = next(self.class_generator)
            class_name = self.class_names[class_index]
            self.timings[class_name].append(line)
            self._flush_to_files()

        self._write_csv_header()
        self._write_csv()

    def _parse_pcap(self):
        """Process capture file."""
        with open(self.capture, 'rb') as pcap:
            progress = None
            try:
                pcap.seek(0, 2)
                exp_len = pcap.tell()
                pcap.seek(0, 0)
                status = [0, exp_len, Event()]
                kwargs = {}
                kwargs['unit'] = 'B'
                kwargs['prefix'] = 'binary'
                kwargs['delay'] = self.delay
                kwargs['end'] = self.carriage_return
                progress = Thread(target=progress_report, args=(status,),
                                  kwargs=kwargs)
                progress.start()

                capture = dpkt.pcap.Reader(pcap)

                exp_srv_ack = 0
                exp_clnt_ack = 0

                pkt_count = 0
                # since timestamp is Decimal() we don't have to worry about
                # float() precision
                for timestamp, pkt in capture:
                    status[0] = pcap.tell()
                    pkt_count += 1
                    link_packet = dpkt.ethernet.Ethernet(pkt)
                    ip_pkt = link_packet.data
                    tcp_pkt = ip_pkt.data

                    if (tcp_pkt.flags & dpkt.tcp.TH_SYN and
                            tcp_pkt.dport == self.port and
                            ip_pkt.dst == self.ip_address):
                        # a SYN packet was found - new connection
                        # (if a retransmission it won't be counted as at least
                        # one client and one server message has to be
                        # exchanged)
                        self.add_timing()

                        # reset timestamps
                        self.server_message = None
                        self.client_message = None
                        self.initial_syn = timestamp
                        self.initial_syn_ack = None
                        self.initial_ack = None
                        self.client_msgs = []
                        self.client_msgs_acks = OrderedDict()
                        self.server_msgs = []
                        self.server_msgs_acks = OrderedDict()
                        self.clnt_fin = None
                        self.srv_fin = None
                        self.ack_for_fin = None
                        self.in_srv_shutdown = False
                        self.in_clnt_shutdown = False
                        self.initial_ack_seq_no = None
                        exp_srv_ack = tcp_pkt.seq + 1 & 0xffffffff
                        exp_clnt_ack = 0
                    elif (tcp_pkt.flags & dpkt.tcp.TH_SYN and
                            tcp_pkt.flags & dpkt.tcp.TH_ACK and
                            tcp_pkt.sport == self.port and
                            ip_pkt.src == self.ip_address):
                        self.initial_syn_ack = timestamp
                        exp_clnt_ack = tcp_pkt.seq + 1 & 0xffffffff
                        if tcp_pkt.ack != exp_srv_ack:
                            print("Mismatched syn/ack seq at {0}\n"
                                  .format(pkt_count))
                            raise ValueError("Packet drops in capture!")
                    elif (tcp_pkt.flags & dpkt.tcp.TH_ACK and
                            tcp_pkt.dport == self.port and
                            ip_pkt.dst == self.ip_address and
                            tcp_pkt.ack == exp_clnt_ack and
                            not self.initial_ack):
                        # the initial ACK is the first ACK that acknowledges
                        # the SYN+ACK
                        self.initial_ack = timestamp
                        self.initial_ack_seq_no = tcp_pkt.ack
                    elif (tcp_pkt.flags & dpkt.tcp.TH_ACK and
                            not tcp_pkt.flags & dpkt.tcp.TH_FIN and
                            tcp_pkt.sport == self.port and
                            tcp_pkt.ack not in self.client_msgs_acks and
                            not self.in_srv_shutdown):
                        # check if it's the first ACK to a client sent message
                        if len(self.client_msgs) > len(self.client_msgs_acks):
                            self.client_msgs_acks[tcp_pkt.ack] = timestamp
                    elif (tcp_pkt.flags & dpkt.tcp.TH_ACK and
                            not tcp_pkt.flags & dpkt.tcp.TH_FIN and
                            tcp_pkt.dport == self.port and
                            tcp_pkt.ack != self.initial_ack_seq_no and
                            tcp_pkt.ack not in self.server_msgs_acks and
                            not self.in_clnt_shutdown):
                        # check if it's the first ACK to a server sent message
                        if len(self.server_msgs) > len(self.server_msgs_acks):
                            self.server_msgs_acks[tcp_pkt.ack] = timestamp
                    elif tcp_pkt.flags & dpkt.tcp.TH_FIN:
                        if tcp_pkt.sport == self.port:
                            self.in_srv_shutdown = True
                            self.srv_fin = timestamp
                            if len(self.client_msgs) > \
                                    len(self.client_msgs_acks):
                                self.client_msgs_acks[tcp_pkt.ack] = timestamp
                        else:
                            self.in_clnt_shutdown = True
                            self.clnt_fin = timestamp
                            if len(self.server_msgs) > \
                                    len(self.server_msgs_acks):
                                self.server_msgs_acks[tcp_pkt.ack] = timestamp
                    elif (tcp_pkt.flags & dpkt.tcp.TH_ACK and
                            not tcp_pkt.flags & dpkt.tcp.TH_FIN and
                            self.in_clnt_shutdown and self.in_srv_shutdown):
                        self.ack_for_fin = timestamp

                    # initial ACK can be combined with the first data packet
                    if tcp_pkt.data:
                        if (tcp_pkt.sport == self.port and
                                ip_pkt.src == self.ip_address):
                            if tcp_pkt.ack != exp_srv_ack:
                                print("Mismatched syn/ack seq at {0}\n"
                                      .format(pkt_count))
                                raise ValueError("Packet drops in capture!")
                            exp_clnt_ack = exp_clnt_ack + len(tcp_pkt.data) \
                                & 0xffffffff
                            # message from the server
                            self.server_message = timestamp
                            self.server_msgs.append(timestamp)
                        else:
                            if tcp_pkt.ack != exp_clnt_ack:
                                print("Mismatched syn/ack seq at {0}\n"
                                      .format(pkt_count))
                                raise ValueError("Packet drops in capture!")
                            exp_srv_ack = exp_srv_ack + len(tcp_pkt.data) \
                                & 0xffffffff
                            # message from the client
                            self.client_message = timestamp
                            self.client_msgs.append(timestamp)

                # deal with the last connection
                self.add_timing()
            finally:
                status[2].set()
                progress.join()
                print()

    def add_timing(self):
        """Associate the timing information with its class"""
        if self.client_message and self.server_message:
            if self.warm_up_messages_left == 0:
                class_index = next(self.class_generator)
                class_name = self.class_names[class_index]
                lst_clnt_ack = 0
                for lst_clnt_ack in self.client_msgs_acks.values():
                    pass
                if self.no_quickack:
                    time_diff = self.server_msgs[-1] - self.client_msgs[-1]
                else:
                    time_diff = self.server_msgs[-1] - lst_clnt_ack
                self.timings[class_name].append(time_diff)
                self.pckt_times.append((
                    self.initial_syn,
                    self.initial_syn_ack,
                    self.initial_ack,
                    self.client_msgs,
                    self.client_msgs_acks,
                    self.server_msgs,
                    self.server_msgs_acks,
                    self.srv_fin,
                    self.clnt_fin,
                    self.ack_for_fin,
                ))
                self._flush_to_files()
            else:
                self.warm_up_messages_left -= 1
                if self.warm_up_messages_left == 0:
                    if self.srv_fin > self.clnt_fin:
                        self.last_warmup_fin = self.srv_fin
                    else:
                        self.last_warmup_fin = self.clnt_fin

    def _flush_to_files(self):
        # we can write only complete lines
        if len(self.timings) != len(self.class_names) or \
                not all(self.timings.values()):
            return

        if not self.raw_times:
            # make sure the csv has a header
            self._write_pkt_header()

            # then write queued up individual packet times
            self._write_pkts()

        # write the header of the already sorted results
        self._write_csv_header()

        # finally write the times of already sorted classes
        self._write_csv()

    def _write_csv_header(self):
        if self._write_class_names is not None:
            return

        filename = join(self.output, self.write_csv)
        with open(filename, 'w') as csvfile:
            print("Writing to {0}\n".format(filename))
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            class_names = sorted(self.timings, key=natural_sort_keys)
            writer.writerow(class_names)
            self._write_class_names = class_names

    def _write_csv(self):
        filename = join(self.output, self.write_csv)
        with open(filename, 'a') as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            for values in zip(*[self.timings[i] for i in
                    self._write_class_names]):
                writer.writerow("{0:.9f}".format(i) for i in values)

            for i in self.timings.values():
                i.clear()

    def _write_pkts(self):
        for _, _, _, clnt_msgs, clnt_msgs_acks, srv_msgs, srv_msgs_acks, _, _, _ in self.pckt_times:
            if len(clnt_msgs) != len(clnt_msgs_acks): # pragma: no cover
                # no coverage; assert
                print(clnt_msgs)
                print()
                print(clnt_msgs_acks)
                raise ValueError("client message ACKs mismatch: {0} vs {1}"
                    .format(len(clnt_msgs), len(clnt_msgs_acks)))
            if len(srv_msgs) != len(srv_msgs_acks):  # pragma: no cover
                # no coverage; assert
                print(srv_msgs)
                print()
                print(srv_msgs_acks)
                raise ValueError("server message ACKs mismatch")

            if len(clnt_msgs) != self._exp_clnt:  # pragma: no cover
                # no coverage; assert
                raise ValueError("inconsistent count of client messages")

            if len(srv_msgs) != self._exp_srv:  # pragma: no cover
                # no coverage: assert
                raise ValueError("inconsistent count of server messages")

        if self._previous_lst_msg is None:
            self._previous_lst_msg = self.last_warmup_fin

        filename = join(self.output, self.write_pkt_csv)
        with open(filename, "a") as csvfile:
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            while self.pckt_times:
                (syn, syn_ack, ack, c_msgs, c_msgs_acks, s_msgs, s_msgs_acks,
                    srv_fin, clnt_fin, ack_for_fin) = self.pckt_times.pop(0)

                row = [
                    syn - self._previous_lst_msg,
                    syn_ack - syn,
                    ack - syn_ack,
                ]
                prv_ack = ack
                for c_msg, c_msg_ack, s_msg, s_msg_ack in zip(
                        c_msgs, c_msgs_acks.values(),
                        s_msgs, s_msgs_acks.values()
                ):
                    # prv_ack_to_clnt_X
                    row.append(c_msg - prv_ack)
                    prv_ack = s_msg_ack
                    # clnt_X_ack
                    row.append(c_msg_ack - c_msg)
                    # clnt_X_rtt
                    row.append(s_msg - c_msg)

                    # prv_ack_to_srv_X
                    row.append(s_msg - c_msg_ack)
                    # srv_X_ack
                    row.append(s_msg_ack - s_msg)

                # lst_srv_to_srv_fin
                row.append(srv_fin - s_msgs[-1])
                # lst_srv_to_clnt_fin
                row.append(clnt_fin - s_msgs[-1])
                if srv_fin > clnt_fin:
                    last_fin = srv_fin
                else:
                    last_fin = clnt_fin
                # second_fin_to_ack
                if ack_for_fin:
                    row.append(ack_for_fin - last_fin)
                    self._previous_lst_msg = ack_for_fin
                else:
                    row.append(0.0)
                    self._previous_lst_msg = last_fin

                writer.writerow(row)

    def _write_pkt_header(self):
        if self._exp_clnt is not None:
            return

        for _, _, _, clnt_msgs, clnt_msgs_acks, srv_msgs, srv_msgs_acks, \
                _, _, _ in self.pckt_times:
            if len(clnt_msgs) != len(clnt_msgs_acks):  # pragma: no cover
                # no overage; assert
                print(clnt_msgs)
                print()
                print(clnt_msgs_acks)
                raise ValueError("client message ACKs mismatch: {0} vs {1}"
                    .format(len(clnt_msgs), len(clnt_msgs_acks)))
            if len(srv_msgs) != len(srv_msgs_acks):  # pragma: no cover
                # no coverage; assert
                print(srv_msgs)
                print()
                print(srv_msgs_acks)
                raise ValueError("server message ACKs mismatch")

            self._exp_clnt = len(clnt_msgs)
            self._exp_srv = len(srv_msgs)

        if self._exp_srv != self._exp_clnt:  # pragma: no cover
            # no coverage; assert
            raise ValueError("For every client query we need a response")

        filename = join(self.output, self.write_pkt_csv)
        with open(filename, 'w') as csvfile:
            print("Writing to {0}\n".format(filename))
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            columns = [
                "lst_msg_to_syn",
                "syn_to_syn_ack",
                "syn_ack_to_ack",
            ]
            for i in range(self._exp_clnt):
                columns.append("prv_ack_to_clnt_{0}".format(i))
                columns.append("clnt_{0}_ack".format(i))
                columns.append("clnt_{0}_rtt".format(i))
                columns.append("prv_ack_to_srv_{0}".format(i))
                columns.append("srv_{0}_ack".format(i))
            columns.extend([
                "lst_srv_to_srv_fin",
                "lst_srv_to_clnt_fin",
                "second_fin_to_ack"
            ])

            writer.writerow(columns)

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
