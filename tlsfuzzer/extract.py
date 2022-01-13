# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Extraction and analysis of timing information from a packet capture."""

from __future__ import print_function

import getopt
import sys
import csv
import time
import math
from os.path import join
from collections import defaultdict
from socket import inet_aton, gethostbyname, gaierror, error
from threading import Thread
import pandas as pd
import numpy as np

import dpkt

from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.statics import WARM_UP
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict


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
    col_name = None

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "l:c:h:p:o:t:n:", ["help", "raw-times="])
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
    analysis = Extract(
        log, capture, output, ip_address, port, raw_times, col_name
    )
    analysis.parse()
    analysis.write_csv('timing.csv')
    if not raw_times:
        analysis.write_pkt_csv('raw_times_detail.csv')


class Extract:
    """Extract timing information from packet capture."""

    def __init__(self, log, capture=None, output=None, ip_address=None,
                 port=None, raw_times=None, col_name=None):
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
        self.client_msgs = []
        self.server_msgs = []
        self.initial_syn = None
        self.initial_syn_ack = None
        self.initial_ack = None
        self.warm_up_messages_left = WARM_UP
        self.raw_times = raw_times
        self.pckt_times = []
        self.col_name = col_name

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

        data = pd.read_csv(self.raw_times, dtype=np.float64)

        data.drop(range(self.warm_up_messages_left), inplace=True)

        if len(data.columns) > 1 and self.col_name is None:
            raise ValueError("Multiple columns in raw_times file!")

        if self.col_name:
            data = data[self.col_name]
        else:
            data = data[0]

        for line in data:
            class_index = next(self.class_generator)
            class_name = self.class_names[class_index]
            self.timings[class_name].append(line)

    @staticmethod
    def _bytes_prefix(count):
        ret = count
        lvl = 0
        lvls = {0: 'B', 1: 'KiB', 2: 'MiB', 3: 'GiB', 4: 'TiB', 5: 'EiB'}
        while ret > 2000:
            ret /= 1024.0
            lvl += 1

        return "{0:.2f} {1}".format(ret, lvls[lvl])

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

    @classmethod
    def _report_progress(cls, status):
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
        prev_loop = start_exec
        delay = 2.0
        while status[2]:
            old_exec = status[0]
            time.sleep(delay)
            now = time.time()
            elapsed = now-start_exec
            loop_time = now-prev_loop
            prev_loop = now
            elapsed_str = cls._format_seconds(elapsed)
            done = status[0]*100.0/status[1]
            try:
                remaining = (100-done)*elapsed/done
            except ZeroDivisionError:
                remaining = status[1]
            remaining_str = cls._format_seconds(remaining)
            eta = time.strftime("%H:%M:%S %d-%m-%Y",
                                time.localtime(now+remaining))
            print("Done: {0:6.2f}%, elapsed: {1}, speed: {2}/s, "
                  "avg speed: {3}/s, remaining: {4}, ETA: {5}{6}"
                  .format(
                      done, elapsed_str,
                      cls._bytes_prefix((status[0] - old_exec)/loop_time),
                      cls._bytes_prefix(status[0]/elapsed),
                      remaining_str,
                      eta,
                      " " * 4), end="\r")

    def _parse_pcap(self):
        """Process capture file."""
        with open(self.capture, 'rb') as pcap:
            progress = None
            try:
                pcap.seek(0, 2)
                exp_len = pcap.tell()
                pcap.seek(0, 0)
                status = [0, exp_len, True]
                progress = Thread(target=self._report_progress, args=(status,))
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

                        # note time of first packet
                # deal with the last connection
                self.add_timing()
            finally:
                status[2] = False
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
            else:
                self.warm_up_messages_left -= 1
                if self.warm_up_messages_left == 0:
                    if self.srv_fin > self.clnt_fin:
                        self.last_warmup_fin = self.srv_fin
                    else:
                        self.last_warmup_fin = self.clnt_fin

    def write_pkt_csv(self, filename):
        """
        Write all packet times to file
        """
        exp_clnt = None
        exp_srv = None
        for _, _, _, clnt_msgs, clnt_msgs_acks, srv_msgs, srv_msgs_acks, _, _, _ in self.pckt_times:
            if len(clnt_msgs) != len(clnt_msgs_acks):
                print(clnt_msgs)
                print()
                print(clnt_msgs_acks)
                raise ValueError("client message ACKs mismatch: {0} vs {1}"
                    .format(len(clnt_msgs), len(clnt_msgs_acks)))
            if len(srv_msgs) != len(srv_msgs_acks):
                print(srv_msgs)
                print()
                print(srv_msgs_acks)
                raise ValueError("server message ACKs mismatch")

            if exp_clnt is None:
                exp_clnt = len(clnt_msgs)
            elif len(clnt_msgs) != exp_clnt:
                raise ValueError("inconsistent count of client messages")

            if exp_srv is None:
                exp_srv = len(srv_msgs)
            elif len(srv_msgs) != exp_srv:
                raise ValueError("inconsistent count of server messages")
        if exp_srv != exp_clnt:
            raise ValueError("For every client query we need a response")

        filename = join(self.output, filename)
        with open(filename, 'w') as csvfile:
            print("Writing to {0}".format(filename))
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            columns = [
                "lst_msg_to_syn",
                "syn_to_syn_ack",
                "syn_ack_to_ack",
            ]
            for i in range(exp_clnt):
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

            previous_lst_msg = self.last_warmup_fin
            for (syn, syn_ack, ack, c_msgs, c_msgs_acks, s_msgs, s_msgs_acks,
                    srv_fin, clnt_fin, ack_for_fin) in self.pckt_times:
                lst_clnt = c_msgs[-1]
                row = [
                    syn - previous_lst_msg,
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
                row.append(ack_for_fin - last_fin)

                writer.writerow(row)
                previous_lst_msg = ack_for_fin

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
