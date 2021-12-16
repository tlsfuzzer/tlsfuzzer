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
    if not raw_times:
        analysis.write_pkt_csv('raw_times_detail.csv')


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
        self.client_msgs = []
        self.server_msgs = []
        self.initial_syn = None
        self.initial_syn_ack = None
        self.initial_ack = None
        self.warm_up_messages_left = WARM_UP
        self.raw_times = raw_times
        self.pckt_times = []

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
                        self.server_msgs = []
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
                time_diff = abs(self.server_message - self.client_message)
                self.timings[class_name].append(time_diff)
                self.pckt_times.append((
                    self.initial_syn,
                    self.initial_syn_ack,
                    self.initial_ack,
                    self.client_msgs,
                    self.server_msgs
                ))
            else:
                self.warm_up_messages_left -= 1
                if self.warm_up_messages_left == 0:
                    self.last_warmup_server = self.server_message

    def write_pkt_csv(self, filename):
        """
        Write all packet times to file
        """
        filename = join(self.output, filename)
        with open(filename, 'w') as csvfile:
            print("Writing to {0}".format(filename))
            writer = csv.writer(csvfile, quoting=csv.QUOTE_MINIMAL)
            columns = [
                "lst_srv_to_syn",
                "syn_to_syn_ack",
                "syn_ack_to_ack",
                "ack_to_lst_clnt",
                "lst_clnt_to_lst_srv",
            ]
            multi = False

            if len(self.pckt_times[0][3]) > 1:
                if not len(self.pckt_times[0][4]) > 1:
                    raise ValueError("Both sides must send multiple packets")
                colums.extend((
                    "2nd_lst_clnt_to_2nd_lst_srv",
                ))
                multi = True

            writer.writerow(columns)

            previous_lst_srv = self.last_warmup_server
            for syn, syn_ack, ack, c_msgs, s_msgs in self.pckt_times:
                lst_clnt = c_msgs[-1]
                row = [
                    syn - previous_lst_srv,
                    syn_ack - syn,
                    ack - syn_ack,
                    lst_clnt - ack,
                    s_msgs[-1] - lst_clnt,
                ]

                if multi and len(c_msgs) > 1 and len(s_msgs):
                    row.extend((
                        s_msgs[-2] - c_msgs[-2],
                    ))

                writer.writerow(row)
                previous_lst_srv = s_msgs[-1]

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
