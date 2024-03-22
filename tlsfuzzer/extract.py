# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Extraction and analysis of timing information from a packet capture."""

from __future__ import print_function

import getopt
import sys
import csv
import time
import math
from os import remove
from os.path import join, splitext, getsize, exists
from collections import defaultdict
from socket import inet_aton, gethostbyname, gaierror, error
import multiprocessing as mp
from threading import Thread, Event
import hashlib
import tempfile
from random import choice
import ecdsa
import pandas as pd
import numpy as np

import dpkt

from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.statics import WARM_UP
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.utils.progress_report import progress_report
from tlslite.utils.cryptomath import bytesToNumber

try:
    from itertools import izip
except ImportError: # will be 3.x series
    izip = zip

if sys.version_info >= (3, 10):
    def bit_count(n):
        return n.bit_count()
else:
    def bit_count(n):
        return bin(n).count("1")

WAIT_FOR_FIRST_BARE_MAX_VALUE = 0
WAIT_FOR_NON_BARE_MAX_VALUE = 1
WAIT_FOR_SECOND_BARE_MAX_VALUE = 2


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
    print(" --no-quickack  Don't assume QUICKACK to be in use (affects")
    print("                capture file parsing only)")
    print(" --status-delay num How often to print the status line.")
    print(" --status-newline Use newline instead of carriage return for")
    print("                printing status line.")
    print(" --raw-data FILE Read the data used for signing from an external")
    print("                file. The file must be in binary format.")
    print(" --data-size num The size of data used for each signature.")
    print(" --prehashed    Specifies that the data on the file are already")
    print("                hashed. Canceled by hash-func option.")
    print(" --raw-sigs FILE Read the signatures from an external file.")
    print("                The file must be in binary format.")
    print(" --priv-key-ecdsa FILE Read the ecdsa private key from PEM file.")
    print(" --clock-frequency freq Assume that the times in the file are not")
    print("                specified in seconds but rather in clock cycles of")
    print("                a clock running at requency 'freq' specified in")
    print("                MHz. Use when the clock source are the raw reads")
    print("                from the Time Stamp Counter register or similar.")
    print(" --hash-func func Specifies the hash function to use for")
    print("                extracting the k value. The function should be")
    print("                available in hashlib module. The default function")
    print("                is sha256.")
    print(" --workers num  Number of worker processes to use for")
    print("                parallelizable computation. More workers")
    print("                will finish analysis faster, but will require")
    print("                more memory to do so. By default: number of")
    print("                threads available on the system (`os.cpu_count()`)")
    print(" --verbose      Print's a more verbose output.")
    print(" --help         Display this message")
    print("")
    print("When extracting data from a capture file, specifying the capture")
    print("file, host and port is necessary.")
    print("When using the external timing source, only it, and the always")
    print("required options: logfile and output dir are necessary.")
    print("When doing signature extraction, data file, data size, signatures")
    print("file, and one private key are necessary.")
    print("For ECDSA signatures, the hash function used for the extraction of")
    print("K depends on the private key's curve size.")


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
    data = None
    data_size = None
    sigs = None
    priv_key = None
    key_type = None
    freq = None
    hash_func_name = None
    workers = None
    verbose = False
    prehashed = False

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "l:c:h:p:o:t:n:",
                               ["help", "raw-times=", "binary=", "endian=",
                                "no-quickack", "status-delay=",
                                "status-newline", "raw-data=", "data-size=",
                                "prehashed", "raw-sigs=", "priv-key-ecdsa=",
                                "clock-frequency=", "hash-func=", "workers=",
                                "verbose"])
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
        elif opt == "--raw-data":
            data = arg
        elif opt == "--data-size":
            data_size = int(arg)
        elif opt == "--prehashed":
            prehashed = True
        elif opt == "--raw-sigs":
            sigs = arg
        elif opt == "--priv-key-ecdsa":
            priv_key = arg
            if not key_type:
                key_type = "ecdsa"
            else:
                raise ValueError(
                    "Can't specify more than one private key.")
        elif opt == "--verbose":
            verbose = True
        elif opt == "--clock-frequency":
            freq = float(arg) * 1e6
        elif opt == "--hash-func":
            hash_func_name = arg
        elif opt == "--workers":
            workers = int(arg)
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

    if not all([any([logfile, sigs]), output]):
        raise ValueError(
            "Specifying either logfile or raw sigs and output is mandatory")

    if capture and not all([logfile, output, ip_address, port]):
        raise ValueError("Some arguments are missing!")

    if any([sigs, priv_key]) \
       and not all([raw_times, data, data_size, sigs, priv_key]):
        raise ValueError(
            "When doing signature extraction, times file, data file, \
data size, signatures file and one private key are necessary.")

    if hash_func_name == None:
        if prehashed:
            hash_func = None
        else:
            hash_func = hashlib.sha256
    else:
        try:
            hash_func = getattr(hashlib, hash_func_name)
        except AttributeError:
            raise ValueError(
                "Hash function {0} is not supported.".format(hash_func_name))

    log = None
    if logfile:
        log = Log(logfile)
        log.read_log()

    extract = Extract(
        log, capture, output, ip_address, port, raw_times, col_name,
        binary=binary, endian=endian, no_quickack=no_quickack,
        delay=delay, carriage_return=carriage_return,
        data=data, data_size=data_size, sigs=sigs, priv_key=priv_key,
        key_type=key_type, frequency=freq, hash_func=hash_func,
        workers=workers, verbose=verbose
    )
    extract.parse()

    if all([raw_times, data, data_size, sigs, priv_key]):
        extract.process_and_create_multiple_csv_files({
            "measurements.csv": "k-size",
            "measurements-invert.csv": "invert-k-size",
        })


class Extract:
    """Extract timing information from packet capture."""

    def __init__(self, log=None, capture=None, output=None, ip_address=None,
                 port=None, raw_times=None, col_name=None,
                 write_csv='timing.csv', write_pkt_csv='raw_times_detail.csv',
                 measurements_csv="measurements.csv",
                 binary=None, endian='little', no_quickack=False, delay=None,
                 carriage_return=None, data=None, data_size=None, sigs=None,
                 priv_key=None, key_type=None, frequency=None,
                 hash_func=hashlib.sha256, workers=None, verbose=False,
                 fin_as_resp=False):
        """
        Initialises instance and sets up class name generator from log.

        :param Log log: Log class instance
        :param str capture: Packet capture filename
        :param str output: Directory where to output results
        :param str ip_address: TLS server ip address
        :param int port: TLS server port
        :param str data: Name of file with data used for signing
        :param int data_size: Size of data used for each signature
        :param str sigs: Signature filename
        :param str priv_key: Private key filename
        :param str key_type: The type of the private key
        :param int binary: number of bytes per timing from raw times file
        :param str endian: endianess of the read numbers
        :param bool no_quickack: If True, don't expect QUICKACK to be in use
        :param float delay: How often to print the status line.
        :param str carriage_return: What chacarter to use as status line end.
        :param func hash_func: The hash function that will be used for hashing
            the message in bit size analysis. None for prehashed data.
        :param int workers: The amount of parallel workers to be used.
        :param bool verbose: Prints a more verbose output
        :param bool fin_as_resp: consider the server FIN packet to be the
            response to previous client query
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
        self.last_warmup_fin = None
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
        self.data = data
        self.data_size = data_size
        self.sigs = sigs
        self.key_type = key_type
        self.frequency = frequency
        self.measurements_csv = measurements_csv
        self.hash_func = hash_func  # None if data are already hashed
        self.workers = workers
        self.verbose = verbose
        self._total_measurements = None
        self._measurements_fp = None
        self._intermedian_fp = None
        self._current_line = None
        self._next_line = None
        self._line_to_write = None
        self._max_tuple_size = 0
        self._measurements_dropped = 0
        self._selections = None
        self._row = 0
        self._max_value = None
        self._fin_as_resp = fin_as_resp

        if data and data_size:
            try:
                self._total_measurements = int(getsize(data) / data_size)
            except OSError:
                self._total_measurements = None

        self.priv_key = None
        if key_type == "ecdsa":
            with open(priv_key, 'r') as f:
                self.priv_key = ecdsa.SigningKey.from_pem(f.read())

        # set up class names generator
        self.log = log
        if log:
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
        times_iter = self._get_time_from_file()

        with open(raw_times_name, 'w') as raw_times:
            raw_times.write("raw times\n")
            for val in times_iter:
                raw_times.write(str(val) + '\n')

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

        if not self.log:
            return

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

        data_iter = self._get_time_from_file()
        for _ in range(self.warm_up_messages_left):
            next(data_iter)

        for line in data_iter:
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
                if self._fin_as_resp:
                    srv_time = self.srv_fin
                else:
                    srv_time = self.server_msgs[-1]
                if self.no_quickack:
                    time_diff = srv_time - self.client_msgs[-1]
                else:
                    time_diff = srv_time - lst_clnt_ack
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
                    if self.srv_fin is None and self.clnt_fin is None:
                        self.last_warmup_fin = 0
                    else:
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
                writer.writerow("{0:.9e}".format(float(i)) for i in values)

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

            if len(srv_msgs) + int(self._fin_as_resp) != self._exp_srv:  # pragma: no cover
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

                if self._previous_lst_msg is None:
                    row = [
                        0,
                        syn_ack - syn,
                        ack - syn_ack,
                    ]
                else:
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
                if srv_fin is None:
                    row.append(0)
                else:
                    row.append(srv_fin - s_msgs[-1])

                # lst_srv_to_clnt_fin
                if clnt_fin is None:
                    row.append(0)
                else:
                    row.append(clnt_fin - s_msgs[-1])

                if srv_fin is None or clnt_fin is None:
                    row.append(0)
                else:
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
                srv_fin, _, _ in self.pckt_times:
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
            self._exp_srv = len(srv_msgs) + int(self._fin_as_resp)

        if self._exp_srv != self._exp_clnt:  # pragma: no cover
            # no coverage; assert
            print(clnt_msgs)
            print(srv_msgs)
            raise ValueError("For every client query we need a response "
                             "(try FIN as server response)")

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

    def _get_data_from_binary_file(
            self, filename, data_size, convert_to_int=False
        ):
        """
        Iterator. Reading raw bytes of data_size from a binary file. Can also
        convert the data to int.
        """
        with open(filename, "rb") as data_fp:
            data = data_fp.read(data_size)
            while data:
                if convert_to_int:
                    data = bytesToNumber(data, endian=self.endian)
                yield data
                data = data_fp.read(data_size)

    def _get_data_from_csv_file(self, filename, col_name=None,
                                convert_to_float=False, convert_to_int=False):
        """
        Iterator. Reading data from a csv file. Can also convert the data to
        float or to integer.
        """
        if not col_name:
            col_name = self.col_name

        with open(filename, "r") as data_fp:
            reader = csv.reader(data_fp)
            columns = next(reader)
            column = 0

            if len(columns) > 1 and col_name is None:
                raise ValueError("Multiple columns in raw_times file and "
                    "no column name specified!")

            if col_name:
                column = columns.index(col_name)

            for row in reader:
                data = row[column]
                if convert_to_float:
                    data = float(data)
                if convert_to_int:
                    data = int(data)
                yield data

    def _divide_by_frequency(self, value_iter):
        """Iterator. Devides value for given iter by frequency."""
        for value in value_iter:
            yield value / self.frequency

    def _get_time_from_file(self, filename=None):
        """Iterator. Read the times from file provided"""
        if self.binary:
            times_iter = self._get_data_from_binary_file(
                self.raw_times, filename if filename else self.binary,
                convert_to_int=True
            )
        else:
            times_iter = self._get_data_from_csv_file(
                filename if filename else self.raw_times, convert_to_float=True
            )

        if self.frequency:
            times_iter = self._divide_by_frequency(times_iter)

        return times_iter

    def _ecdsa_get_signature_from_file(self, filename=None):
        """Iterator. Read the signatures from file provided"""
        with open(filename if filename else self.sigs, "rb") as sigs_fp:
            sig = sigs_fp.read(1)
            while sig:
                if not ecdsa.der.is_sequence(sig):
                    raise \
                        ValueError("There was an error in parsing signatures.")
                length_bytes = sigs_fp.read(1)
                sig_length = 0
                try:
                    sig_length = ecdsa.der.read_length(length_bytes)[0]
                except ecdsa.UnexpectedDER:
                    length_bytes += sigs_fp.read(1)
                    try:
                        sig_length = ecdsa.der.read_length(length_bytes)[0]
                    except ecdsa.UnexpectedDER:
                        raise \
                            ValueError("Couldn't read size of a signature.")
                sig_data = sigs_fp.read(sig_length)
                if sig_length != len(sig_data):
                    raise \
                        ValueError("Signature file ended unexpectedly.")
                sig += length_bytes + sig_data
                yield sig
                sig = sigs_fp.read(1)

    def _ecdsa_message_to_int(self, filename=None):
        """Iterator. Hashes the message used and converts it to int."""
        data_iter = self._get_data_from_binary_file(
            filename if filename else self.data, self.data_size
        )

        for msg in data_iter:
            if self.hash_func:
                hashed = self.hash_func(msg).digest()
                hashed = hashed[: self.priv_key.curve.baselen]
            else:
                hashed = msg
            number = int.from_bytes(hashed, 'big')
            max_length = ecdsa.util.bit_length(self.priv_key.curve.order)
            length = len(hashed) * 8
            number >>= max(0, length - max_length)
            yield number

    def _ecdsa_calculate_k(self, sig_and_hashed):
        """Iterator. Calculated the K value from a singature."""
        try:
            sig, hashed = sig_and_hashed
        except ValueError:
            raise ValueError(
                "Signature or hash not provided."
            )

        n_value = self.priv_key.curve.order
        g_value = self.priv_key.curve.generator

        r_value, s_value = ecdsa.util.sigdecode_der(
                sig, n_value
            )
        k_value = (
            (hashed + (
                r_value * self.priv_key.privkey.secret_multiplier
            ))
            * ecdsa.ecdsa.numbertheory.inverse_mod(s_value, n_value)
            ) % n_value
        kxg = (k_value * g_value).to_affine().x()

        if kxg == r_value:
            return k_value
        else:
            raise ValueError(
                "Failed to calculate k from given signatures."
                    )

    def _convert_to_bit_size(self, value_iter):
        """Iterator. Convert a value to the bit length of it."""
        for value in value_iter:
            yield ecdsa.util.bit_length(value)

    def _convert_to_hamming_weight(self, value_iter):
        """Iterator. Converts a value to the Hamming weight of it."""
        for value in value_iter:
            yield bit_count(value)

    def _calculate_invert_k(self, value_iter):
        """Iterator. It will calculate the invert K."""
        n_value = self.priv_key.curve.order
        for value in value_iter:
            yield ecdsa.ecdsa.numbertheory.inverse_mod(value, n_value)

    def ecdsa_iter(self, return_type="k-size"):
        """
        Iterator. Iterator to use for signatures signed by ECDSA private key.
        """
        k_map_filename = join(self.output, "ecdsa-k-time-map.csv")
        sigs_iter = self._ecdsa_get_signature_from_file()
        hashed_iter = self._ecdsa_message_to_int()
        times_iter = self._get_time_from_file()

        if not exists(k_map_filename):
            if self.verbose:
                print("[i] Creating ecdsa-k-time-map.csv file...")

            progress = None
            status = [0]
            if self.verbose and self._total_measurements:
                status = [0, self._total_measurements, Event()]
                kwargs = {}
                kwargs['unit'] = ' pairs'
                kwargs['prefix'] = 'decimal'
                kwargs['delay'] = self.delay
                kwargs['end'] = self.carriage_return
                progress = Thread(target=progress_report, args=(status,),
                                kwargs=kwargs)
                progress.start()

            try:
                with (open(k_map_filename, "w") as fp,
                       mp.Pool(self.workers) as pool):
                    k_iter = pool.imap(
                        self._ecdsa_calculate_k,
                        izip(sigs_iter, hashed_iter), 10000
                    )

                    fp.write("k_value,time\n")

                    for k_value, time_value in izip(k_iter, times_iter):
                        fp.write("{0},{1}\n".format(k_value, time_value))
                        status[0] += 1
            finally:
                if progress:
                    status[2].set()
                    progress.join()
                    print()

        k_iter = self._get_data_from_csv_file(
            k_map_filename, col_name="k_value", convert_to_int=True
        )

        if return_type == "k-size":
            k_wrap_iter = self._convert_to_bit_size(k_iter)
        elif return_type == "invert-k-size":
            k_wrap_iter = self._convert_to_bit_size(
                self._calculate_invert_k(k_iter)
            )
        elif return_type == "hamming-weight":
            k_wrap_iter = self._convert_to_hamming_weight(k_iter)
        else:
            raise ValueError(
                "Iterator return must be "
                "k-size, invert-k-size or hamming-weight."
            )

        return k_wrap_iter

    def ecdsa_max_value(self):
        """Returns the max K size depending on the ECDSA private key"""
        return ecdsa.util.bit_length(self.priv_key.curve.order)

    def _create_and_write_line(self):
        """
        Takes multiple possible values for each key value, selecting one
        in random for each key and writes the created line into the
        intermediate file.
        """
        if self._max_value not in self._current_line:
            return

        self._line_to_write = {
            self._max_value: self._current_line[self._max_value]
        }

        final_choices = {}

        # The idea here is that each comparing_value entry will choose
        # randomly if he will pair with a non comparing_value that chose it
        # from before or from after, if it has on both sides value. Finally,
        # if the side has more than one values, it choose one in random.
        for side in ['before', 'after']:
            for size in self._current_line[side]:
                if size not in final_choices:
                    final_choices[size] = {}

                num_of_values = len(self._current_line[side][size])
                if num_of_values == 1:
                    final_choices[size][side] = \
                        self._current_line[side][size][0]
                else:
                    final_choices[size][side] = \
                        choice(self._current_line[side][size])

                    self._measurements_dropped += num_of_values - 1

        for size in final_choices:
            random_choice = choice(['before', 'after'])

            if random_choice not in final_choices[size]:
                if random_choice == 'before':
                    random_choice = 'after'
                else:
                    random_choice = 'before'

            self._line_to_write[size] = final_choices[size][random_choice]
            self._selections[size][random_choice] += 1

        line = ""
        for size in self._line_to_write:
            line += '{0},{1},'.format(
                size, self._line_to_write[size]
            )
        self._intermedian_fp.write(line[:-1] + '\n')

    def _write_selections(self):
        """
        Writes how many times a value was selected, from before or after,
        into a file.
        """
        selections_keys_sorted = sorted(self._selections.keys(), reverse=True)

        with open(
            join(self.output, "selections.csv"), 'w', encoding="utf-8"
        ) as out_fp:
            out_fp.write("value,before,after\n")
            for size in selections_keys_sorted:
                out_fp.write('{0},{1},{2}\n'.format(
                    size,
                    self._selections[size]['before'],
                    self._selections[size]['after']
                ))

    def _append_sanity_to_line(self, data):
        """Appends sanity value into a measurement line."""
        self._measurements_fp.write('{0},{1},{2}\n'.format(
                                self._row, data[0], data[1]
                            ))

    def _create_and_write_sanity_entries(self):
        """
        Reads the intermediate file and adds sanity records to the final
        mesurements file.
        """
        temp_file_path = self._intermedian_fp.name
        self._intermedian_fp.close()
        state = WAIT_FOR_FIRST_BARE_MAX_VALUE
        last_single_max_value = None
        self._row -= 1
        sanity_entries_count = 0

        with open(temp_file_path, "r") as in_fp:
            reader = csv.reader(in_fp)
            for row in reader:
                if len(row) > 2:
                    self._row += 1
                    for i in range(0, len(row), 2):
                        self._measurements_fp.write(
                            '{0},{1},{2}\n'.format(
                                self._row, row[i], row[i + 1]
                            )
                        )

                    if len(row) / 2 > self._max_tuple_size:
                        self._max_tuple_size = len(row) / 2

                if state != WAIT_FOR_SECOND_BARE_MAX_VALUE and len(row) == 2:
                    if state == WAIT_FOR_NON_BARE_MAX_VALUE:
                        self._measurements_dropped += 1

                    last_single_max_value = row.copy()
                    state = WAIT_FOR_NON_BARE_MAX_VALUE
                elif state == WAIT_FOR_NON_BARE_MAX_VALUE and len(row) > 2:
                    state = WAIT_FOR_SECOND_BARE_MAX_VALUE
                elif state == WAIT_FOR_SECOND_BARE_MAX_VALUE and len(row) == 2:
                    random_choice = choice([0, 1])
                    sanity_entries_count += 1

                    if random_choice == 0: # use the one before
                        self._append_sanity_to_line(last_single_max_value)
                        last_single_max_value = row.copy()
                        state = WAIT_FOR_NON_BARE_MAX_VALUE
                    else: # use the one after
                        self._append_sanity_to_line(row)
                        state = WAIT_FOR_FIRST_BARE_MAX_VALUE
                else:
                    if state > WAIT_FOR_FIRST_BARE_MAX_VALUE:
                        self._measurements_dropped += 1

                    state = WAIT_FOR_FIRST_BARE_MAX_VALUE

        remove(temp_file_path)

        if self.verbose:
            print('[i] {0}-bit-sized sanity entries: {1:,}'.format(
                self._max_value, sanity_entries_count
            ))

    def _check_for_iter_left_overs(self, iterator, desc=''):
        left_overs = []
        for item in iterator:
            left_overs.append(item)
        if len(left_overs) > 0 and self.verbose:
            if desc:
                print(desc)
            else:
                print("Left-overs on iterator:")
            for item in left_overs:
                print(item)

            raise ValueError("There are some extra values that are not used.")

    def process_measurements_and_create_csv_file(
            self, values_iter, comparing_value
            ):
        """
        Processing all the measurements from the given files and
        creates a randomized measurement file with tuples associating
        the max values with non max values.
        """
        self._measurements_fp = open(
            join(self.output, self.measurements_csv), "w"
        )
        self._intermedian_fp = tempfile.NamedTemporaryFile(
            mode="w", delete=False
        )
        self._current_line = {
            "before": {}
        }
        self._next_line = None
        self._line_to_write = {}
        self._max_tuple_size = 0
        self._measurements_dropped = 0
        self._selections = defaultdict(lambda: defaultdict(lambda: 0))
        self._row = 0
        self._max_value = comparing_value

        time_iter = self._get_time_from_file()

        if self.verbose:
            print("[i] Creating {0} file...".format(self.measurements_csv))

        progress = None
        status = [0]
        if self.verbose and self._total_measurements:
            status = [0, self._total_measurements, Event()]
            kwargs = {}
            kwargs['unit'] = ' signatures'
            kwargs['prefix'] = 'decimal'
            kwargs['delay'] = self.delay
            kwargs['end'] = self.carriage_return
            progress = Thread(target=progress_report, args=(status,),
                            kwargs=kwargs)
            progress.start()

        try:
            for value, time_value in izip(values_iter, time_iter):
                status[0] += 1

                # The idea here is that every value != comparing_value chooses
                # randomly to pair with the comparing_value before or with
                # the one after
                if value == comparing_value:
                    if self._next_line is None:
                        self._current_line[value] = time_value
                        self._current_line['after'] = {}
                        self._next_line = {
                            'before': {}
                        }
                    else:
                        self._create_and_write_line()

                        self._current_line = self._next_line
                        self._current_line[value] = time_value
                        self._current_line['after'] = {}
                        self._next_line = {
                            'before': {}
                        }
                else:
                    if self._next_line is not None:
                        random_choice = choice([0, 1])
                        if random_choice == 0:
                            line = self._current_line
                        else:
                            line = self._next_line
                    else:
                        line = self._current_line

                    if "after" in line:
                        stage = "after"
                    else:
                        stage = "before"

                    if value not in line[stage]:
                        line[stage][value] = []

                    line[stage][value].append(time_value)

            if self._next_line:
                for size in self._next_line["before"]:
                    self._measurements_dropped += \
                        len(self._next_line["before"][size])

            self._create_and_write_line()

            self._write_selections()
        finally:
            if progress:
                status[2].set()
                progress.join()
                print()

        self._check_for_iter_left_overs(
            values_iter, "Left over values in measurements"
        )

        self._check_for_iter_left_overs(
            time_iter, "Left over times in measurements"
        )

        self._create_and_write_sanity_entries()

        if self.verbose:
            if self._total_measurements:
                print(
                    '[i] Measurements that have been dropped: {0:,} ({1:.2f}%)'
                    .format(
                        self._measurements_dropped,
                        (self._measurements_dropped * 100)
                        / self._total_measurements
                    )
                )
            print(
                '[i] Biggest tuple size in file: {0}\n'
                    .format(int(self._max_tuple_size)) +
                '[i] Written rows: {0:,}'.format(self._row)
            )

        self._measurements_fp.close()

    def process_and_create_multiple_csv_files(self, files = {
        "measurements.csv": "k-size"
    }):
        original_measuremments_csv = self.measurements_csv

        if exists(join(self.output, "ecdsa-k-time-map.csv")):
            remove(join(self.output, "ecdsa-k-time-map.csv"))

        for file in files:
            self.measurements_csv = file

            self.process_measurements_and_create_csv_file(
                self.ecdsa_iter(return_type=files[file]), self.ecdsa_max_value()
            )

        self.measurements_csv = original_measuremments_csv

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
