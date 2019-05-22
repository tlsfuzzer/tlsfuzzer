# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ResetHandshakeHashes, SetMaxRecordSize
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType
from tlslite.extensions import TLSExtension

def natural_sort_keys(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(_nsre, s)]


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" --help         this message")

def main():
    #
    # Test if server can handle handshake protocol messages fragmented over
    # multiple records
    #

    host = "localhost"
    port = 4433
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {21: TLSExtension().create(21, bytearray(10))}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["sanity"] = conversation

    # 2**14-49 - max size of Client Hello for OpenSSL
    # 2**16-5 - max size of extensions in TLS
    # 2**14-52 - min size of extension that will cause the message to be
    #            fragmented over multiple records
    #
    # note: None for record_len will cause the limit to be set to protocol
    # maximum - 2**14

    for name, ext_len, record_len in [
                                ("small hello", 20, None),
                                ("medium hello", 1024, None),
                                ("medium hello, pow2 fragmentation", 1024, 127),
                                ("medium hello, pow2 fragmentation", 1024, 128),
                                ("medium hello, pow2 fragmentation", 1024, 128),
                                ("medium hello, pow2 fragmentation", 1024, 255),
                                ("medium hello, pow2 fragmentation", 1024, 256),
                                ("medium hello, pow2 fragmentation", 1024, 257),
                                ("big, non fragmented", 2**12, None),
                                ("big, needs fragmentation", 2**14-49, None),
                                ("big, needs fragmentation", 2**14-48, None),
                                ("big, needs fragmentation", 2**15, None),
                                ("maximum size", 2**16-5, None),
                                ("small, reasonable fragmentation", 20, 1024),
                                ("medium, reasonable fragmentation", 1024, 1024),
                                ("big, reasonable fragmentation", 2**12, 1024),
                                ("small, excessive fragmentation", 20, 20),
                                ("medium, excessive fragmentation", 1024, 20),
                                ("big, excessive fragmentation", 2**12, 20),
                                ("small, maximum fragmentation", 20, 1),
                                ("medium, maximum fragmentation", 1024, 1),
                                ("maximum size without fragmentation", 2**14-53, None)]:

        conversation = Connect(host, port)
        node = conversation
        node = node.add_child(SetMaxRecordSize(record_len))
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {21: TLSExtension().create(21, bytearray(ext_len))}
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        # XXX RFCs do NOT consider Alerts special with regards to fragmentation
        node = node.add_child(SetMaxRecordSize(2))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()

        if record_len is None:
            record_len = "max"
        conversations[name + ": " + str(record_len) + " fragment - " +
                      str(ext_len) + "B extension"] = conversation

    # check if records bigger than TLSPlaintext limit are rejected
    padding_extension = TLSExtension().create(21, bytearray(2**14-52))

    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(SetMaxRecordSize(2**16-1))
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={21: padding_extension}))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["non fragmented, over fragmentation limit: " + str(2**16-1) +
                  " fragment - " + str(2**14-52) + "B extension"] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
    shuffled_tests = sample(regular_tests, len(regular_tests))
    ordered_tests = chain(sanity_tests, shuffled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
