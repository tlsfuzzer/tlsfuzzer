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
from tlsfuzzer.utils.lists import natural_sort_keys

version = 2


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" --help         this message")


def main():
    #
    # Test if server can handle handshake protocol messages fragmented over
    # multiple records
    #

    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:x:X:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
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
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info: None}))
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
        ("big, non fragmented", 2 ** 12, None),
        ("big, needs fragmentation", 2 ** 14 - 49, None),
        ("big, needs fragmentation", 2 ** 14 - 48, None),
        ("big, needs fragmentation", 2 ** 15, None),
        ("maximum size", 2 ** 16 - 5, None),
        ("small, reasonable fragmentation", 20, 1024),
        ("medium, reasonable fragmentation", 1024, 1024),
        ("big, reasonable fragmentation", 2 ** 12, 1024),
        ("small, excessive fragmentation", 20, 20),
        ("medium, excessive fragmentation", 1024, 20),
        ("big, excessive fragmentation", 2 ** 12, 20),
        ("small, maximum fragmentation", 20, 1),
        ("medium, maximum fragmentation", 1024, 1),
        ("maximum size without fragmentation", 2 ** 14 - 53, None)]:

        conversation = Connect(host, port)
        node = conversation
        node = node.add_child(SetMaxRecordSize(record_len))
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {21: TLSExtension().create(21, bytearray(ext_len))}
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info: None}))
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
    padding_extension = TLSExtension().create(21, bytearray(2 ** 14 - 52))

    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(SetMaxRecordSize(2 ** 16 - 1))
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={21: padding_extension}))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["non fragmented, over fragmentation limit: " + str(2 ** 16 - 1) +
                  " fragment - " + str(2 ** 14 - 52) + "B extension"] = conversation

    # run the conversation
    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    if run_only:
        if num_limit > len(run_only):
            num_limit = len(run_only)
        regular_tests = [(k, v) for k, v in conversations.items() if
                         k in run_only]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        exception = None
        try:
            runner.run()
        except Exception as exp:
            exception = exp
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if c_name in expected_failures:
            if res:
                xpass += 1
                xpassed.append(c_name)
                print("XPASS-expected failure but test passed\n")
            else:
                if expected_failures[c_name] is not None and \
                        expected_failures[c_name] not in str(exception):
                    bad += 1
                    failed.append(c_name)
                    print("Expected error message: {0}\n"
                          .format(expected_failures[c_name]))
                else:
                    xfail += 1
                    print("OK-expected failure\n")
        else:
            if res:
                good += 1
                print("OK\n")
            else:
                bad += 1
                failed.append(c_name)

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + 2 * len(sanity_tests)))
    print("SKIP: {0}".format(len(run_exclude.intersection(conversations.keys()))))
    print("PASS: {0}".format(good))
    print("XFAIL: {0}".format(xfail))
    print("FAIL: {0}".format(bad))
    print("XPASS: {0}".format(xpass))
    print(20 * '=')
    sort = sorted(xpassed, key=natural_sort_keys)
    if len(sort):
        print("XPASSED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))
    sort = sorted(failed, key=natural_sort_keys)
    if len(sort):
        print("FAILED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))

    if bad > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
