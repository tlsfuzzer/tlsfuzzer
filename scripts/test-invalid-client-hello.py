# Author: Hubert Kario, (c) 2016
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
        fuzz_message
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType


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
    print(" -n num         only run `num` random tests instead of a full set")
    print("                (excluding \"sanity\" tests)")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
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
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3)))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity w/ext"] = conversation

    # test different message types for client hello
    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        hello_gen = ClientHelloGenerator(ciphers, version=(3, 3))
        node = node.add_child(fuzz_message(hello_gen, xors={0: i}))
        node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                          description=AlertDescription.unexpected_message))
        node = node.add_child(ExpectClose())
        conversations["Client Hello type fuzz to {0}".format(1 ^ i)] = conversation


    # test invalid sizes for session ID length
    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        hello_gen = ClientHelloGenerator(ciphers, version=(3, 3))
        node = node.add_child(fuzz_message(hello_gen, substitutions={38: i}))
        node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                          description=AlertDescription.decode_error))
        node = node.add_child(ExpectClose())
        conversations["session ID len fuzz to {0}".format(i)] = conversation

    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ext = {ExtensionType.renegotiation_info: None}
        hello_gen = ClientHelloGenerator(ciphers, version=(3, 3),
                                         extensions=ext)
        node = node.add_child(fuzz_message(hello_gen, substitutions={38: i}))
        node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                          description=AlertDescription.decode_error))
        node = node.add_child(ExpectClose())
        conversations["session ID len fuzz to {0} w/ext".format(i)] = conversation


    # test invalid sizes for cipher suites length
    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        hello_gen = ClientHelloGenerator(ciphers, version=(3, 3))
        node = node.add_child(fuzz_message(hello_gen, xors={40: i}))
        node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                          description=AlertDescription.decode_error))
        node = node.add_child(ExpectClose())
        conversations["cipher suites len fuzz to {0}".format(4 ^ i)] = conversation

    for i in (1, 2, 4, 8, 16, 128, 254, 255):
        for j in range(0, 0x100):
            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            hello_gen = ClientHelloGenerator(ciphers, version=(3, 3))
            node = node.add_child(fuzz_message(hello_gen, substitutions={39: i, 40: j}))
            node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                              description=AlertDescription.decode_error))
            node = node.add_child(ExpectClose())
            conversations["cipher suites len fuzz to {0}".format((i<<8) + j)] = conversation

    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ext = {ExtensionType.renegotiation_info: None}
        hello_gen = ClientHelloGenerator(ciphers, version=(3, 3),
                                         extensions=ext)
        node = node.add_child(fuzz_message(hello_gen, xors={40: i}))
        node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                          description=AlertDescription.decode_error))
        node = node.add_child(ExpectClose())
        conversations["cipher suites len fuzz to {0} w/ext".format(4 ^ i)] = conversation

    for i in (1, 2, 4, 8, 16, 128, 254, 255):
        for j in range(0, 0x100):
            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
            ext = {ExtensionType.renegotiation_info: None}
            hello_gen = ClientHelloGenerator(ciphers, version=(3, 3),
                                             extensions=ext)
            node = node.add_child(fuzz_message(hello_gen, substitutions={39: i, 40: j}))
            node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                              description=AlertDescription.decode_error))
            node = node.add_child(ExpectClose())
            conversations["cipher suites len fuzz to {0} w/ext".format((i<<8) + j)] = conversation

    # test invalid sizes for compression methods
    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        hello_gen = ClientHelloGenerator(ciphers, version=(3, 3))
        node = node.add_child(fuzz_message(hello_gen, xors={45: i}))
        node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                          description=AlertDescription.decode_error))
        node = node.add_child(ExpectClose())
        conversations["compression methods len fuzz to {0}".format(1 ^ i)] = conversation

    for i in range(1, 0x100):
        if 1 ^ i == 8:  # this length creates a valid extension-less hello
            continue
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ext = {ExtensionType.renegotiation_info: None}
        hello_gen = ClientHelloGenerator(ciphers, version=(3, 3),
                                         extensions=ext)
        node = node.add_child(fuzz_message(hello_gen, xors={43: i}))
        node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                          description=AlertDescription.decode_error))
        node = node.add_child(ExpectClose())
        conversations["compression methods len fuzz to {0} w/ext".format(1 ^ i)] = conversation

    # test invalid sizes for extensions
    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ext = {ExtensionType.renegotiation_info: None}
        hello_gen = ClientHelloGenerator(ciphers, version=(3, 3),
                                         extensions=ext)
        node = node.add_child(fuzz_message(hello_gen, xors={46: i}))
        node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                          description=AlertDescription.decode_error))
        node = node.add_child(ExpectClose())
        conversations["extensions len fuzz to {0}".format(5 ^ i)] = conversation

    for i in (1, 2, 4, 8, 16, 254, 255):
        for j in range(0, 0x100):
            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
            ext = {ExtensionType.renegotiation_info: None}
            hello_gen = ClientHelloGenerator(ciphers, version=(3, 3),
                                             extensions=ext)
            node = node.add_child(fuzz_message(hello_gen, substitutions={45: i, 46: j}))
            node = node.add_child(ExpectAlert(level=AlertLevel.fatal,
                                              description=AlertDescription.decode_error))
            node = node.add_child(ExpectClose())
            conversations["extensions len fuzz to {0}".format((i<<8)+j)] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

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
