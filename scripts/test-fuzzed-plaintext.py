# Author: Hubert Kario, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Example MAC value fuzzer"""

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain, islice

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        fuzz_padding, CertificateGenerator, replace_plaintext, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData
from tlsfuzzer.fuzzers import structured_random_iter

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription
from tlsfuzzer.utils.lists import natural_sort_keys


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
    """check if incorrect padding is rejected by server"""
    host = "localhost"
    port = 4433
    num_limit = 800
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
    node = node.add_child(ClientHelloGenerator(ciphers))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateRequest())
    fork = node
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator())

    # handle servers which ask for client certificates
    fork.next_sibling = ExpectServerHelloDone()
    join = ClientKeyExchangeGenerator()
    fork.next_sibling.add_child(join)

    node = node.add_child(join)
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(
        ApplicationDataGenerator(b"GET / HTTP/1.0\r\n\r\n"))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity"] = \
            conversation

    # block size is 16 bytes for AES_128, 2**14 is the TLS protocol max
    for data in structured_random_iter(num_limit, min_length=16,
                                       max_length=2**14,
                                       step=16):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateRequest())
        fork = node
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(CertificateGenerator())

        # handle servers which ask for client certificates
        fork.next_sibling = ExpectServerHelloDone()
        join = ClientKeyExchangeGenerator()
        fork.next_sibling.add_child(join)

        node = node.add_child(join)
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(replace_plaintext(
            ApplicationDataGenerator(b"I'm ignored, only type is important"),
            data.data))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
#        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())

        conversations["encrypted plaintext of {0}".format(data)] = \
                conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throught
    sanity_test = ('sanity', conversations['sanity'])
    ordered_tests = chain([sanity_test],
                          islice(filter(lambda x: x[0] != 'sanity',
                                        conversations.items()), num_limit),
                          [sanity_test])

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except Exception:
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
