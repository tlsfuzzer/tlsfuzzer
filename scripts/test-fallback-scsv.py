# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
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
    print(" --help         this message")


def main():
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

    ext = {ExtensionType.renegotiation_info: None}
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3)))
    node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
    ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
               CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               ]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2)))
    node = node.add_child(ExpectServerHello(version=(3, 2), extensions=ext))
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
    conversations["sanity - TLSv1.1"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
               CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 4)))
    node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
    conversations["sanity - SSL3.4 version negotiation"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
               CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3)))
    node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
    conversations["record TLSv1.2 hello TLSv1.2"] = conversation

    conversation = Connect(host, port, version=(3, 2))
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2)))
    node = node.add_child(ExpectServerHello(version=(3, 2), extensions=ext))
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
    conversations["record TLSv1.1 hello TLSv1.1"] = conversation

    conversation = Connect(host, port, version=(3, 4))
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 4)))
    node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
    conversations["record SSL3.4 hello SSL3.4"] = conversation

    # test with FALLBACK_SCSV
    for place in (0, 1, 2):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3)))
        node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
        conversations["FALLBACK - hello TLSv1.2 - pos {0}".format(place)] = conversation

        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2)))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.inappropriate_fallback))
        node = node.add_child(ExpectClose())
        conversations["FALLBACK - hello TLSv1.1 - pos {0}".format(place)] = conversation

        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 4)))
        node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
        conversations["FALLBACK - hello SSL3.4 - pos {0}".format(place)] = conversation

        conversation = Connect(host, port, version=(3, 3))
        node = conversation
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3)))
        node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
        conversations["FALLBACK - record TLSv1.2 hello TLSv1.2 - pos {0}".format(place)] = conversation

        conversation = Connect(host, port, version=(3, 2))
        node = conversation
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2)))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.inappropriate_fallback))
        node = node.add_child(ExpectClose())
        conversations["FALLBACK - record TLSv1.1 hello TLSv1.1 - pos {0}".format(place)] = conversation

        conversation = Connect(host, port, version=(3, 4))
        node = conversation
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 4)))
        node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
        conversations["FALLBACK - record SSL3.4 hello SSL3.4 - pos {0}".format(place)] = conversation


    # run the conversation
    good = 0
    bad = 0
    failed = []

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throught
    sanity_test = ('sanity', conversations['sanity'])
    ordered_tests = chain([sanity_test],
                          filter(lambda x: x[0] != 'sanity',
                                 conversations.items()),
                          [sanity_test])

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
