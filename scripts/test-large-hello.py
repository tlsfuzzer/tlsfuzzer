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
        split_message, FlushMessageList
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType
from tlslite.extensions import PaddingExtension, TLSExtension
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
    print(" -m min-ext-no  the minimum extension number to use (default=52)")
    print("                (the test uses random extensions past this number)")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    min_ext = 52
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:m:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-m':
            min_ext = int(arg)
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
    node = node.add_child(ExpectClose())
    conversations["sanity"] = conversation

    # send client hello with large padding extension
    for i in chain(range(10), range(0x3f00, 0x4010), range(0x1ff0, 0x2010),
                   range(0x8ff0, 0x9010), range(0xff00, 0xffff-4)):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {ExtensionType.client_hello_padding:PaddingExtension().create(i)}
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
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
        node = node.add_child(ExpectClose())
        conversations["ext padding, {0} bytes".format(i)] = conversation

    # send large extension from unallocated range
    for i in chain(range(10), range(0x3f00, 0x4010), range(0x1ff0, 0x2010),
                   range(0x8ff0, 0x9010), range(0xff00, 0xffff-4)):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {80:TLSExtension(extType=80).create(bytearray(i))}
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
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
        node = node.add_child(ExpectClose())
        conversations["ext #80, {0} bytes".format(i)] = conversation

    # send two extensions, where one is large (4096) and the other is
    # changing size
    for i in chain(range(10), range(0x2f00, 0x3010),
                   range(0x3f00, 0x4010), range(0x1ff0, 0x2010),
                   range(0x8ff0, 0x9010), range(0xef00, 0xefff-8)):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {80:TLSExtension(extType=80).create(bytearray(i)),
               ExtensionType.client_hello_padding:
                   PaddingExtension().create(0x1000)}
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
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
        node = node.add_child(ExpectClose())
        conversations["two ext, #80 {0} bytes".format(i)] = conversation

    # send client hello messages with multiple extensions
    for i in chain(range(10//4), range(0x3f00//4, 0x4010//4),
                   range(0x1ff0//4, 0x2010//4),
                   range(0x8ff0//4, 0x9010//4), range(0xff00//4, 0x10000//4)):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        high_num_ext = (ExtensionType.supports_npn,
                        ExtensionType.tack,
                        ExtensionType.renegotiation_info)
        # increase the count if some extension points will be skipped because
        # they are meaningful
        for num in high_num_ext:
            if i+min_ext > num:
                i+=1
        ext = dict((j, TLSExtension(extType=j))
                    for j in range(min_ext, min_ext+i)
                    if j not in high_num_ext)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
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
        node = node.add_child(ExpectClose())
        conversations["multiple extensions {0}".format(i)] = conversation

    # send client hello with large number of ciphersuites but overall
    # even length
    for i in chain(range(1, 10//2), range(0x3f00//2, 0x4010//2),
                   range(0x1ff0//2, 0x2010//2),
                   range(0x8ff0//2, 0x9010//2), range(0xff00//2, 0xffff//2-2)):
        conversation = Connect(host, port)
        node = conversation
        if i < 0x5600 - 0x0100:
            ciphers = list(range(0x0100, 0x0100 + i))
        else:
            ciphers = list(range(0x0100, 0x5600))
            i -= 0x5600 - 0x0100
            ciphers += list(range(0x5601, 0x5601 + i))
        ciphers += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        node = node.add_child(ClientHelloGenerator(ciphers))
        node = node.add_child(ExpectServerHello())
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
        node = node.add_child(ExpectClose())
        conversations["ciphers even {0}".format(i)] = conversation

    # send client hello with large number of ciphersuites but overall
    # odd length
    for i in chain(range(1, 10//2), range(0x3f00//2, 0x4010//2),
                   range(0x1ff0//2, 0x2010//2),
                   range(0x8ff0//2, 0x9010//2), range(0xff00//2, 0xffff//2-2)):
        conversation = Connect(host, port)
        node = conversation
        if i < 0x5600 - 0x0100:
            ciphers = list(range(0x0100, 0x0100 + i))
        else:
            ciphers = list(range(0x0100, 0x5600))
            i -= 0x5600 - 0x0100
            ciphers += list(range(0x5601, 0x5601 + i))
        ext = {ExtensionType.client_hello_padding:
                   PaddingExtension().create(1)}
        ciphers += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello())
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
        node = node.add_child(ExpectClose())
        conversations["ciphers odd {0}".format(i)] = conversation

    # hello split over at least two records, first very small (2B)
    for i in chain(range(10), range(0x3f00, 0x4010), range(0x1ff0, 0x2010),
                   range(0x8ff0, 0x9010), range(0xff00, 0xffff-4)):
        fragment_list = []
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {ExtensionType.client_hello_padding:PaddingExtension().create(i)}
        hello_gen = ClientHelloGenerator(ciphers, extensions=ext)
        node = node.add_child(split_message(hello_gen, fragment_list, 2))
        node = node.add_child(FlushMessageList(fragment_list))
        node = node.add_child(ExpectServerHello())
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
        node = node.add_child(ExpectClose())
        conversations["fragmented, padding ext {0} bytes".format(i)] = conversation

    # sanity check fragmentation
    fragment_list = []
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    hello_gen = ClientHelloGenerator(ciphers)
    node = node.add_child(split_message(hello_gen, fragment_list, 2))
    node = node.add_child(FlushMessageList(fragment_list))
    node = node.add_child(ExpectServerHello())
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
    node = node.add_child(ExpectClose())
    conversations["sanity check - fragmented"] = conversation

    # test with ciphers and extensions filled to the brim
    conversation = Connect(host, port)
    node = conversation
    i = 0xfffe // 2 - 2  # two ciphers are constant
    if i < 0x5600 - 0x0100:
        ciphers = list(range(0x0100, 0x0100 + i))
    else:
        ciphers = list(range(0x0100, 0x5600))
        i -= 0x5600 - 0x0100
        ciphers += list(range(0x5601, 0x5601 + i))
    ciphers += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    # the 4 bytes subtracted from 0xffff are for ext ID and ext len
    ext = {80:TLSExtension(extType=80).create(bytearray(0xffff-4))}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
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
    node = node.add_child(ExpectClose())
    conversations["huge hello"] = conversation

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
