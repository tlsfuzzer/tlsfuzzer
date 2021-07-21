# Author: Hubert Kario, (c) 2015-2019
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        pad_handshake, split_message, FlushMessageList, \
        TCPBufferingEnable, TCPBufferingDisable, TCPBufferingFlush
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, ExpectNoMessage
from tlsfuzzer.utils.lists import natural_sort_keys

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType


version = 5


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (\"sanity\" tests are always executed)")
    print(" --help         this message")


def main():

    #
    # Test if client hello with garbage at the end gets rejected
    #

    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
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

    # sanity check
    conversation = Connect(host, port)
    node = conversation
    ext = {ExtensionType.renegotiation_info: None}
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
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
    conversations["sanity"] = conversation

    # test if server doesn't interpret extensions past extensions length
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(pad_handshake(ClientHelloGenerator(ciphers,
                                               extensions={}),
                                        # empty renegotiation info
                                        pad=bytearray(b'\xff\x01\x00\x01\x00')))
    # responding to a malformed client hello is not correct, but tested below
    node = node.add_child(ExpectServerHello(extensions={}))
    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.decode_error)
    node.next_sibling.add_child(ExpectClose())

    conversations["extension past extensions"] = conversation


    for name, pad_len, pad_byte in [
                                ("small pad", 1, 0),
                                ("small pad", 2, 0),
                                ("small pad", 3, 0),
                                ("small pad", 1, 0xff),
                                ("small pad", 2, 0xff),
                                ("small pad", 3, 0xff),
                                ("medium pad", 256, 0),
                                ("large pad", 4096, 0),
                                ("big pad", 2**16, 0),
                                ("huge pad", 2**17+512, 0),
                                ("max pad", 2**24-1-48, 0),
                                ("small truncate", -1, 0),
                                ("small truncate", -2, 0),
                                ("small truncate", -3, 0),
                                ("small truncate", -4, 0),
                                ("small truncate", -5, 0),
                                ("small truncate", -6, 0),
                                # 7 bytes truncates whole 'extensions' creating
                                # a valid message
                                #("small truncate", -7, 0),
                                ("hello truncate", -8, 0),
                                ("hello truncate", -9, 0),
                                ("hello truncate", -10, 0),
                                ("hello truncate", -11, 0),
                                ("hello truncate", -12, 0),
                                ("hello truncate", -13, 0),
                                ("hello truncate", -32, 0),
                                ("hello truncate", -39, 0),
                                # truncate so that only one byte...
                                ("hello truncate", -47, 0),
                                # ...or no message remains
                                ("full message truncate", -48, 0)
                                ]:

        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]

        msg = pad_handshake(ClientHelloGenerator(ciphers,
                                                 extensions={ExtensionType.renegotiation_info: None}),
                            pad_len, pad_byte)
        fragments = []
        node = node.add_child(split_message(msg, fragments, 2**14))
        node = node.add_child(ExpectNoMessage())
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                         AlertDescription.decode_error)
        node.next_sibling.add_child(ExpectClose())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(FlushMessageList(fragments))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decode_error))
        node.add_child(ExpectClose())

        if "pad" in name:
            conversations[name + ": " + str(pad_len) + " of \"" + str(pad_byte) +
                          "\" byte padding"] = conversation
        else:
            conversations[name + ": " + str(-pad_len) +
                          " of bytes truncated"] = conversation

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
                if expected_failures[c_name] is not None and  \
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

    print("Check if ClientHello length checking is correct in server")

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + 2*len(sanity_tests)))
    print("SKIP: {0}".format(len(run_exclude.intersection(conversations.keys()))))
    print("PASS: {0}".format(good))
    print("XFAIL: {0}".format(xfail))
    print("FAIL: {0}".format(bad))
    print("XPASS: {0}".format(xpass))
    print(20 * '=')
    sort = sorted(xpassed ,key=natural_sort_keys)
    if len(sort):
        print("XPASSED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))
    sort = sorted(failed, key=natural_sort_keys)
    if len(sort):
        print("FAILED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))

    if bad or xpass:
        sys.exit(1)

if __name__ == "__main__":
    main()
