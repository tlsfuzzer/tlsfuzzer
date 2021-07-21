# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Test for DHE_RSA key exchange error handling"""

from __future__ import print_function
import traceback
import sys
import getopt
from random import sample
import re
from itertools import chain

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        truncate_handshake, TCPBufferingEnable, TCPBufferingDisable, \
        TCPBufferingFlush, pad_handshake
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectServerKeyExchange, \
        ExpectApplicationData

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import RSA_SIG_ALL


version = 4


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
    print(" -a alert       numerical value of the expected alert for messages")
    print("                with publicly invalid client key shares,")
    print("                47 (illegal_parameter) by default")
    print(" --help         this message")



def main():
    """Test if server correctly handles malformed DHE_RSA CKE messages"""
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    alert = AlertDescription.illegal_parameter

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:x:X:a:", ["help"])
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
        elif opt == "-a":
            alert = int(arg)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None


    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.renegotiation_info] = None
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                     renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
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

    # invalid dh_Yc value
    #for i in [2*1024, 4*1024, 8*1024, 16*1024]:
    for i in [8*1024]:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        ext[ExtensionType.renegotiation_info] = None
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                         renegotiation_info:None}))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(dh_Yc=2**(i)))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          alert))
        node = node.add_child(ExpectClose())

        conversations["invalid dh_Yc value - " + str(i) + "b"] = conversation

    for i in [0, 1]:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        ext[ExtensionType.renegotiation_info] = None
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                         renegotiation_info:None}))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(dh_Yc=i))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          alert))
        node = node.add_child(ExpectClose())

        conversations["invalid dh_Yc value - {0}".format(i)] = conversation

    # share equal to p
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.renegotiation_info] = None
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                     renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(p_as_share=True))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      alert))
    node = node.add_child(ExpectClose())

    conversations["invalid dh_Yc value - p"] = conversation

    # share equal to p-1
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.renegotiation_info] = None
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                     renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(p_1_as_share=True))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      alert))
    node = node.add_child(ExpectClose())

    conversations["invalid dh_Yc value - p-1"] = conversation

    # truncated dh_Yc value
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.renegotiation_info] = None
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                     renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(truncate_handshake(ClientKeyExchangeGenerator(),
                                             1))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())

    conversations["truncated dh_Yc value"] = conversation

    # padded Client Key Exchange
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.renegotiation_info] = None
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.
                                                     renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(pad_handshake(ClientKeyExchangeGenerator(),
                                             1))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())

    conversations["padded Client Key Exchange"] = conversation

    # run the conversations
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

    print("Check if server properly verifies received Client Key Exchange")
    print("message. That the extra data (pad) at the end is noticed, that")
    print("too short message is rejected and a message with \"obviously\"")
    print("wrong client key share is rejected")

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
