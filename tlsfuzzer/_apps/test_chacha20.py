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
        fuzz_encrypted_message, PlaintextMessageGenerator, SetMaxRecordSize
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ContentType, ExtensionType, GroupName
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import SIG_ALL


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(50)")
    print("                (excluding \"sanity\" tests)")
    print(" --extra-exts   Send extensions to indicate support for SHA-2 and specific curves")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = 50
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    extra_exts = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:", ["help", "extra-exts"])
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
        elif opt == '--extra-exts':
            extra_exts = True
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
    if not extra_exts:
        exts = None
    else:
        exts = {}
        exts[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create([GroupName.secp256r1, GroupName.ffdhe2048,
                     GroupName.x25519])
        exts[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        exts[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)

    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=exts))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # reject ciphers in TLS1.1
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2),
                                               extensions=exts))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.handshake_failure))
    node.add_child(ExpectClose())
    conversations["Chacha20 in TLS1.1"] = conversation

    # empty application data message acceptance
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=exts))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray()))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    conversations["empty app data"] = conversation

    # 1/n-1 message splitting
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=exts))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"G")))
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"ET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    conversations["1/n-1 record splitting"] = conversation

    # plaintext just under the maximum permissible
    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(SetMaxRecordSize(2**16-1))
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=exts))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    data = bytearray(b"GET / HTTP/1.0\r\n" +
                     b"X-test: " + b"A" * (2**14 - 28) +
                     b"\r\n\r\n")
    assert len(data) == 2**14
    node = node.add_child(ApplicationDataGenerator(data))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    # allow for multiple application data records in response
    node = node.add_child(ExpectApplicationData())
    loop = node
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    loop.next_sibling = node
    node.next_sibling = ExpectClose()
    conversations["max size plaintext"] = conversation

    # plaintext over the maximum permissible
    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(SetMaxRecordSize(2**16-1))
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=exts))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    data = bytearray(b"GET / HTTP/1.0\r\n" +
                     b"X-test: " + b"A" * (2**14 - 28 + 1) +
                     b"\r\n\r\n")
    assert len(data) == 2**14 + 1
    node = node.add_child(ApplicationDataGenerator(data))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      [AlertDescription.decompression_failure,
                                       AlertDescription.record_overflow]))
    node.add_child(ExpectClose())
    conversations["too big plaintext"] = conversation

    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(SetMaxRecordSize(2**16-1))
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=exts))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    data = bytearray(b"GET / HTTP/1.0\r\n" +
                     b"X-test: " + b"A" * (2**14 + 1024 - 28) +
                     b"\r\n\r\n")
    assert len(data) == 2**14 + 1024
    node = node.add_child(ApplicationDataGenerator(data))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      [AlertDescription.decompression_failure,
                                       AlertDescription.record_overflow]))
    node.add_child(ExpectClose())
    conversations["too big plaintext - max compress"] = conversation

    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(SetMaxRecordSize(2**16-1))
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=exts))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    data = bytearray(b"GET / HTTP/1.0\r\n" +
                     b"X-test: " + b"A" * (2**14 + 1024 - 28 + 1) +
                     b"\r\n\r\n")
    assert len(data) == 2**14 + 1024 + 1
    node = node.add_child(ApplicationDataGenerator(data))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.record_overflow))
    node.add_child(ExpectClose())
    conversations["too big plaintext - above TLSCompressed max"] = conversation


    # fuzz the tag (16 last bytes)
    for val in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        for pos in range(-1, -17, -1):
            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                       CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       extensions=exts))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectServerKeyExchange())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(ClientKeyExchangeGenerator())
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectFinished())
            msg = ApplicationDataGenerator(
                    bytearray(b"GET / HTTP/1.0\r\n\r\n"))
            node = node.add_child(fuzz_encrypted_message(msg, xors={pos:val}))
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_record_mac))
            node.add_child(ExpectClose())
            conversations["fuzz tag with {0} on pos {1}".format(val, pos)] \
                    = conversation

    # too small message handling
    for val in range(16):
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                   CipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=exts))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        # any byte value will do, a1 chosen at random
        msg = PlaintextMessageGenerator(ContentType.application_data,
                                        bytearray([0xa1]*val))
        node = node.add_child(msg)
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())
        conversations["{0} bytes long ciphertext".format(val)] \
                = conversation

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
    run_sanity = True
    if run_only:
        if len(run_only) == 1 and 'sanity' in run_only:
            run_sanity = False
            regular_tests = sanity_tests
        else:
            if not 'sanity' in run_only:
                run_sanity = False
            regular_tests = [(k, v) for k, v in conversations.items() if
                             k in run_only and (k != 'sanity')]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    if run_sanity:
        ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)
    else:
        ordered_tests = sampled_tests

    for c_name, c_test in ordered_tests:
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

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    if run_sanity:
        print("TOTAL: {0}".format(len(sampled_tests) + 2 * len(sanity_tests)))
    else:
        print("TOTAL: {0}".format(len(sampled_tests)))
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
