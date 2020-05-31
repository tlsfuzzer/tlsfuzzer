# Author: Hubert Kario, (c) 2015-2018
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Tests for Lucky 13 vulnerabilities and related conditions"""

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.timing_runner import TimingRunner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
    ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
    FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
    fuzz_mac, fuzz_padding
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
    ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
    ExpectAlert, ExpectApplicationData, ExpectClose, \
    ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
    GroupName, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, \
    SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import SIG_ALL

version = 1


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
    print(" -n num         only run `num` random tests instead of a full set")
    print("                (\"sanity\" tests are always executed)")
    print(" -i interface   Allows recording timing information on")
    print("                on specified interface. Required to enable timing tests")
    print(" -o dir         Specifies output directory for timing information")
    print("                /tmp by default")
    print(" --repeat rep   How many timing samples should be gathered for each test")
    print("                100 by default")
    print(" --help         this message")

def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    timing = False
    outdir = "/tmp"
    repetitions = 100
    interface = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:l:o:i:", ["help", "repeat="])
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
        elif opt == '-l':
            level = int(arg)
        elif opt == "-i":
            timing = True
            interface = arg
        elif opt == '-o':
            outdir = arg
        elif opt == "--repeat":
            repetitions = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    tag_sizes = {
        "md5": 16,
        "sha": 20,
        "sha256": 32,
        "sha384": 48,
    }

    block_sizes = {
        "3des": 8,
        "aes128": 16,
        "aes256": 16,
    }
    ciphersuites = chain(CipherSuite.tripleDESSuites, CipherSuite.aes128Suites, CipherSuite.aes256Suites)
    for cipher in ciphersuites:
        if CipherSuite.canonicalMacName(cipher) not in tag_sizes:
            continue

        conversations = {}
        dhe = cipher in CipherSuite.ecdhAllSuites
        if dhe:
            ext = {}
            groups = [GroupName.secp256r1,
                      GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension() \
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIG_ALL)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        else:
            ext = None

        # first run sanity test and verify that server supports this ciphersuite
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\r\n\r\n"))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        # sending of the close_notify reply to a close_notify is very unrealiable
        # ignore it not being sent
        node.next_sibling = ExpectClose()
        conversations["sanity"] = conversation
        runner = Runner(conversation)
        try:
            runner.run()
        except Exception as exp:
            # no exception means the server rejected the ciphersuite, skip to next ciphersuite
            print("Skipping {0} because server does not support it. ".format(CipherSuite.ietfNames[cipher]))
            print(20 * '=')
            continue

        # correct padding for comparison
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\r\n\r\n"))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.close_notify))
        # sending of the close_notify reply to a close_notify is very unrealiable
        # ignore it not being sent
        node.next_sibling = ExpectClose()
        conversations["correct padding"] = conversation

        mac_len = tag_sizes[CipherSuite.canonicalMacName(cipher)]
        block_len = block_sizes[CipherSuite.canonicalCipherName(cipher)]
        invert_mac = {}
        for index in range(0, mac_len):
            invert_mac[index] = 0xff

        # iterate over: incorrect padding, correct padding and wrong mac
        for pad_len in range(1, 256):

            # ciphertext 1 has 512 bytes, calculate payload size
            payload_len = 512 - mac_len - pad_len - block_len

            # skip padding of length 1 because that would be correct padding
            if pad_len != 1:
                conversation = Connect(host, port)
                node = conversation
                ciphers = [cipher]
                node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
                node = node.add_child(ExpectServerHello())
                node = node.add_child(ExpectCertificate())
                if dhe:
                    node = node.add_child(ExpectServerKeyExchange())
                node = node.add_child(ExpectServerHelloDone())
                node = node.add_child(ClientKeyExchangeGenerator())
                node = node.add_child(ChangeCipherSpecGenerator())
                node = node.add_child(FinishedGenerator())
                node = node.add_child(ExpectChangeCipherSpec())
                node = node.add_child(ExpectFinished())
                node = node.add_child(
                    fuzz_padding(ApplicationDataGenerator(bytearray(payload_len)), substitutions={0: 0},
                                 min_length=pad_len))
                node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                                  AlertDescription.bad_record_mac))
                node.next_sibling = ExpectClose()
                conversations["incorrect padding of length {0}".format(pad_len)] = conversation

            conversation = Connect(host, port)
            node = conversation
            ciphers = [cipher]
            node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectCertificate())
            if dhe:
                node = node.add_child(ExpectServerKeyExchange())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(ClientKeyExchangeGenerator())
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectFinished())
            node = node.add_child(
                fuzz_padding(fuzz_mac(ApplicationDataGenerator(bytearray(payload_len)), xors=invert_mac),
                             min_length=pad_len))
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_record_mac))
            node.next_sibling = ExpectClose()
            conversations["incorrect mac, padding of length {0}".format(pad_len)] = conversation

            padding = 128 - 1 - block_len - mac_len
            # ciphertext 2 has 128 bytes and broken padding to make server check mac "before" the plaintext
            conversation = Connect(host, port)
            node = conversation
            ciphers = [cipher]
            node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectCertificate())
            if dhe:
                node = node.add_child(ExpectServerKeyExchange())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(ClientKeyExchangeGenerator())
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectFinished())
            node = node.add_child(
                fuzz_padding(ApplicationDataGenerator(bytearray(1)), substitutions={-1: pad_len, 0: 0},
                             min_length=padding))
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_record_mac))
            node.next_sibling = ExpectClose()
            conversations["mac out of bounds, padding byte={0}".format(pad_len)] = conversation

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
        regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
        sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
        ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

        print("Running tests for {0}".format(CipherSuite.ietfNames[cipher]))

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
                    print("XPASS: expected failure but test passed\n")
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

        print("Lucky 13 distinguishing attack check for {0}".format(CipherSuite.ietfNames[cipher]))

        print("Test end")
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
        elif timing:
            # if regular tests passed, run timing collection and analysis
            if TimingRunner.check_tcpdump():
                timing_runner = TimingRunner("{0}_{1}".format(sys.argv[0], CipherSuite.ietfNames[cipher]),
                                             sampled_tests,
                                             outdir,
                                             host,
                                             port,
                                             interface)
                print("Running timing tests...")
                timing_runner.generate_log(run_only, run_exclude, repetitions)
                ret_val = timing_runner.run()
                print("Statistical analysis exited with {0}".format(ret_val))
            else:
                print("Could not run timing tests because tcpdump is not present!")
                sys.exit(1)
            print(20 * '=')


if __name__ == "__main__":
    main()
