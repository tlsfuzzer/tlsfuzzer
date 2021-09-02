# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Tests for Lucky 13 vulnerabilities and related conditions"""

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain, product
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


version = 7


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
    print(" -C cipher      specify cipher for connection. Use integer value")
    print("                or IETF name. Integer must be prefixed with '0x'")
    print("                if it is hexadecimal. By default uses")
    print("                TLS_RSA_WITH_AES_128_CBC_SHA ciphersuite.")
    print(" -n num         only run `num` random tests instead of a full set")
    print("                (\"sanity\" tests are always executed)")
    print(" -i interface   Allows recording timing information on the")
    print("                specified interface. Required to enable timing tests")
    print(" -o dir         Specifies output directory for timing information")
    print("                /tmp by default")
    print(" --repeat rep   How many timing samples should be gathered for each test")
    print("                100 by default")
    print(" --quick        Only run a basic subset of tests")
    print(" --cpu-list     Set the CPU affinity for the tcpdump process")
    print("                See taskset(1) man page for the syntax of this")
    print("                option. Not used by default.")
    print(" --payload-len num Size of the sent Application Data record, in bytes.")
    print("                512 by default.")
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
    quick = False
    cipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    affinity = None
    ciphertext_len = 512

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:l:o:i:C:", ["help",
                                                              "repeat=",
                                                              "quick",
                                                              "cpu-list=",
                                                              "payload-len="])
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
        elif opt == '-C':
            if arg[:2] == '0x':
                cipher = int(arg, 16)
            else:
                try:
                    cipher = getattr(CipherSuite, arg)
                except AttributeError:
                    cipher = int(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-l':
            level = int(arg)
        elif opt == "-i":
            timing = True
            interface = arg
        elif opt == '-o':
            outdir = arg
        elif opt == "--payload-len":
            ciphertext_len = int(arg)
        elif opt == "--repeat":
            repetitions = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '--quick':
            quick = True
        elif opt == '--cpu-list':
            affinity = arg
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    mac_sizes = {
        "md5": 16,
        "sha": 20,
        "sha256": 32,
        "sha384": 48,
    }

    if CipherSuite.canonicalMacName(cipher) not in mac_sizes:
        print("Unsupported MAC, exiting")
        exit(1)

    # group conversations that should have the same timing signature
    if quick:
        groups = {"quick - wrong MAC": {}}
    else:
        groups = {
            "wrong padding and MAC": {},
            "MAC out of bounds": {}
        }

    dhe = cipher in CipherSuite.ecdhAllSuites
    ext = {}
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if dhe:
        sup_groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension() \
            .create(sup_groups)

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
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    for group_name in groups:
        groups[group_name]["sanity"] = conversation
    runner = Runner(conversation)
    try:
        runner.run()
    except Exception as exp:
        # Exception means the server rejected the ciphersuite
        print("Failing on {0} because server does not support it. ".format(CipherSuite.ietfNames[cipher]))
        print(20 * '=')
        exit(1)

    # assume block length of 16 if not 3des
    block_len = 8 if CipherSuite.canonicalCipherName(cipher) == "3des" else 16
    mac_len = mac_sizes[CipherSuite.canonicalMacName(cipher)]
    invert_mac = {}
    for index in range(0, mac_len):
        invert_mac[index] = 0xff

    if quick:
        # iterate over min/max padding and first/last byte MAC error
        for pad_len, error_pos in product([1, 256], [0, -1]):
            payload_len = ciphertext_len - mac_len - pad_len - block_len

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
                fuzz_padding(
                    fuzz_mac(
                        ApplicationDataGenerator(bytearray(payload_len)),
                        xors={error_pos: 0xff}
                    ),
                    min_length=pad_len
                )
            )
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_record_mac))
            node = node.add_child(ExpectClose())
            groups["quick - wrong MAC"][
                "wrong MAC at pos {0}, padding length {1}".format(error_pos, pad_len)] = conversation

        # iterate over min/max padding and first/last byte of padding error
        for pad_len, error_pos in product([256], [0, 254]):
            payload_len = ciphertext_len - mac_len - pad_len - block_len

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
                fuzz_padding(
                    ApplicationDataGenerator(bytearray(payload_len)),
                    min_length=pad_len,
                    xors={(error_pos): 0xff}
                )
            )
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_record_mac))
            node = node.add_child(ExpectClose())
            groups["quick - wrong MAC"][
                "wrong pad at pos {0}, padding length {1}".format(error_pos, pad_len)] = conversation

    else:
        # iterate over: padding length with incorrect MAC
        #               invalid padding length with correct MAC
        for pad_len in range(1, 257):

            # ciphertext 1 has 512 bytes, calculate payload size
            payload_len = ciphertext_len - mac_len - pad_len - block_len

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
                fuzz_padding(
                    fuzz_mac(
                        ApplicationDataGenerator(bytearray(payload_len)),
                        xors=invert_mac
                    ),
                    min_length=pad_len
                )
            )
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_record_mac))
            node = node.add_child(ExpectClose())
            groups["wrong padding and MAC"]["wrong MAC, padding length {0}".format(pad_len)] = conversation

            # incorrect padding of length 255 (256 with the length byte)
            # with error byte iterated over the length of padding

            # avoid changing the padding length byte
            if pad_len < 256:
                payload_len = ciphertext_len - mac_len - 256 - block_len

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
                    fuzz_padding(
                        ApplicationDataGenerator(bytearray(payload_len)),
                        min_length=256,
                        xors={(pad_len - 1): 0xff}
                    )
                )
                node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                                  AlertDescription.bad_record_mac))
                node = node.add_child(ExpectClose())
                groups["wrong padding and MAC"][
                    "padding length 255 (256 with the length byte), padding error at position {0}".format(
                        pad_len - 1)] = conversation

            # ciphertext 2 has 128 bytes and broken padding to make server check mac "before" the plaintext
            padding = 128 - 1 - block_len - mac_len
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
                fuzz_padding(ApplicationDataGenerator(bytearray(1)), substitutions={-1: pad_len - 1, 0: 0},
                             min_length=padding))
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_record_mac))
            node = node.add_child(ExpectClose())
            groups["MAC out of bounds"]["padding length byte={0}".format(pad_len - 1)] = conversation

        # iterate over MAC length and fuzz byte by byte
        payload_len = ciphertext_len - mac_len - block_len - 256
        for mac_index in range(0, mac_len):
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
                fuzz_padding(fuzz_mac(ApplicationDataGenerator(bytearray(payload_len)), xors={mac_index: 0xff}),
                             min_length=256))
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_record_mac))
            node = node.add_child(ExpectClose())
            groups["wrong padding and MAC"]["padding length 255 (256 with the length byte), incorrect MAC at pos {0}".format(mac_index)] = conversation

    for group_name, conversations in groups.items():

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
            regular_tests = [(k, v) for k, v in conversations.items() if k in run_only]
        else:
            regular_tests = [(k, v) for k, v in conversations.items() if
                             (k != 'sanity') and k not in run_exclude]
        sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
        ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)
        if not sampled_tests:
            continue

        print("Running tests for {0}".format(CipherSuite.ietfNames[cipher]))

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

        print("Lucky 13 attack check for {0} {1}".format(group_name, CipherSuite.ietfNames[cipher]))

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

        if bad or xpass:
            sys.exit(1)
        elif timing:
            # if regular tests passed, run timing collection and analysis
            if TimingRunner.check_tcpdump():
                timing_runner = TimingRunner("{0}_v{1}_{2}_{3}".format(
                                                sys.argv[0],
                                                version,
                                                group_name,
                                                CipherSuite.ietfNames[cipher]),
                                             sampled_tests,
                                             outdir,
                                             host,
                                             port,
                                             interface,
                                             affinity)
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
