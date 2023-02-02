# Author: Hubert Kario, (c) 2021-2022
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Bleichenbacher attack test for Marvin workaround."""
from __future__ import print_function
import traceback
import sys
import getopt
import os
import math
import time
from itertools import chain, repeat
from random import sample
from threading import Thread

from tlsfuzzer.runner import Runner
from tlsfuzzer.timing_runner import TimingRunner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
    ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
    FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
    TCPBufferingEnable, TCPBufferingDisable, TCPBufferingFlush, fuzz_mac, \
    fuzz_padding, fuzz_pkcs1_padding
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
    ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
    ExpectAlert, ExpectClose, ExpectApplicationData, ExpectNoMessage

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
    ExtensionType
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.extensions import SNIExtension, SignatureAlgorithmsCertExtension,\
    SignatureAlgorithmsExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.utils.progress_report import progress_report
from tlsfuzzer.helpers import SIG_ALL, RSA_PKCS1_ALL
from tlslite.x509 import X509
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.utils.cryptomath import getRandomBytes, numBytes, secureHMAC, \
    numberToByteArray, numBits, secureHash
from tlsfuzzer.utils.statics import WARM_UP
from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.rsa import MarvinCiphertextGenerator


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
    print(" -a desc        the expected alert description for invalid Finished")
    print("                messages - 20 (bad_record_mac) by default")
    print("                Note: other values are NOT RFC compliant!")
    print(" -l level       the expected alert level for invalid Finished")
    print("                - 2 (fatal) by default")
    print("                Note: other values are NOT RFC compliant!")
    print(" -C cipher      specify cipher for connection. Use integer value")
    print("                or IETF name. Integer must be prefixed with '0x'")
    print("                if it is hexadecimal. By default uses")
    print("                TLS_RSA_WITH_AES_128_CBC_SHA ciphersuite.")
    print(" -i interface   Allows recording timing information")
    print("                on specified interface. Required to enable timing tests")
    print(" -o dir         Specifies output directory for timing information")
    print("                /tmp by default")
    print(" --repeat rep   How many timing samples should be gathered for each test")
    print("                100 by default")
    print(" --no-safe-renego  Allow the server not to support safe")
    print("                renegotiation extension")
    print(" --no-sni       do not send server name extension.")
    print("                Sends extension by default if the hostname is a")
    print("                valid DNS name, not an IP address")
    print(" --cpu-list     Set the CPU affinity for the tcpdump process")
    print("                See taskset(1) man page for the syntax of this")
    print("                option. Not used by default.")
    print(" --pms-len len  Generate ciphertexts that decrypt to specified")
    print("                number of bytes, 48 by default.")
    print(" --srv-key key  File with server private key.")
    print(" --srv-cert crt File with server certificate.")
    print(" --pms-tls-version ver Control the TLS version in the decrypted or")
    print("                synthethic plaintext. If left undefined the script")
    print("                will make sure not to generate message values that")
    print("                start with values appropriate for SSLv3, TLS 1.0,")
    print("                TLS 1.1, and TLS 1.2. If set, it should be a")
    print("                hex-encoded integer representing two bytes to be")
    print("                used as the version, e.g. \"0x0303\" for TLS 1.2")
    print("                Note: using this option will significantly increase")
    print("                the time to generate ciphertexts.")
    print(" --probe-reuse num How many times to reuse a probe before generating")
    print("                a new one. Low values will increase time to generate")
    print("                probes while large values risk false positives caused")
    print("                by ciphertext value. Set to 0 to never regenerate.")
    print("                Default 100")
    print(" --status-delay num How long to wait between status line updates.")
    print("                In seconds. Default: 2.0")
    print(" --help         this message")


def main():
    """Check if server implements Marvin workaround correctly."""
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    alert = AlertDescription.bad_record_mac
    level = AlertLevel.fatal
    srv_extensions = {ExtensionType.renegotiation_info: None}
    no_sni = False
    repetitions = 100
    interface = None
    timing = False
    outdir = "/tmp"
    cipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    affinity = None
    pms_len = 48
    srv_key = None
    srv_cert = None
    pms_tls_version = None
    probe_reuse = 100
    status_delay = 2.0

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv,
                               "h:p:e:x:X:n:a:l:l:o:i:C:",
                               ["help",
                                "no-safe-renego",
                                "no-sni",
                                "repeat=",
                                "cpu-list=",
                                "pms-len=",
                                "srv-key=",
                                "srv-cert=",
                                "pms-tls-version=",
                                "probe-reuse=",
                                "status-delay="])
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
        elif opt == '-C':
            if arg[:2] == '0x':
                cipher = int(arg, 16)
            else:
                try:
                    cipher = getattr(CipherSuite, arg)
                except AttributeError:
                    cipher = int(arg)
        elif opt == '-a':
            alert = int(arg)
        elif opt == '-l':
            level = int(arg)
        elif opt == "-i":
            timing = True
            interface = arg
        elif opt == '-o':
            outdir = arg
        elif opt == "--repeat":
            repetitions = int(arg)
        elif opt == "--no-safe-renego":
            srv_extensions = None
        elif opt == "--no-sni":
            no_sni = True
        elif opt == "--cpu-list":
            affinity = arg
        elif opt == "--pms-len":
            pms_len = int(arg)
        elif opt == "--srv-key":
            with open(arg, "rb") as f:
                text_key = f.read()
            if sys.version_info[0] >= 3:
                text_key = str(text_key, "utf-8")
            srv_key = parsePEMKey(text_key, private=True)
        elif opt == "--srv-cert":
            with open(arg, "rb") as f:
                text_cert = f.read()
            if sys.version_info[0] >= 3:
                text_cert = str(text_cert, "utf-8")
            srv_cert = X509()
            srv_cert.parse(text_cert)
        elif opt == "--pms-tls-version":
            int_ver = int(arg, 16)
            pms_tls_version = divmod(int_ver, 256)
        elif opt == "--probe-reuse":
            probe_reuse = int(arg)
        elif opt == "--status-delay":
            status_delay = float(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if not srv_cert or not srv_key:
        print("You must provide server private key and certificate")
        exit(1)

    print("Generating ciphertexts...")
    marvin_gen = MarvinCiphertextGenerator(
        srv_key, srv_cert.publicKey, pms_len, pms_tls_version)
    ciphertexts = marvin_gen.generate()
    print("Ciphertexts generated.")

    if args:
        run_only = set(args)
    else:
        run_only = None

    cln_extensions = {ExtensionType.renegotiation_info: None}
    if is_valid_hostname(host) and not no_sni:
        cln_extensions[ExtensionType.server_name] = \
            SNIExtension().create(bytearray(host, 'ascii'))
    cln_extensions[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_PKCS1_ALL)
    cln_extensions[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)

    # RSA key exchange check
    if cipher not in CipherSuite.certSuites:
        print("Ciphersuite has to use RSA key exchange.")
        exit(1)

    conversations = OrderedDict()

    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity"] = conversation

    # verify that we have the correct server certificate
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    secret = bytearray([3, 3] + [0x11] * 46)
    enc_secret = srv_cert.publicKey.encrypt(secret)
    node = node.add_child(ClientKeyExchangeGenerator(
        encrypted_premaster=enc_secret,
        premaster_secret=secret,
        reuse_encrypted_premaster=True))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity (opaque encrypt)"] = conversation


    for name, enc_pms in ciphertexts.items():
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))

        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(
            encrypted_premaster=enc_pms))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations[name] = conversation

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
    if num_limit < len(conversations):
        sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    else:
        sampled_tests = regular_tests
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

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
    print("""Tests for handling of malformed encrypted values in CKE

This test script checks if the server implements the Marvin workaround
correctly. That is, it expects that it leaks both the length of the encrypted
pre-master secret and the encrypted TLS version in it, but that PMS does not
depend on correctness of PKCS#1 padding.
When executed with `-i` it will also verify that different errors
are rejected in the same amount of time; it checks for timing
sidechannel.
The script executes tests without \"sanity\" in name multiple
times to estimate server response time.

Quick reminder: when encrypting a value using PKCS#1 v1.5 standard
the plaintext has the following structure, starting from most
significant byte:
- one byte, the version of the encryption, must be 0
- one byte, the type of encryption, must be 2 (is 1 in case of
  signature)
- one or more bytes of random padding, with no zero bytes. The
  count must equal the byte size of the public key modulus less
  size of encrypted value and 3 (for version, type and separator)
  For signatures the bytes must equal 0xff.
  Minimal length of padding is 8 bytes.
- one zero byte that acts as separator between padding and
  encrypted value
- one or more bytes that are the encrypted value, for TLS it must
  be 48 bytes long and the first two bytes need to equal the
  TLS version advertised in Client Hello.""")
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

    if bad or xpass:
        sys.exit(1)
    elif timing:
        # if regular tests passed, run timing collection and analysis
        if TimingRunner.check_tcpdump():
            tests = [('generic', None)]

            timing_runner = TimingRunner("{0}_v{1}_{2}".format(
                                            sys.argv[0],
                                            version,
                                            CipherSuite.ietfNames[cipher]),
                                         tests,
                                         outdir,
                                         host,
                                         port,
                                         interface,
                                         affinity,
                                         skip_extract=True)
            print("Pre-generating pre-master secret values...")

            with open(
                os.path.join(timing_runner.out_dir, 'pms_values.bin'),
                "wb"
            ) as pms_file:
                # create a real order of tests to run
                log = Log(os.path.join(timing_runner.out_dir, "real_log.csv"))
                actual_tests = []
                for c_name, c_test in sampled_tests:
                    if run_only and c_name not in run_only or \
                            c_name in run_exclude:
                        continue
                    if not c_name.startswith("sanity"):
                        actual_tests.append(c_name)

                log.start_log(actual_tests)
                for _ in range(repetitions):
                    log.shuffle_new_run()
                log.write()
                log.read_log()
                test_classes = log.get_classes()
                queries = chain(repeat(0, WARM_UP), log.iterate_log())

                status = [0, len(test_classes) * repetitions + WARM_UP, True]
                kwargs = dict()
                kwargs['delay'] = status_delay
                progress = Thread(target=progress_report, args=(status,),
                                  kwargs=kwargs)
                progress.start()

                exp_key_size = (len(srv_cert.publicKey) + 7) // 8

                # generate the PMS values
                try:
                    for executed, index in enumerate(queries):
                        if probe_reuse and executed > WARM_UP and \
                                executed % (len(test_classes) * probe_reuse) == 0:
                            ciphertexts = marvin_gen.generate()

                        status[0] = executed

                        g_name = test_classes[index]

                        res = ciphertexts[g_name]
                        assert len(res) == exp_key_size, len(res)

                        pms_file.write(res)
                finally:
                    status[2] = False
                    progress.join()
                    print()

            # fake the set of tests to run so it's just one
            pms_file = open(
                os.path.join(timing_runner.out_dir, 'pms_values.bin'),
                "rb"
            )

            conversation = Connect(host, port)
            node = conversation
            ciphers = [cipher]
            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       extensions=cln_extensions))
            node = node.add_child(ExpectServerHello(extensions=srv_extensions))

            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(TCPBufferingEnable())
            node = node.add_child(ClientKeyExchangeGenerator(
                encrypted_premaster_file=pms_file,
                encrypted_premaster_length=exp_key_size
                ))
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(TCPBufferingDisable())
            node = node.add_child(TCPBufferingFlush())
            node = node.add_child(ExpectAlert(level,
                                              alert))
            node.add_child(ExpectClose())

            tests[:] = [('generic', conversation)]

            print("Running timing tests...")
            timing_runner.generate_log(
                ['generic'], [],
                repetitions * len(actual_tests))
            ret_val = timing_runner.run()
            if ret_val != 0:
                print("run failed")
                sys.exit(ret_val)
            os.remove(os.path.join(timing_runner.out_dir, 'log.csv'))
            os.rename(
                os.path.join(timing_runner.out_dir, 'real_log.csv'),
                os.path.join(timing_runner.out_dir, 'log.csv')
            )
            if not timing_runner.extract():
                ret_val = 2
            else:
                timing_runner.analyse()

            if ret_val == 0:
                print("No statistically significant difference detected")
            elif ret_val == 1:
                print("Statisticaly significant difference detected at alpha="
                      "0.05")
            else:
                print("Statistical analysis exited with {0}".format(ret_val))
        else:
            print("Could not run timing tests because tcpdump is not present!")
            sys.exit(1)
        print(20 * '=')


if __name__ == "__main__":
    main()
