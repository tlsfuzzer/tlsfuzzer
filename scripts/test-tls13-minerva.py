# Author: George Pantelakis, (c) 2023
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import os
import getopt
import time
from itertools import chain
from random import sample
from os.path import join

# Do not have any Warm up runs
from tlsfuzzer.utils import statics
statics.WARM_UP = 0

from tlsfuzzer.runner import Runner
from tlsfuzzer.timing_runner import TimingRunner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, CloseRST
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectChangeCipherSpec, ExpectFinished, ExpectAlert, \
        ExpectApplicationData, ExpectClose, ExpectEncryptedExtensions, \
        ExpectCertificateVerify, ExpectNewSessionTicket

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import key_share_gen, SIG_ALL

version = 7


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname      name of the host to run the test against")
    print("                  localhost by default")
    print(" -p port          port number to use for connection, 4433 by default")
    print(" probe-name       if present, will run only the probes with given")
    print("                  names and not all of them, e.g \"sanity\"")
    print(" -o dir           Specifies output directory for timing information")
    print("                  Default is /tmp")
    print(" -i interface     Recording timing information on specified interface.")
    print(" -e probe-name    exclude the probe from the list of the ones run")
    print("                  may be specified multiple times")
    print(" -x probe-name    expect the probe to fail. When such probe passes despite being marked like this")
    print("                  it will be reported in the test summary and the whole script will fail.")
    print("                  May be specified multiple times.")
    print(" -X message       expect the `message` substring in exception raised during")
    print("                  execution of preceding expected failure probe")
    print("                  usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num           run 'num' or all(if 0) tests instead of default(all)")
    print("                  (\"sanity\" tests are always executed)")
    print(" -C ciph          Use specified ciphersuite. Either numerical value or")
    print("                  IETF name.")
    print(" --curve curve    The curve to use to run the test. Choose from P-256,")
    print("                  P-384 or P-521. Default P-256.")
    print(" --repeat rep     How many timing samples should be gathered for each test")
    print("                  Default 100,000")
    print(" --priv-key file  The file that contains the ecdsa private key. This is")
    print("                  optional for running timing analysis.")
    print(" --alpha num      Acceptable probability of a false positive. Default: 1e-6.")
    print(" --status-delay num How long to wait between status line updates.")
    print("                  In seconds. Default: 2.0")
    print(" --status-newline Use a newline for line end instead of carriage return.")
    print(" --verbose        Prints a more verbose output.")
    print(" --help           This message")


def main():
    host = "127.0.0.1"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    ciphers = None
    curve = "P-256"
    data_size = 32
    outdir = "/tmp"
    timing = False
    samples = 100000
    alpha = 1e-6
    delay = 2.0
    carriage_return = None
    verbose = False

    data_file = "data.bin"
    sigs_file = "sigs.bin"
    priv_key_file = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:o:i:e:x:X:n:C:", ["help", "curve=",
                                                    "repeat=", "priv-key=",
                                                    "alpha=", "status-delay=",
                                                    "status-newline",
                                                    "verbose"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-o':
            outdir = arg
        elif opt == '-i':
            timing = True
            interface = arg
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
                ciphers = [int(arg, 16)]
            else:
                try:
                    ciphers = [getattr(CipherSuite, arg)]
                except AttributeError:
                    ciphers = [int(arg)]
        elif opt == '--curve':
            curve = arg
        elif opt == '--repeat':
            samples = int(arg)
        elif opt == '--priv-key':
            priv_key_file = arg
        elif opt == "--alpha":
            alpha = float(arg)
        elif opt == "--status-delay":
            delay = float(arg)
        elif opt == "--status-newline":
            carriage_return = '\n'
        elif opt == "--verbose":
            verbose = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if os.path.isfile(data_file):
        os.remove(data_file)
    if os.path.isfile(sigs_file):
        os.remove(sigs_file)

    if not ciphers:
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256]

    conversations = {}

    ext = {}

    if curve == "P-256":
        curve_sig_algs = [SignatureScheme.ecdsa_secp256r1_sha256]
        data_size = 32
    elif curve == "P-384":
        curve_sig_algs = [SignatureScheme.ecdsa_secp384r1_sha384]
        data_size = 48
    elif curve == "P-521":
        curve_sig_algs = [SignatureScheme.ecdsa_secp521r1_sha512]
        data_size = 64
    else:
        raise ValueError("Unknown curve: {0}.".format(curve))

    groups = [
        GroupName.secp256r1,
        GroupName.secp384r1,
        GroupName.secp521r1
    ]

    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))

    # Common ext creation -----------------------------------------------------
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(SIG_ALL)

    # Start of sanity conversation --------------------------------------------
    conversation = Connect(host, port)
    node = conversation

    sanity_ext = ext.copy()
    sig_algs = [
        SignatureScheme.ecdsa_secp256r1_sha256,
        SignatureScheme.ecdsa_secp384r1_sha384,
        SignatureScheme.ecdsa_secp521r1_sha512
    ]
    sanity_ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)

    node = node.add_child(ClientHelloGenerator(
        ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
        extensions=sanity_ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # Start of generic conversation -------------------------------------------
    conversation = Connect(host, port)
    node = conversation

    generic_ext = ext.copy()
    generic_ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(curve_sig_algs)

    node = node.add_child(ClientHelloGenerator(
        ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
        extensions=generic_ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(CloseRST())
    conversations["generic"] = conversation

    # run the conversations ---------------------------------------------------
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

    for c_name, c_test in ordered_tests:
        print("{0}... ".format(c_name), end="")

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

    print("""Test script to check is a server is vulnerable to Minerva attack

This script takes as argument a server, a curve and gathers signatures created
by the server during the TLS handshake and the amount of time the server took
to sign the data. These signatures then are gathered and (if the servers
private key is provided) it extracts from then the nonce (K value) from each
signature. Then the nonces are grouped (one of max nonce bit size with one or
more of less nonce bit size). Finally the groups are analyzed with several
statical tests to figure out if there is a correlation between the nonce bit
size and the timing that was needed to sign the data.""")

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

    if timing:
        if not TimingRunner.check_tcpdump():
            print("tcpdump is not installed in the system. Cannot gather data!")
            sys.exit(1)

        tests = [('generic', None)]

        timing_runner = TimingRunner("{0}_v{1}_minerva_{2}".format(
                                        sys.argv[0],
                                        version,
                                        curve),
                                    tests,
                                    outdir,
                                    host,
                                    port,
                                    interface,
                                    skip_extract=True,
                                    alpha=alpha,
                                    delay=delay,
                                    carriage_return=carriage_return,
                                    verbose_analysis=verbose)

        # Create and open files to write the results.
        if os.path.exists(join(timing_runner.out_dir, data_file)) \
            or os.path.exists(join(timing_runner.out_dir, sigs_file)):
            raise ValueError('Something went extremely wrong! Panic!')
        else:
            data_fp = open(join(timing_runner.out_dir, data_file), 'wb')
            sigs_fp = open(join(timing_runner.out_dir, sigs_file), 'wb')

        # Creating new connection for timing...
        conversation = Connect(host, port)
        node = conversation

        generic_ext = ext.copy()
        generic_ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(curve_sig_algs)

        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=generic_ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify(
            hash_file=data_fp,
            sig_file=sigs_fp
        ))
        node = node.add_child(ExpectFinished())
        node = node.add_child(CloseRST())

        tests[:] = [('generic', conversation)]

        print("Running timing tests...")
        timing_runner.generate_log(['generic'], [], samples)

        # Delay so the runner is not capturing the last packet from sanity checks.
        time.sleep(1)

        ret_val = timing_runner.run()
        if ret_val != 0:
            print("run failed")
            sys.exit(ret_val)

        data_fp.close()
        sigs_fp.close()

        extract_res = timing_runner.extract()

        if priv_key_file and extract_res:
            try:
                from tlsfuzzer.extract import Extract
                timing_outdir = timing_runner.out_dir
                extract = Extract(
                    output=timing_outdir,
                    raw_times=join(timing_outdir, "timing.csv"),
                    data=join(timing_outdir, data_file),
                    data_size=data_size,
                    sigs=join(timing_outdir, sigs_file),
                    priv_key=priv_key_file,
                    key_type="ecdsa",
                    verbose=verbose,
                    hash_func=None  # The data are already hashed.
                )
                extract.process_and_create_multiple_csv_files({
                    "measurements.csv": "k-size",
                    "measurements-invert.csv": "invert-k-size"
                })

                ret_val = timing_runner.analyse_bit_sizes()

                if ret_val != 0:
                    print("Possible side channel detected.")
                    exit(ret_val)
            except ImportError:
                print("Extraction is not available. "
                      "Install required packages to enable.")
    else:
        print("Skipping data gathering because network interface is not set.")

if __name__ == "__main__":
    main()
