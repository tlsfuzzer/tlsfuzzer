# Author: Hubert Kario, (c) 2018-2022
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Test for correct handling of short DHE shared secret."""

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
        CopyVariables
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectServerKeyExchange, \
        ExpectApplicationData
from tlsfuzzer.utils.lists import natural_sort_keys

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlslite.utils.cryptomath import numBytes
from tlsfuzzer.helpers import SIG_ALL, AutoEmptyExtension


version = 8


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(1)")
    print("                (excluding \"sanity\" tests)")
    print(" --min-zeros m  minimal number of zeros that have to be cut from")
    print("                shared secret for test case to be valid,")
    print("                1 by default")
    print(" -z             don't expect 1/n-1 record split in TLS1.0")
    print(" --extra-exts   Send additional extensions to advertise support for")
    print("                stronger primes and signatures")
    print(" -M | --ems     enable support for Extended Master Secret")
    print(" --help         this message")


def main():
    """Verify correct DHE shared secret and key share handling."""
    host = "localhost"
    port = 4433
    num_limit = 1
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    min_zeros = 1
    record_split = True
    extra_exts = False
    ems = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:zM", ["help", "min-zeros=",
        "extra-exts", "ems"])
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
        elif opt == '-M' or opt == '--ems':
            ems = True
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-z':
            record_split = False
        elif opt == '--extra-exts':
            extra_exts = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '--min-zeros':
            min_zeros = int(arg)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    collected_premaster_secrets = []
    collected_dh_primes = []
    collected_client_key_shares = []
    variables_check = \
        {'premaster_secret':
         collected_premaster_secrets,
         'ServerKeyExchange.dh_p':
         collected_dh_primes,
         'ClientKeyExchange.dh_Yc':
         collected_client_key_shares}

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    exts = {}
    exts[ExtensionType.renegotiation_info] = None
    if ems:
        exts[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if extra_exts:
        exts[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create([GroupName.ffdhe2048, GroupName.ffdhe3072,
                     GroupName.ffdhe4096])
        exts[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        exts[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions=exts))
    srv_ext = {ExtensionType.renegotiation_info:None}
    if ems:
        srv_ext[ExtensionType.extended_master_secret] = None
    node = node.add_child(ExpectServerHello(
        extensions=srv_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(CopyVariables(variables_check))
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

    for prot in [(3, 0), (3, 1), (3, 2), (3, 3)]:
        for ssl2 in [True, False]:
            conversation = Connect(host, port,
                                   version=(0, 2) if ssl2 else (3, 0))
            node = conversation
            if ssl2:
                ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                           CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            else:
                ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       extensions=exts,
                                                       version=prot,
                                                       ssl2=ssl2))
            if prot > (3, 0):
                ext = {ExtensionType.renegotiation_info: None}
                if ems and not ssl2:
                    ext[ExtensionType.extended_master_secret] = None
            else:
                ext = None
            node = node.add_child(ExpectServerHello(extensions=ext,
                                                    version=prot))
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectServerKeyExchange())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(ClientKeyExchangeGenerator())
            node = node.add_child(CopyVariables(variables_check))
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectFinished())
            node = node.add_child(ApplicationDataGenerator(
                bytearray(b"GET / HTTP/1.0\n\n")))
            node = node.add_child(ExpectApplicationData())
            if prot < (3, 2) and record_split:
                # 1/n-1 record splitting
                node = node.add_child(ExpectApplicationData())
            node = node.add_child(AlertGenerator(AlertLevel.warning,
                                                 AlertDescription.close_notify))
            node = node.add_child(ExpectAlert())
            node.next_sibling = ExpectClose()

            conversations["Protocol {0}{1}".format(
                prot,
                " in SSLv2 compatible ClientHello" if ssl2 else "")] = \
                    conversation

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
        i = 0
        break_loop = False
        break_loop_clnt = False
        while True:
            # don't hog the memory unnecessairly
            collected_dh_primes[:] = []
            collected_premaster_secrets[:] = []
            collected_client_key_shares[:] = []

            print("\"{1}\" repeat {0}...".format(i, c_name))
            i += 1
            if c_name == "sanity":
                break_loop = True
                break_loop_clnt = True

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
                break
            else:
                if res:
                    good += 1
                    if numBytes(collected_dh_primes[-1]) \
                            >= len(collected_premaster_secrets[-1]) \
                            + min_zeros:
                        print("Got prime {0} bytes long and a premaster_secret"
                              " {1} bytes long"
                              .format(numBytes(collected_dh_primes[-1]),
                                  len(collected_premaster_secrets[-1])))
                        break_loop = True
                    if numBytes(collected_dh_primes[-1]) \
                            >= numBytes(collected_client_key_shares[-1]) + \
                            min_zeros:
                        print("Got prime {0} bytes long and a client "
                              "key share {1} bytes long"
                              .format(
                                  numBytes(collected_dh_primes[-1]),
                                  numBytes(collected_client_key_shares[-1])))
                        break_loop_clnt = True
                    print("OK\n")
                else:
                    bad += 1
                    failed.append(c_name)
                    break
            if break_loop and break_loop_clnt:
                break


    print('')

    print("Check if the calculated DHE pre_master_secret is truncated when")
    print("there are zeros on most significant bytes, and that server")
    print("accepts a client key share when it does the same")

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
