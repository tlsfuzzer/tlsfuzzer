# Author: Hubert Kario, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Test for correct handling of zero-padded ECDHE shared secrets."""

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
        ExtensionType, GroupName, ECPointFormat
from tlslite.extensions import ECPointFormatsExtension, \
        SupportedGroupsExtension


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(1)")
    print("                (excluding \"sanity\" tests)")
    print(" --min-zeros m  minimal number of zeros that have to be cut from")
    print("                shared secret for test case to be valid,")
    print("                1 by default")
    print(" -z             don't expect 1/n-1 record split in TLS1.0")
    print(" --help         this message")


def main():
    """Verify correct ECDHE shared secret handling."""
    host = "localhost"
    port = 4433
    num_limit = 1
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    min_zeros = 1
    record_split = True

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:z", ["help", "min-zeros="])
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
        elif opt == '-z':
            record_split = False
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
    variables_check = \
        {'premaster_secret':
         collected_premaster_secrets}

    groups = [GroupName.x25519, GroupName.x448, GroupName.secp256r1,
              GroupName.secp384r1, GroupName.secp521r1]

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA]
    groups_ext = SupportedGroupsExtension().create(groups)
    points_ext = ECPointFormatsExtension().create([ECPointFormat.uncompressed])
    exts = {ExtensionType.renegotiation_info: None,
            ExtensionType.supported_groups: groups_ext,
            ExtensionType.ec_point_formats: points_ext}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=exts))
    exts = {ExtensionType.renegotiation_info:None,
            ExtensionType.ec_point_formats: None}
    node = node.add_child(ExpectServerHello(extensions=exts))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(CopyVariables(variables_check))
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

    for prot in [(3, 0), (3, 1), (3, 2), (3, 3)]:
        for ssl2 in [True, False]:
            for group in groups:
                # with SSLv2 compatible or with SSLv3 we can't advertise
                # curves so do just one check
                if (ssl2 or prot == (3, 0)) and group != groups[0]:
                    continue
                conversation = Connect(host, port,
                                       version=(0, 2) if ssl2 else (3, 0))
                node = conversation
                ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                           CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
                if ssl2 or prot == (3, 0):
                    exts = None
                else:
                    groups_ext = SupportedGroupsExtension().create([group])
                    exts = {ExtensionType.supported_groups: groups_ext,
                            ExtensionType.ec_point_formats: points_ext}
                node = node.add_child(ClientHelloGenerator(ciphers,
                                                           version=prot,
                                                           extensions=exts,
                                                           ssl2=ssl2))
                if prot > (3, 0):
                    if ssl2:
                        ext = {ExtensionType.renegotiation_info: None}
                    else:
                        ext = {ExtensionType.renegotiation_info: None,
                               ExtensionType.ec_point_formats: None}
                else:
                    ext = None
                node = node.add_child(ExpectServerHello(extensions=ext,
                                                        version=prot))
                node = node.add_child(ExpectCertificate())
                node = node.add_child(ExpectServerKeyExchange())
                node = node.add_child(CopyVariables(variables_check))
                node = node.add_child(ExpectServerHelloDone())
                node = node.add_child(ClientKeyExchangeGenerator())
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

                conversations["Protocol {0}{1}{2}".format(
                    prot,
                    "" if ssl2 or prot < (3, 1)
                    else " with {0} group".format(GroupName.toStr(group)),
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
        while True:
            # don't hog the memory unnecessairly
            collected_premaster_secrets[:] = []
            print("\"{1}\" repeat {0}...".format(i, c_name))
            i += 1
            if c_name == 'sanity':
                break_loop = True

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
                break_loop = True
            else:
                if res:
                    good += 1
                    if collected_premaster_secrets[-1][:min_zeros] == \
                            bytearray(min_zeros):
                        print("Got premaster secret with {0} most significant "
                            "bytes equal to zero."
                            .format(min_zeros))
                        break_loop = True
                    print("OK\n")
                else:
                    bad += 1
                    failed.append(c_name)
                    break_loop = True
            if break_loop:
                break

    print('')

    print("Check if the connections work when the calculated ECDH shared")
    print("secret must be padded on the left with zeros")

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
