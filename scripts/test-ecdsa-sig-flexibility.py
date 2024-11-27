# Author: Alicja Kario, (c) 2017,2019,2024
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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.extensions import SignatureAlgorithmsExtension, \
        SupportedGroupsExtension, SignatureAlgorithmsCertExtension
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType, GroupName, \
        TLS_1_3_BRAINPOOL_SIG_SCHEMES, SignatureScheme
from tlsfuzzer.helpers import SIG_ALL
from tlsfuzzer.utils.lists import natural_sort_keys


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (\"sanity\" tests are always executed)")
    print(" -C ciph        Use specified ciphersuite. Either numerical value or")
    print("                IETF name.")
    print(" -g kex         Key exchange groups to advertise in the supported_groups")
    print("                extension, separated by colons. By default:")
    print("                \"secp256r1:secp384r1:secp521r1\"")
    print(" -M | --ems     Advertise support for Extended Master Secret")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    ciphers = None
    ems = False
    groups = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:C:Mg:", ["help", "ems"])
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
                ciphers = [int(arg, 16)]
            else:
                try:
                    ciphers = [getattr(CipherSuite, arg)]
                except AttributeError:
                    ciphers = [int(arg)]
        elif opt == '-g':
            vals = arg.split(":")
            groups = [getattr(GroupName, i) for i in vals]
        elif opt == '-M' or opt == '--ems':
            ems = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    # double check that provided cipher is valid for ECDSA
    if ciphers:
        if ciphers[0] not in CipherSuite.ecdheEcdsaSuites:
            raise ValueError("Ciphersuite not defined for ECDHE-ECDSA key exchange")
    else:
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA]
    ciphers += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

    if groups is None:
        groups = [GroupName.secp256r1,
                  GroupName.secp384r1,
                  GroupName.secp521r1]

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ext = {}
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    sigalgs = [(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha224, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha384, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha512, SignatureAlgorithm.ecdsa)]
    ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sigalgs)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
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
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # all algorithms, but in order from strongest to weakest
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    sigalgs = [(HashAlgorithm.sha512, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha384, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha224, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha1, SignatureAlgorithm.ecdsa)]
    ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sigalgs)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
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
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity - strongest to weakest"] = conversation

    # test all hashes one by one
    for h_alg in ["sha1", "sha224", "sha256", "sha384", "sha512"]:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        sigalgs = [(getattr(HashAlgorithm, h_alg), SignatureAlgorithm.ecdsa)]
        ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sigalgs)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                                   extensions=ext))
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
            bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["connect with {0}+ecdsa only".format(h_alg)] = conversation

    for sig_scheme in TLS_1_3_BRAINPOOL_SIG_SCHEMES:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        sigalgs = [sig_scheme]
        ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sigalgs)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                                   extensions=ext))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.handshake_failure))
        node.add_child(ExpectClose())
        conversations["connect with {0} only".format(SignatureScheme.toStr(sig_scheme))] = conversation

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

    print("Test if the server doesn't have the TLSv1.3 limitation on ECDSA")
    print("signatures also in TLSv1.2 mode.\n")

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
