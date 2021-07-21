# Author: Hubert Kario, (c) 2016
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
        ExpectAlert, ExpectApplicationData, ExpectClose, ExpectServerKeyExchange
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, GroupName, \
        ExtensionType
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import protocol_name_to_tuple, RSA_SIG_ALL


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
    print(" -d             Use (EC)DHE instead of RSA for key exchange")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" --min-ver val  The lowest version support, \"SSLv3\" by default")
    print("                may be \"TLSv1.0\", \"TLSv1.1\" or \"TLSv1.2\"")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    min_ver = (3, 0)
    dhe = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:d", ["help", "min-ver="])
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
        elif opt == '-d':
            dhe = True
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '--min-ver':
            min_ver = protocol_name_to_tuple(arg)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port, version=(3, 0))
    node = conversation
    ext = {}
    groups = [GroupName.ffdhe2048]
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    if dhe:
        ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
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
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    expected_cipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    if dhe:
        expected_cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

    for c_id, name in [(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
                       (0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
                       (0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"),
                       (0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"),
                       (0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"),
                       (0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"),
                       (0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"),
                       (0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"),
                       (0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"),
                       (0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"),
                       (0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"),
                       (0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"),
                       (0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA")]:
        for prot, prot_name in [((3, 3), "TLSv1.2"),
                                ((3, 2), "TLSv1.1"),
                                ((3, 1), "TLSv1.0"),
                                ((3, 0), "SSLv3")]:
            conversation = Connect(host, port, version=(3, 0))
            node = conversation
            ext = {}
            groups = [GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
            ciphers = [c_id,
                       expected_cipher,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            node = node.add_child(ClientHelloGenerator(ciphers, version=prot, extensions=ext))
            if prot < min_ver:
                node = node.add_child(
                    ExpectAlert(AlertLevel.fatal,
                                (AlertDescription.protocol_version,
                                 AlertDescription.handshake_failure)))
                node = node.add_child(ExpectClose())
            else:
                node = node.add_child(ExpectServerHello(cipher=expected_cipher))
                node = node.add_child(ExpectCertificate())
                if dhe:
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
                # allow for 1/n-1 record splitting
                node = node.add_child(ExpectApplicationData())
                record_split = node
                node.next_sibling = ExpectAlert(AlertLevel.warning,
                                              AlertDescription.close_notify)
                node.next_sibling.next_sibling = ExpectClose()
                node = record_split.add_child(record_split.next_sibling)
                node.add_child(ExpectClose())
            conversations["{0} with AES_128 in {1}".format(name, prot_name)] \
                    = conversation

            # alone
            conversation = Connect(host, port, version=(3, 0))
            node = conversation
            ciphers = [c_id,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            node = node.add_child(ClientHelloGenerator(ciphers))
            node = node.add_child(
                ExpectAlert(AlertLevel.fatal,
                            (AlertDescription.handshake_failure,
                             AlertDescription.protocol_version)))
            node = node.add_child(ExpectClose())
            conversations["{0} in {1}".format(name, prot_name)] = conversation


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

    print("Test if export grade ciphers are rejected by server.\n")

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
