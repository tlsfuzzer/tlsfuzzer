# Author: Milan Lysonek, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details
# CVE-2016-8610
# SSL Death Alert
# OpenSSL SSL/TLS SSL3_AL_WARNING undefined alert flood remote DoS

from __future__ import print_function
import traceback
from random import sample
import sys
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectServerKeyExchange
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import flexible_getattr
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import RSA_SIG_ALL


version = 6


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [--alerts number_of_alerts]")
    print("       [[probe-name] ...]")
    print(" -h hostname          name of the host to run the test against")
    print("                      localhost by default")
    print(" -p port              port number to use for connection,")
    print("                      4433 by default")
    print(" probe-name           if present, will run only the probes with given")
    print("                      names and not all of them, e.g \"sanity\"")
    print(" -e probe-name        exclude the probe from the list of the ones run")
    print("                      may be specified multiple times")
    print(" -x probe-name        expect the probe to fail. When such probe passes despite being marked like this")
    print("                      it will be reported in the test summary and the whole script will fail.")
    print("                      May be specified multiple times.")
    print(" -X message           expect the `message` substring in exception raised during")
    print("                      execution of preceding expected failure probe")
    print("                      usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                      (excluding \"sanity\" tests)")
    print(" -d                   negotiate (EC)DHE instead of RSA key exchange")
    print(" --alerts num         sends 'num' of alerts. by default(4)")
    print(" --alert-level        expected Alert.level of the abort")
    print("                      alert from server, fatal by default")
    print(" --alert-description  expected Alert.description of the")
    print("                      abort alert from server, None (any) by default")
    print(" --help               this message")


def main():
    hostname = "localhost"
    port = 4433
    number_of_alerts = 4
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    alert_level = AlertLevel.fatal
    alert_description = None
    dhe = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:d",
                               ["help", "alerts=", "alert-level=",
                                "alert-description="])
    for opt, arg in opts:
        if opt == '-h':
            hostname = arg
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
        elif opt == '-d':
            dhe = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '--alerts':
            number_of_alerts = flexible_getattr(arg, number_of_alerts)
        elif opt == '--alert-level':
            alert_level = flexible_getattr(arg, AlertLevel)
        elif opt == '--alert-description':
            alert_description = flexible_getattr(arg, AlertDescription)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(hostname, port, version=(3, 3))
    node = conversation
    if dhe:
        ext = {}
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    for _ in range(number_of_alerts):  # sending alerts during handshake
        node = node.add_child(AlertGenerator(  # alert description: 46, 41, 43
            AlertLevel.warning, AlertDescription.unsupported_certificate))
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
    node = node.add_child(AlertGenerator(
        AlertLevel.warning, AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    conversations["SSL Death Alert without getting alert"] = conversation

    conversation = Connect(hostname, port, version=(3, 3))
    node = conversation
    if dhe:
        ext = {}
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    for _ in range(number_of_alerts+1):
        node = node.add_child(AlertGenerator(
            AlertLevel.warning, AlertDescription.unsupported_certificate))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ExpectAlert(alert_level, alert_description))
    node = node.add_child(ExpectClose())
    conversations["SSL Death Alert with getting alert"] = conversation


    # run the conversation
    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    if not num_limit:
        num_limit = len(conversations)

    if run_only:
        if num_limit > len(run_only):
            num_limit = len(run_only)
        regular_tests = [(k, v) for k, v in conversations.items() if
                          k in run_only]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                          k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))

    for c_name, conversation in sampled_tests:
        if run_only and c_name not in run_only:
            continue
        if c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(conversation)

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

    print("Test for the OpenSSL Death Alert (CVE-2016-8610) vulnerability")
    print("Checks if the server will accept arbitrary number of warning level")
    print("alerts (specified with the -n option)")

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests)))
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

if __name__ == "__main__":
    main()
