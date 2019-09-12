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


version = 3


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [-n number_of_alerts]")
    print("       [[probe-name] ...]")
    print(" -h hostname          name of the host to run the test against")
    print("                      localhost by default")
    print(" -p port              port number to use for connection,")
    print("                      4433 by default")
    print(" probe-name           if present, will run only the probes with given")
    print("                      names and not all of them, e.g \"sanity\"")
    print(" -e probe-name        exclude the probe from the list of the ones run")
    print("                      may be specified multiple times")
    print(" -n number_of_alerts  how many alerts client sends to server,")
    print("                      4 by default")
    print(" -d                   negotiate (EC)DHE instead of RSA key exchange")
    print(" --alert-level        expected Alert.level of the abort")
    print("                      alert from server, fatal by default")
    print(" --alert-description  expected Alert.description of the")
    print("                      abort alert from server, None (any) by default")
    print(" --help               this message")


def main():
    hostname = "localhost"
    port = 4433
    number_of_alerts = 4
    run_exclude = set()
    alert_level = AlertLevel.fatal
    alert_description = None
    dhe = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:d",
                               ["help", "alert-level=",
                                "alert-description="])
    for opt, arg in opts:
        if opt == '-h':
            hostname = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            number_of_alerts = int(arg)
        elif opt == '-d':
            dhe = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
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
    failed = []

    shuffled_tests = sample(list(conversations.items()), len(conversations))

    for conversation_name, conversation in shuffled_tests:
        if run_only and conversation_name not in run_only:
            continue
        if conversation_name in run_exclude:
            continue
        print("{0} ...".format(conversation_name))

        runner = Runner(conversation)

        res = True
        try:
            runner.run()
        except Exception:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(conversation_name)

    print("Test for the OpenSSL Death Alert (CVE-2016-8610) vulnerability")
    print("Checks if the server will accept arbitrary number of warning level")
    print("alerts (specified with the -n option)")
    print("version: {0}\n".format(version))

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
