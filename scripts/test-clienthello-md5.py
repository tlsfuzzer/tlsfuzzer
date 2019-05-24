# Author: Stanislav Zidek, (c) 2017
# Released under Gnu GPL v2.0, see LICENSE file for details
"""
Test md5 and unassigned numbers in signature_algorithms
extension in ClientHello
"""

from __future__ import print_function
import traceback
from random import sample
import sys
import getopt
import re
from itertools import chain

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, \
        AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerKeyExchange, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from tlsfuzzer.helpers import RSA_SIG_ALL


def natural_sort_keys(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(_nsre, s)]


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" --workaround   workaround https://bugzilla.redhat.com/show_bug.cgi?id=1411238")
    print(" --help         this message")


def main():
    """Check what signature algorithms server advertises"""
    hostname = "localhost"
    port = 4433
    run_exclude = set()
    workaround = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:", ["help", "workaround"])
    for opt, arg in opts:
        if opt == '-h':
            hostname = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '--workaround':
            workaround = True
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    # sanity check of connection
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers))

    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()

    conversations["sanity"] = conversation

    # advertising only MD5 in ClientHello
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (HashAlgorithm.md5, SignatureAlgorithm.rsa)]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    if workaround:
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        # here we expect (SHA1, RSA) as a workaround for
        # https://bugzilla.redhat.com/show_bug.cgi?id=1411238
        valid = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
        node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
    else:
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.handshake_failure))
        node = node.add_child(ExpectClose())
    conversations["only-md5-rsa-signature_algorithm"] = conversation

    # advertising bogus in ClientHello
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([(21, 69)]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    if workaround:
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        # here we expect (SHA1, RSA) as a workaround for
        # https://bugzilla.redhat.com/show_bug.cgi?id=1411238
        valid = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
        node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
    else:
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.handshake_failure))
        node = node.add_child(ExpectClose())

    conversations["unknown-signature_algorithm-numbers"] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
    shuffled_tests = sample(regular_tests, len(regular_tests))
    ordered_tests = chain(sanity_tests, shuffled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Test to verify if server rejects ClientHello with ")
    print("either unsupported hash (advertising only (MD5, RSA) pair)")
    print("or bogus numbers not assigned to real algorithms")
    print("advertised in SignatureAlgorithms extension")
    print("Test version 1\n")

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
