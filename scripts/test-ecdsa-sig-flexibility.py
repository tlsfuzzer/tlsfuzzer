# Author: Hubert Kario, (c) 2017
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
import re
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
        HashAlgorithm, SignatureAlgorithm, ExtensionType, GroupName
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
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
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

    conversation = Connect(host, port)
    node = conversation
    ext = {}
    sigalgs = [(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha384, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha512, SignatureAlgorithm.ecdsa)]
    ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sigalgs)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    curves = [GroupName.secp256r1,
              GroupName.secp384r1,
              GroupName.secp521r1]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(curves)
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello())
    # ECDSA is not supported by tlslite-ng v0.7.0a3
    #node = node.add_child(ExpectCertificate())
    #node = node.add_child(ExpectServerKeyExchange())
    #node = node.add_child(ExpectServerHelloDone())
    #node = node.add_child(ClientKeyExchangeGenerator())
    #node = node.add_child(ChangeCipherSpecGenerator())
    #node = node.add_child(FinishedGenerator())
    #node = node.add_child(ExpectChangeCipherSpec())
    #node = node.add_child(ExpectFinished())
    #node = node.add_child(ApplicationDataGenerator(
    #    bytearray(b"GET / HTTP/1.0\n\n")))
    #node = node.add_child(ExpectApplicationData())
    #node = node.add_child(AlertGenerator(AlertLevel.warning,
    #                                     AlertDescription.close_notify))
    #node = node.add_child(ExpectAlert())
    #node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # all algorithms, but in order from strongest to weakest
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    sigalgs = [(HashAlgorithm.sha512, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha384, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
               (HashAlgorithm.sha1, SignatureAlgorithm.ecdsa)]
    ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sigalgs)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    curves = [GroupName.secp256r1,
              GroupName.secp384r1,
              GroupName.secp521r1]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(curves)
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello())
    # ECDSA is not supported by tlslite-ng v0.7.0a3
    #node = node.add_child(ExpectCertificate())
    #node = node.add_child(ExpectServerKeyExchange())
    #node = node.add_child(ExpectServerHelloDone())
    #node = node.add_child(ClientKeyExchangeGenerator())
    #node = node.add_child(ChangeCipherSpecGenerator())
    #node = node.add_child(FinishedGenerator())
    #node = node.add_child(ExpectChangeCipherSpec())
    #node = node.add_child(ExpectFinished())
    #node = node.add_child(ApplicationDataGenerator(
    #    bytearray(b"GET / HTTP/1.0\n\n")))
    #node = node.add_child(ExpectApplicationData())
    #node = node.add_child(AlertGenerator(AlertLevel.warning,
    #                                     AlertDescription.close_notify))
    #node = node.add_child(ExpectAlert())
    #node.next_sibling = ExpectClose()
    conversations["sanity - strongest to weakest"] = conversation

    # test all hashes one by one
    for h_alg in ["sha1", "sha256", "sha384", "sha512"]:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        sigalgs = [(getattr(HashAlgorithm, h_alg), SignatureAlgorithm.ecdsa)]
        ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sigalgs)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        curves = [GroupName.secp256r1,
                  GroupName.secp384r1,
                  GroupName.secp521r1]
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(curves)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello())
        # ECDSA is not supported by tlslite-ng v0.7.0a3
        #node = node.add_child(ExpectCertificate())
        #node = node.add_child(ExpectServerKeyExchange())
        #node = node.add_child(ExpectServerHelloDone())
        #node = node.add_child(ClientKeyExchangeGenerator())
        #node = node.add_child(ChangeCipherSpecGenerator())
        #node = node.add_child(FinishedGenerator())
        #node = node.add_child(ExpectChangeCipherSpec())
        #node = node.add_child(ExpectFinished())
        #node = node.add_child(ApplicationDataGenerator(
        #    bytearray(b"GET / HTTP/1.0\n\n")))
        #node = node.add_child(ExpectApplicationData())
        #node = node.add_child(AlertGenerator(AlertLevel.warning,
        #                                     AlertDescription.close_notify))
        #node = node.add_child(ExpectAlert())
        #node.next_sibling = ExpectClose()
        conversations["connect with {0}+ecdsa only".format(h_alg)] = conversation

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

    print("Test if the server doesn't have the TLSv1.3 limitation on ECDSA")
    print("signatures also in TLSv1.2 mode.\n")

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
