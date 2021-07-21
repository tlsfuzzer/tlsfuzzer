# Author: Hubert Kario, (c) 2015
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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        fuzz_message
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, HashAlgorithm, SignatureAlgorithm, SignatureScheme, \
        GroupName
from tlslite.extensions import SignatureAlgorithmsExtension, TLSExtension, \
        SignatureAlgorithmsCertExtension, SupportedGroupsExtension
from tlsfuzzer.helpers import RSA_SIG_ALL
from tlsfuzzer.utils.ordered_dict import OrderedDict
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
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:x:X:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
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
    sigs = [SignatureScheme.rsa_pss_rsae_sha256,
            SignatureScheme.rsa_pss_rsae_sha384,
            SignatureScheme.rsa_pss_rsae_sha512,
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512,
            (HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha224, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.secp256r1,
              GroupName.x25519,
              GroupName.secp384r1,
              GroupName.secp521r1]
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
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
    node = node.add_child(ExpectClose())
    conversations["sanity"] = conversation

    for sig in [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_rsae_sha512,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.rsa_pss_pss_sha384,
                SignatureScheme.rsa_pss_pss_sha512
                ]:
        conversation = Connect(host, port)
        node = conversation
        ext = {ExtensionType.signature_algorithms:
                SignatureAlgorithmsExtension().create([sig]),
               ExtensionType.signature_algorithms_cert:
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
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
        node = node.add_child(ExpectClose())
        conversations["{0} only"
                      .format(SignatureScheme.toRepr(sig))] = conversation

    # MD5 not selected, even if first
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.md5, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha224, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa),
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=sigs[1:]))
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
    node = node.add_child(ExpectClose())
    conversations["MD5 first"] = conversation

    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.md5, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha224, SignatureAlgorithm.rsa),
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=sigs[1:]))
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
    node = node.add_child(ExpectClose())
    conversations["MD5 first, no SHA-1"] = conversation

    # sha-1 must not be the only option
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha224, SignatureAlgorithm.rsa),
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
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
    node = node.add_child(ExpectClose())
    conversations["no SHA-1"] = conversation

    # undefined values
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha256, 24),  # undefined signature algorithm
            (24, SignatureAlgorithm.rsa),  # undefined hash algorithm
            (10, 10),  # undefined pair
            (9, 24),  # undefined pair
            (0xff, 0xff),  # undefined pair
            (HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha224, SignatureAlgorithm.rsa),
            SignatureScheme.rsa_pss_pss_sha256,
            SignatureScheme.rsa_pss_pss_sha384,
            SignatureScheme.rsa_pss_pss_sha512]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=sigs[5:]))
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
    node = node.add_child(ExpectClose())
    conversations["extra sigalgs"] = conversation

    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha256, 24),  # undefined signature algorithm
            (24, SignatureAlgorithm.rsa),  # undefined hash algorithm
            (10, 10),  # undefined pair
            (9, 24),  # undefined pair
            (0xff, 0xff)  # undefined pair
           ]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.handshake_failure))
    node = node.add_child(ExpectClose())
    conversations["only undefined sigalgs"] = conversation

    # invalid formatting
    conversation = Connect(host, port)
    node = conversation
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create([]),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["empty sigalgs"] = conversation

    # invalid length
    conversation = Connect(host, port)
    node = conversation
    ext = OrderedDict()
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    sigs = [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sigs)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    msg = ClientHelloGenerator(ciphers, extensions=ext)
    node = node.add_child(fuzz_message(msg, xors={-3: 1}))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["fuzz length of sigalgs"] = conversation

    # invalid length
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)]
    ext = OrderedDict()
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    ext[ExtensionType.signature_algorithms] =  SignatureAlgorithmsExtension()\
        .create(sigs)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    msg = ClientHelloGenerator(ciphers, extensions=ext)
    node = node.add_child(fuzz_message(msg, substitutions={-3: 4}))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["truncate sigalgs extension"] = conversation

    # odd length
    conversation = Connect(host, port)
    node = conversation
    ext = {ExtensionType.signature_algorithms:
            TLSExtension(extType=ExtensionType.signature_algorithms)
            .create(bytearray(b'\x00\x03'  # length of array
                              b'\x04\x01'  # sha256 + rsa
                              b'\x04')),  # the odd byte
           ExtensionType.signature_algorithms_cert:
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    msg = ClientHelloGenerator(ciphers, extensions=ext)
    node = node.add_child(msg)
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["odd length of sigalgs"] = conversation

    # padded extension
    conversation = Connect(host, port)
    node = conversation
    ext = {ExtensionType.signature_algorithms:
            TLSExtension(extType=ExtensionType.signature_algorithms)
            .create(bytearray(b'\x00\x04'  # length of array
                              b'\x02\x01'  # sha1+rsa
                              b'\x04\x01'  # sha256 + rsa
                              b'\x04\x03')),  # extra bytes
           ExtensionType.signature_algorithms_cert:
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    msg = ClientHelloGenerator(ciphers, extensions=ext)
    node = node.add_child(msg)
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["padded sigalgs"] = conversation

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

    print("Test end\n")

    print("Check if server correctly selects signature algorithm for SKE\n")
    print("Test to verify that Server Key Exchange is signed with safe")
    print("and correct algorithms.\n")
    print("Note that test expects server with support for both rsa_pss_rsae_*")
    print("and rsa_pss_pss_* signatures, in other words, one with both")
    print("rsaEncryption key in one certificate and rsasse-pss in second")
    print("certificate. If there's only one certificate installed in server,")
    print("some of the tests that advertise just one algorithm may need to be")
    print("configured as expected failures.")
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
