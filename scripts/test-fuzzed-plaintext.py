# Author: Hubert Kario, (c) 2018, 2019
# Released under Gnu GPL v2.0, see LICENSE file for details
"""MAC value fuzzer"""

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        fuzz_padding, CertificateGenerator, replace_plaintext, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData, ExpectServerKeyExchange
from tlsfuzzer.fuzzers import structured_random_iter, StructuredRandom

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import RSA_SIG_ALL


version = 4


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" --random count generate `count` random tests in addition to the")
    print("                basic 8192 pre-programmed ones. 8192 by default")
    print(" -n num         only run `num` random tests instead of a full set.")
    print("                1024 by default")
    print("                (\"sanity\" tests are always executed)")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" -C cipher      specify cipher for connection. Use integer value")
    print("                or IETF name. Integer must be prefixed with '0x'")
    print("                if it is hexadecimal. By default uses")
    print("                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA with -d option")
    print("                RSA_WITH_AES_128_CBC_SHA without -d option.")
    print("                See tlslite.constants.CipherSuite for ciphersuite")
    print("                definitions")
    print(" --1/n-1        Expect the 1/n-1 record splitting for BEAST")
    print("                mitigation (should not be used with TLS 1.1 or up)")
    print(" --0/n          Expect the 0/n record splitting for BEAST")
    print("                mitigation (should not be used with TLS 1.1 or up)")
    print(" --help         this message")


def main():
    """Check if incorrect padding and MAC is rejected by server."""
    host = "localhost"
    port = 4433
    num_limit = 1024
    rand_limit = 4096
    run_exclude = set()
    dhe = False
    cipher = None
    splitting = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:dC:", ["help", "random=",
                                                    "1/n-1", "0/n"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '--random':
            rand_limit = int(arg)
        elif opt == '-d':
            dhe = True
        elif opt == '--1/n-1':
            splitting = 1
        elif opt == '--0/n':
            splitting = 0
        elif opt == '-C':
            if arg[:2] == '0x':
                cipher = int(arg, 16)
            else:
                try:
                    cipher = getattr(CipherSuite, arg)
                except AttributeError:
                    cipher = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if dhe and cipher is not None:
        raise ValueError("-C and -d are mutually exclusive")
    if cipher is None:
        if dhe:
            cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        else:
            cipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA

    block_size = 16
    if cipher in CipherSuite.tripleDESSuites:
        block_size = 8

    if cipher in CipherSuite.ecdhAllSuites or cipher in CipherSuite.dhAllSuites:
        dhe = True
    else:
        dhe = False

    if args:
        run_only = set(args)
    else:
        run_only = None
    # if we are to execute only some tests, we need to not filter the
    # static ones
    if run_only:
        num_limit = None

    conversations = {}

    conversation = Connect(host, port)
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
        ciphers = [cipher,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ext = None
        ciphers = [cipher,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectCertificateRequest())
    fork = node
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator())

    # handle servers which ask for client certificates
    fork.next_sibling = ExpectServerHelloDone()
    join = ClientKeyExchangeGenerator()
    fork.next_sibling.add_child(join)

    node = node.add_child(join)
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(
        ApplicationDataGenerator(b"GET / HTTP/1.0\r\n\r\n"))
    if splitting is not None:
        node = node.add_child(ExpectApplicationData(size=splitting))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity"] = \
            conversation

    # test all combinations of lengths and values for plaintexts up to 256
    # bytes long uniform content (where every byte has the same value)
    mono = (StructuredRandom([(length, value)]) for length in
            range(block_size, 257, block_size)
            for value in range(256))
    rand = structured_random_iter(rand_limit,
                                  min_length=block_size, max_length=2**14,
                                  step=block_size)
    # block size is 16 bytes for AES_128, 2**14 is the TLS protocol max
    for data in chain(mono, rand):
        conversation = Connect(host, port)
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
            ciphers = [cipher,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ext = None
            ciphers = [cipher,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectCertificateRequest())
        fork = node
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(CertificateGenerator())

        # handle servers which ask for client certificates
        fork.next_sibling = ExpectServerHelloDone()
        join = ClientKeyExchangeGenerator()
        fork.next_sibling.add_child(join)

        node = node.add_child(join)
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(replace_plaintext(
            ApplicationDataGenerator(b"I'm ignored, only type is important"),
            data.data))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node = node.add_child(ExpectClose())
        conversations["encrypted Application Data plaintext of {0}"
                      .format(data)] = \
                conversation

    # do th same thing but for handshake record
    # (note, while the type is included in the MAC, we are never
    # sending a valid MAC, so the server has only the record layer header to
    # deduce if the message needs special handling, if any)

    # test all combinations of lengths and values for plaintexts up to 256
    # bytes long uniform content (where every byte has the same value)
    mono = (StructuredRandom([(length, value)]) for length in
            range(block_size, 257, block_size)
            for value in range(256))
    rand = structured_random_iter(rand_limit,
                                  min_length=block_size, max_length=2**14,
                                  step=block_size)
    # block size is 16 bytes for AES_128, 2**14 is the TLS protocol max
    for data in chain(mono, rand):
        conversation = Connect(host, port)
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
            ciphers = [cipher,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ext = None
            ciphers = [cipher,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectCertificateRequest())
        fork = node
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(CertificateGenerator())

        # handle servers which ask for client certificates
        fork.next_sibling = ExpectServerHelloDone()
        join = ClientKeyExchangeGenerator()
        fork.next_sibling.add_child(join)

        node = node.add_child(join)
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(replace_plaintext(
            FinishedGenerator(),
            data.data))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node = node.add_child(ExpectClose())
        conversations["encrypted Handshake plaintext of {0}".format(data)] = \
                conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

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
            failed.append(c_name)

    print("Tester for de-padding and MAC verification\n")
    print("Generates plaintexts that can be incorrectly handled by de-padding")
    print("and MAC verification algorithms and verifies that they are handled")
    print("correctly and consistently.\n")
    print("Should be executed with multiple ciphers (especially regarding the")
    print("HMAC used) and TLS versions. Note: test requires CBC mode")
    print("ciphers.\n")
    print("TLS 1.0 servers should require enabling BEAST workaround, see")
    print("help message.\n")
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
