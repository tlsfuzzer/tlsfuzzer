# Author: Hubert Kario, (c) 2015-2022
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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, Close, \
        SetMaxRecordSize
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
        TLSExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import SIG_ALL, AutoEmptyExtension


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
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num         run 'num' or all(if 0) tests instead of default(1000)")
    print("                (\"sanity\" tests are always executed)")
    print(" -d             use TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256")
    print("                instead of TLS_RSA_WITH_AES_128_CBC_SHA256")
    print(" -C cipher      ciphersuite to use for the connection,")
    print("                TLS_RSA_WITH_AES_128_CBC_SHA256 by default")
    print(" --extra-exts   send also supported_groups, signature_algorithms,")
    print("                and signature_algorithms_cert extensions in Client")
    print("                Hello. Default for DHE and ECDHE ciphers")
    print(" -t timeout     Connection and server reply timeout, in seconds.")
    print("                5 seconds by default.")
    print(" --etm          Advertise and expect encrypt_then_mac extension")
    print(" --size-limit num Send a max_fragment_length extension advertising")
    print("                num as the max size we're willing to receive.")
    print("                Valid values are 512, 1024, 2048 and 4096")
    print(" -M | --ems     Enable support for Extended Master Secret")
    print(" --help         this message")
    # already used single-letter options:
    # -m test-large-hello.py - min extension number for fuzz testing
    # -s signature algorithms sent by server
    # -k client key
    # -c client certificate
    # -z don't expect 1/n-1 record split in TLS1.0
    # -a override for expected alert description
    # -l override the expected alert level
    # -C explicit cipher for connection
    # -T expected certificates types in CertificateRequest
    # -b server is expected to have multiple (both) certificate types available
    #    at the same time
    # -t timeout to wait for messages (also count of NSTs in
    #    test-tls13-count-tickets.py)
    # -r perform renegotation multiple times
    # -S signature algorithms sent by client
    # -E additional extensions to be sent by client
    #
    # reserved:
    # -x expected fail for probe (alternative to -e)
    # -X expected failure message for probe (to be used together with -x)
    # -i enables timing the test using the specified interface
    # -o output directory for files related to collection of timing information


def main():
    host = "localhost"
    port = 4433
    num_limit = 1000
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    cipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256
    extra_exts = False
    etm = False
    size_limit = None
    timeout = 5.0
    ems = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:dC:t:M",
        ["help", "extra-exts", "etm", "size-limit=", "ems"])
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
        elif opt == '-d':
            cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        elif opt == '--extra-exts':
            extra_exts = True
        elif opt == '--etm':
            etm = True
        elif opt == '--size-limit':
            size_limit = int(arg)
            if size_limit not in (512, 1024, 2048, 4096):
                raise ValueError("Invalid size to --size-limit")
            if size_limit == 512:
                size_limit = 1
            elif size_limit == 1024:
                size_limit = 2
            elif size_limit == 2048:
                size_limit = 3
            else:
                size_limit = 4
        elif opt == '-C':
            if arg[:2] == '0x':
                cipher = int(arg, 16)
            else:
                try:
                    cipher = getattr(CipherSuite, arg)
                except AttributeError:
                    cipher = int(arg)
        elif opt == '-t':
            timeout = float(arg)
        elif opt == '-M' or opt == '--ems':
            ems = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if cipher in CipherSuite.dhAllSuites \
            or cipher in CipherSuite.ecdhAllSuites:
        extra_exts = True
        dhe = True

    if args:
        run_only = set(args)
        num_limit = None
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port, timeout=timeout)
    node = conversation
    ext = {}
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if extra_exts:
        groups = [GroupName.secp256r1,
                  GroupName.secp384r1,
                  GroupName.secp521r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if etm:
        ext[ExtensionType.encrypt_then_mac] = AutoEmptyExtension()
    if size_limit:
        ext[ExtensionType.max_fragment_length] = \
            TLSExtension(extType=1).create(bytearray([size_limit]))
    if not ext:
        ext = None
    ciphers = [cipher,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    srv_ext = {ExtensionType.renegotiation_info: None}
    if etm:
        srv_ext[ExtensionType.encrypt_then_mac] = None
    if ems:
        srv_ext[ExtensionType.extended_master_secret] = None
    if size_limit:
        srv_ext[ExtensionType.max_fragment_length] =\
            TLSExtension(extType=1).create(bytearray([size_limit]))
    node = node.add_child(ExpectServerHello(extensions=srv_ext))
    if size_limit:
        node = node.add_child(SetMaxRecordSize(2**(8+size_limit)))
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
    node.add_child(Close())
    conversations["sanity"] = conversation

    lengths = range(1, 2**14 + 1)
    if num_limit:
        lengths = sample(lengths, num_limit)

    for data_len in lengths:
        conversation = Connect(host, port, timeout=timeout)
        node = conversation
        ext = {}
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        if extra_exts:
            groups = [GroupName.secp256r1,
                      GroupName.secp384r1,
                      GroupName.secp521r1,
                      GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIG_ALL)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        if etm:
            ext[ExtensionType.encrypt_then_mac] = AutoEmptyExtension()
        if size_limit:
            ext[ExtensionType.max_fragment_length] =\
                TLSExtension(extType=1).create(bytearray([size_limit]))
        if not ext:
            ext = None
        ciphers = [cipher,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        srv_ext = {ExtensionType.renegotiation_info: None}
        if etm:
            srv_ext[ExtensionType.encrypt_then_mac] = None
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        if size_limit:
            srv_ext[ExtensionType.max_fragment_length] =\
                TLSExtension(extType=1).create(bytearray([size_limit]))
        node = node.add_child(ExpectServerHello(extensions=srv_ext))
        if size_limit:
            node = node.add_child(SetMaxRecordSize(2**(8+size_limit)))
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        if size_limit == 4 and data_len == 16384:
            node = node.add_child(ApplicationDataGenerator(
                bytearray((b"A" * 4095 + b"\n") * 4)))
        else:
            node = node.add_child(ApplicationDataGenerator(
                bytearray(b"A" * (data_len - 1) + b"\n")))
        if size_limit:
            for i in range(data_len // 2**(8 + size_limit)):
                node = node.add_child(ExpectApplicationData(
                    size=2**(8 + size_limit),
                    description=str(i)))
            if data_len % 2**(8 + size_limit):
                node = node.add_child(ExpectApplicationData(
                    size=data_len % 2**(8 + size_limit),
                    description="last"))
        else:
            node = node.add_child(ExpectApplicationData(size=data_len))
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["length: {0}".format(data_len)] = conversation

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
    run_sanity = True
    if run_only:
        if len(run_only) == 1 and 'sanity' in run_only:
            run_sanity = False
            regular_tests = sanity_tests
        else:
            if not 'sanity' in run_only:
                run_sanity = False
            regular_tests = [(k, v) for k, v in conversations.items() if
                             k in run_only and (k != 'sanity')]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    if run_sanity:
        ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)
    else:
        ordered_tests = sampled_tests

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

    print("Check if different lengths of plaintext are handled correctly.")
    print("Test expects the server to reply with plaintext of the same length")
    print("it sent, that's usually called an 'echo' mode in test servers.")
    print("For full test coverage you should execute it with all valid")
    print("combinations of cipher (AES-128, AES-256, 3DES, etc.), all valid")
    print("cipher modes (CBC, GCM, CCM, etc.), all valid HMACs (SHA1, SHA256,")
    print("SHA384, etc.), EtM vs MtE for CBC ciphersuites and")
    print("max_fragment_length extension.")
    print()

    print("Test end")
    print("Cipher used: {0}".format(CipherSuite.ietfNames[cipher]))
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    if run_sanity:
        print("TOTAL: {0}".format(len(sampled_tests) + 2 * len(sanity_tests)))
    else:
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
