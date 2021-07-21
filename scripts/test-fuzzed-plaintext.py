# Author: Hubert Kario, (c) 2018, 2019
# Released under Gnu GPL v2.0, see LICENSE file for details
"""MAC value fuzzer"""

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain
from random import sample
from math import ceil

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        CertificateGenerator, replace_plaintext, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData, ExpectServerKeyExchange
from tlsfuzzer.fuzzers import structured_random_iter, StructuredRandom
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import SIG_ALL

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension


version = 9


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
    print(" --random count generate `count` random tests in addition to the")
    print("                basic 8192 pre-programmed ones. 8192 by default")
    print("                for ciphers with 128 bit block size and 16384 for")
    print("                ciphers with 64 bit block size.")
    # the above counts are twice as large as default rand_limit as we're
    # generating two sets of tests, one for handshake and one for
    # application_data
    print("                Vaues smaller than the default will make the")
    print("                pre-programmed tests more likely while larger")
    print("                values will make them less likely to be executed.")
    print(" -n num         run 'num' or all(if 0) tests instead of default(50)")
    print("                (excluding \"sanity\" tests)")
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


def add_dhe_extensions(extensions):
    groups = [GroupName.secp256r1,
              GroupName.ffdhe2048]
    extensions[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    extensions[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    extensions[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)


def add_app_data_conversation(conversations, host, port, cipher, dhe, data):
    conversation = Connect(host, port)
    node = conversation
    if dhe:
        ext = {}
        add_dhe_extensions(ext)
    else:
        ext = None
    ciphers = [cipher,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())

    # handle servers that ask for client certificates
    node = node.add_child(ExpectCertificateRequest())
    fork = node
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator())

    # handle servers that don't ask for client certificates
    fork.next_sibling = ExpectServerHelloDone()

    # join both paths
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


def add_handshake_conversation(conversations, host, port, cipher, dhe, data):
    conversation = Connect(host, port)
    node = conversation
    if dhe:
        ext = {}
        add_dhe_extensions(ext)
    else:
        ext = None
    ciphers = [cipher,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())

    # handle servers that ask for client certificates
    node = node.add_child(ExpectCertificateRequest())
    fork = node
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator())

    # handle servers that don't ask for client certificates
    fork.next_sibling = ExpectServerHelloDone()

    # join both paths
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


def str_to_int_or_none(text):
    if "None" in text:
        return None
    return int(text)


def parse_structured_random_params(text):
    regex = re.compile(r'.* of StructuredRandom\(vals=\[(.*)\]\)')
    match = regex.match(text)
    if not match:
        raise ValueError("Invalid name of conversation: \"{0}\"".format(text))
    values = []
    for i in re.finditer(r'\((.*?)\)', match.group(1)):
        values.extend(
            [(str_to_int_or_none(x),
              str_to_int_or_none(y))
             for x, y in [i.group(1).split(',')]])
    return values


def main():
    """Check if incorrect padding and MAC is rejected by server."""
    host = "localhost"
    port = 4433
    num_limit = 50
    rand_limit = 100
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    cipher = None
    splitting = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:dC:", ["help", "random=",
                                                     "1/n-1", "0/n"])
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
        elif opt == '--random':
            rand_limit = int(arg)//2
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

    if block_size == 8:
        rand_limit *= 2


    dhe = cipher in CipherSuite.ecdhAllSuites or \
            cipher in CipherSuite.dhAllSuites

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
        add_dhe_extensions(ext)
    else:
        ext = None
    ciphers = [cipher,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())

    # handle servers that ask for client certificates
    node = node.add_child(ExpectCertificateRequest())
    fork = node
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator())

    # handle servers that don't ask for client certificates
    fork.next_sibling = ExpectServerHelloDone()

    # join both paths
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
    # bytes long with uniform content (where every byte has the same value)
    mono_tests = [(length, value) for length in
                  range(block_size, 257, block_size)
                  for value in range(256)]
    if not num_limit:
        mono_iter = mono_tests
        rand_len_to_generate = rand_limit
    else:
        # we want to speed up generation, so generate only as many conversations
        # as necessary to meet num_limit, but do that uniformely between
        # random payloads, mono payloads, application_data tests and handshake
        # tests
        ratio = rand_limit * 1.0 / len(mono_tests)

        # `num_limit / 2` because of handshake and application_data tests
        mono_len_to_generate = min(len(mono_tests),
                                   int(ceil((num_limit / 2) * (1 - ratio))))
        rand_len_to_generate = int(ceil((num_limit) / 2 * ratio))
        mono_iter = sample(mono_tests, mono_len_to_generate)

    mono = (StructuredRandom([(length, value)]) for length, value in
            mono_iter)

    # 2**14 is the TLS protocol max
    rand = structured_random_iter(rand_len_to_generate,
                                  min_length=block_size, max_length=2**14,
                                  step=block_size)

    if not run_only:
        for data in chain(mono, rand):
            add_app_data_conversation(conversations, host, port, cipher, dhe, data)
    else:
        for conv in run_only:
            if "Application Data" in conv:
                params = parse_structured_random_params(conv)
                data = StructuredRandom(params)
                add_app_data_conversation(conversations, host, port, cipher,
                                          dhe, data)

    # do th same thing but for handshake record
    # (note, while the type is included in the MAC, we are never
    # sending a valid MAC, so the server has only the record layer header to
    # deduce if the message needs special handling, if any)

    # test all combinations of lengths and values for plaintexts up to 256
    # bytes long with uniform content (where every byte has the same value)
    mono_tests = [(length, value) for length in
                  range(block_size, 257, block_size)
                  for value in range(256)]
    if not num_limit:
        mono_iter = mono_tests
        rand_len_to_generate = rand_limit
    else:
        # we want to speed up generation, so generate only as many conversations
        # as necessary to meet num_limit, but do that uniformely between
        # random payloads, mono payloads, application_data tests and handshake
        # tests
        ratio = rand_limit * 1.0 / len(mono_tests)

        # `num_limit / 2` because of handshake and application_data tests
        mono_len_to_generate = min(len(mono_tests),
                                   int(ceil((num_limit / 2) * (1 - ratio))))
        rand_len_to_generate = int(ceil((num_limit) / 2 * ratio))
        mono_iter = sample(mono_tests, mono_len_to_generate)

    mono = (StructuredRandom([(length, value)]) for length, value in
            mono_iter)

    # 2**14 is the TLS protocol max
    rand = structured_random_iter(rand_len_to_generate,
                                  min_length=block_size, max_length=2**14,
                                  step=block_size)

    if not run_only:
        for data in chain(mono, rand):
            add_handshake_conversation(conversations, host, port, cipher, dhe,
                                       data)
    else:
        for conv in run_only:
            if "Handshake" in conv:
                params = parse_structured_random_params(conv)
                data = StructuredRandom(params)
                add_handshake_conversation(conversations, host,
                                           port, cipher,
                                           dhe, data)

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
        regular_tests = [(k, v) for k, v in conversations.items() if k in run_only]
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

    print("Tester for de-padding and MAC verification\n")
    print("Generates plaintexts that can be incorrectly handled by de-padding")
    print("and MAC verification algorithms and verifies that they are handled")
    print("correctly and consistently.\n")
    print("Should be executed with multiple ciphers (especially regarding the")
    print("HMAC used) and TLS versions. Note: test requires CBC mode")
    print("ciphers.\n")
    print("TLS 1.0 servers should require enabling BEAST workaround, see")
    print("help message.\n")

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
