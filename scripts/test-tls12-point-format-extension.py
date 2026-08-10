# Author: Alexander Scheel & Hubert Kario, (c) 2022
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test for RFC 8422 / Section 5.2.1 Point Format Extension"""

from __future__ import print_function
import traceback
from itertools import chain, islice
from random import sample
import sys
import re
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        AlertGenerator, Close
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectApplicationData, ExpectServerKeyExchange
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension, SupportedGroupsExtension, \
        ECPointFormatsExtension, TLSExtension
from tlslite.constants import CipherSuite, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType, GroupName, \
        ECPointFormat, AlertLevel, AlertDescription, SignatureScheme

from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import SIG_ALL


version = 1


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
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
    """check if app data records with zero payload are accepted by server"""
    conversations = {}
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None

    argv = sys.argv[1:]
    opts, argv = getopt.getopt(argv, "h:p:e:n:x:X:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
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
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if argv:
        run_only = set(argv)
    else:
        run_only = None

    conversations = {}

    # Permissive list of default ciphers, with ECDHE.
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

    # Setup the base group info; we'll duplicate this per test scenario
    # (w.r.t. point format) desired.
    ext = {}
    groups = [GroupName.secp256r1,
             GroupName.ffdhe2048]
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    ext_missing = ext.copy()

    # Extension present, no point formats supported.
    ext_assumed = ext.copy()
    ext_assumed[ExtensionType.ec_point_formats] = TLSExtension(extType=ExtensionType.ec_point_formats).create(b"")

    # Extensions with uncompressed point format.
    ext_uncompressed = ext.copy()
    ext_uncompressed[ExtensionType.ec_point_formats] = \
        ECPointFormatsExtension().create([ECPointFormat.uncompressed])

    # No uncompressed; only ANSI point formats.
    ext_ansi = ext.copy()
    ext_ansi[ExtensionType.ec_point_formats] = \
        ECPointFormatsExtension().create([
            ECPointFormat.ansiX962_compressed_prime,
            ECPointFormat.ansiX962_compressed_char2])

    # All the point formats!
    ext_all = ext.copy()
    ext_all[ExtensionType.ec_point_formats] = \
        ECPointFormatsExtension().create([ECPointFormat.uncompressed,
            ECPointFormat.ansiX962_compressed_prime,
            ECPointFormat.ansiX962_compressed_char2])

    # A handshake with format extension should pass.
    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext_uncompressed))
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
    node.add_child(Close())
    conversations["sanity"] = conversation

    # A basic handshake with no format extension should pass.
    #
    # See this comment in RFC 8422:
    #
    # > RFC 4492 specified that if this extension is missing, it means that
    # > only the uncompressed point format is supported, so interoperability
    # > with implementations that support the uncompressed format should work
    # > with or without the extension.
    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext_missing))
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
    node.add_child(Close())
    conversations["no_format_ext"] = conversation

    # A handshake with all format extensions should pass.
    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext_all))
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
    node.add_child(Close())
    conversations["all_formats"] = conversation

    # A handshake with only ANSI extensions should fail.
    #
    # See this comment in RFC 8422:
    # > If the client sends the extension and the extension does not contain
    # > the uncompressed point format, and the client has used the Supported "
    # > Groups extension to indicate support for any of the curves defined in "
    # > this specification, then the server MUST abort the handshake and "
    # > return an illegal_parameter alert.
    #
    # While we _shouldn't_ see other point formats, if we do and we
    # expect both client and server to conform to RFC 8422 (assumed
    # by this test suite), we should be able to negotiate the
    # uncompressed point format.
    #
    # However, it might also be valid to fail this request. This depends
    # on whether the server assumes a RFC 8422 client. In particular, OpenSSL
    # will send back a reply with all three point types.
    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext_ansi))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node.add_child(Close())
    conversations["only_ansi"] = conversation

    # A handshake with the point format extension (but no listed formats)
    # should fail.
    #
    # However, it might also be valid to fail this request. This depends
    # on whether the server assumes a RFC 8422 client.
    conversation = Connect(host, port)
    node = conversation
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext_assumed))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node.add_child(Close())
    conversations["ext_with_no_formats"] = conversation

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
    # to verify that server was running and kept running throught
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

    for c_name, conversation in sampled_tests:
        if c_name in run_exclude:
            continue

        print("{0} ...".format(c_name))

        runner = Runner(conversation)

        res = True
        exception = None
        #because we don't want to abort the testing and we are reporting
        #the errors to the user, using a bare except is OK
        #pylint: disable=bare-except
        try:
            runner.run()
        except Exception as exp:
            exception = exp
            print("Error while processing")
            print(traceback.format_exc())
            res = False
        #pylint: enable=bare-except

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
                good+=1
                print("OK")
            else:
                bad+=1

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
