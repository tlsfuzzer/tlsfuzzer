# Author: Hubert Kario, (c) 2015-2019
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Check for SSLv2 Client Hello support for negotiating TLS"""
from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        RawMessageGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectApplicationData, \
        ExpectServerKeyExchange
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, ContentType, GroupName
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import RSA_SIG_ALL


version = 7


def help_msg():
    """Usage information"""
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
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" --no-ssl2      expect the server to not support SSL2 Client Hello")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" --help         this message")


def main():
    """
    Check SSLv2Hello support

    Test if the server supports SSLv2-style Client Hello messages for
    negotiating TLS connections
    """
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    no_ssl2 = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:d", ["help", "no-ssl2"])
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
            dhe = True
        elif opt == '--no-ssl2':
            no_ssl2 = True
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
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    if no_ssl2:
        # any unassigned ciphers are ok, they just work as padding
        # we use them to set the length byte of the cipher list in SSLv2 to
        # value that will cause the packet to be rejected when parsed as SSLv3
        ciphers += [0x0a00 + i for i in range(1, 1+256-len(ciphers))]
        # here we are verifying just that the server will not fall over when it
        # receives them
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext={ExtensionType.renegotiation_info:None}
    node = node.add_child(ExpectServerHello(extensions=ext))
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
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.child = ExpectClose()
    # if we're doing TLSv1.0 the server should be doing 1/n-1 splitting
    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling
    node.next_sibling = ExpectClose()

    conversations["sanity"] = conversation

    # instruct RecordLayer to use SSLv2 record layer protocol (0, 2)
    conversation = Connect(host, port, version=(0, 2))
    node = conversation
    if dhe:
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    if no_ssl2:
        # to create a SSLv2 CH that is clearly broken SSLv3 CH we need
        # SSLv2 CH with a list of ciphers that has length divisible by 256
        # (as cipher IDs in SSLv2 are 3 byte long, 256*3 is the smallest common
        # multiple of 3 and 256)
        ciphers += [0x0a00 + i for i in range(1, 1+256-len(ciphers))]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               ssl2=True))
    if no_ssl2:
        node = node.add_child(ExpectAlert())
        node.add_child(ExpectClose())
    else:
        ext={ExtensionType.renegotiation_info:None}
        node = node.add_child(ExpectServerHello(extensions=ext))
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
            bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.child = ExpectClose()
        # if we're doing TLSv1.0 the server should be doing 1/n-1 splitting
        node.next_sibling = ExpectApplicationData()
        node = node.next_sibling
        node.next_sibling = ExpectClose()

    conversations["SSLv2 Client Hello"] = conversation

    conversation = Connect(host, port, version=(0, 2))
    node = conversation
    node = node.add_child(RawMessageGenerator(ContentType.handshake,
                                              bytearray()))
    if dhe:
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    if no_ssl2:
        ciphers += [0x0a00 + i for i in range(1, 1+256-len(ciphers))]
        # we depend on alignment of the SSLv2 CH ciphers length and session id
        # length with the SSLv3 CH handshake protocol length value
        # so for the same kind of test, we need to send 0 bytes as the 7th to
        # 9th byte
        # the first message is two bytes so it will be interpreted as
        # protocol \x80 and first byte of version \x00
        # then this header will be interpreted as second byte of version \x80
        # and first byte of length - we thus need to send something that is
        # multiple of 256
        data = bytearray(b'\x04' +  # will be interpreted as second byte of
                                    # SSLv3 RecordLayer header
                         b'\x01' +  # will be interpreted as handshake protocol
                                    # message type - client_hello
                         b'\x00' * 3 + # length of handshake message - 0 bytes
                                    # (invalid)
                         b'\xff' * (256-5) # padding needed to bring SSLv2
                                    # record length to be multiple of 256
                        )
        assert len(data) % 256 == 0
        node = node.add_child(RawMessageGenerator(0, data))
    else:
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   ssl2=True))
    # SSLv2 does not have well defined error handling, so usually errors
    # just cause connection close. But sending TLS alert is correct too.
    node = node.add_child(ExpectAlert())
    if not no_ssl2:
        # but be strict with Alerts when SSLv2 is not supported
        node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["Empty SSLv2 record"] = conversation

    conversation = Connect(host, port, version=(0, 2))
    node = conversation
    node = node.add_child(RawMessageGenerator(ContentType.handshake,
                                              bytearray(1)))
    if dhe:
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    if no_ssl2:
        ciphers += [0x0a00 + i for i in range(1, 1+256-len(ciphers))]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               ssl2=True))
    node = node.add_child(ExpectAlert())
    if not no_ssl2:
        node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["Empty SSLv2 record - type 0"] = conversation

    conversation = Connect(host, port, version=(0, 2))
    node = conversation
    node = node.add_child(RawMessageGenerator(ContentType.handshake,
                                              bytearray([1])))
    if dhe:
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    if no_ssl2:
        ciphers += [0x0a00 + i for i in range(1, 1+256-len(ciphers))]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               ssl2=True))
    node = node.add_child(ExpectAlert())
    if not no_ssl2:
        node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["Empty SSLv2 record - type 1"] = conversation

    conversation = Connect(host, port, version=(0, 2))
    node = conversation
    node = node.add_child(RawMessageGenerator(ContentType.handshake,
                                              bytearray(b'\x01\x03\x03')))
    if dhe:
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    if no_ssl2:
        ciphers += [0x0a00 + i for i in range(1, 1+256-len(ciphers))]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               ssl2=True))
    node = node.add_child(ExpectAlert())
    if not no_ssl2:
        node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())

    conversations["Just version in SSLv2 hello"] = conversation


    # run the conversations
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

    print("Basic test for SSLv2 Hello protocol for TLS 1.0 to TLS 1.2 "
          "negotiation")
    print("Checks if the server can negotiate TLS when client initiated the")
    print("connection using a SSLv2 compatible ClientHello but included TLS")
    print("compatible ciphersuites")
    print("Alternatively, verifies that SSLv2 records are rejected when run")
    print("with --no-ssl2 option\n")
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
