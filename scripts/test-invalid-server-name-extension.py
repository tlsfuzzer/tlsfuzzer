# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Tests for SNI"""
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
        ExpectAlert, ExpectClose, ExpectApplicationData

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, HashAlgorithm, SignatureAlgorithm, NameType
from tlslite.extensions import TLSExtension, SignatureAlgorithmsExtension, \
        SNIExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import RSA_SIG_ALL
from tlsfuzzer.utils.lists import natural_sort_keys


version = 5


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
    print(" --sni hostname name the server expects to receive with SNI")
    print("                \"localhost\" by default")
    print(" --sni-fatal    expect unrecognised names to be fatal alerts")
    print(" --help         this message")


def main():
    """check if server handles malformed server name indication extension"""
    host = "localhost"
    hostname = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    sni_fatal = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:n:e:x:X:", ["help", "sni=", "sni-fatal"])
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
        elif opt == '--sni':
            hostname = arg
        elif opt == '--sni-fatal':
            sni_fatal = True
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    # sanity check without SNI
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertDescription.close_notify))
    node = node.add_child(ExpectClose())
    node.next_sibling = ExpectAlert(AlertLevel.warning,
                                    AlertDescription.close_notify)
    node.next_sibling.add_child(ExpectClose())
    conversations["sanity"] = conversation

    # sanity check SNI
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    sni = SNIExtension().create(bytearray(hostname, 'utf-8'))
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertDescription.close_notify))
    node = node.add_child(ExpectClose())
    node.next_sibling = ExpectAlert(AlertLevel.warning,
                                    AlertDescription.close_notify)
    node.next_sibling.add_child(ExpectClose())
    conversations["Sanity check, SNI"] = conversation

    # empty SNI extension
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    sni = TLSExtension(extType=ExtensionType.server_name).create(bytearray(0))
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["Empty SNI extension"] = conversation

    # empty host list
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    sni = SNIExtension().create(serverNames=[])
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["Empty host list in SNI extension"] = conversation

    # empty host name
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    sni = SNIExtension().create(hostNames=[bytearray(0)])
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["Empty hostname in SNI extension"] = conversation

    # trailing data in extension
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    payload = bytearray(b'\x00\x04'  # overall length
                        b'\x00'      # type - host_name
                        b'\x00\x01'  # length of host name
                        b'e'         # host name
                        b'x'         # trailing data
                        )
    sni = TLSExtension(extType=ExtensionType.server_name).create(payload)
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["Trailing data in extension"] = conversation

    # incorrect host name
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    sni = SNIExtension().create(bytearray(b'www.') +
                                bytearray(hostname, 'utf-8'))
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    if sni_fatal:
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.unrecognized_name))
        node = node.add_child(ExpectClose())
    else:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.unrecognized_name))
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertDescription.close_notify))
        node = node.add_child(ExpectClose())
        node.next_sibling = ExpectAlert(AlertLevel.warning,
                                        AlertDescription.close_notify)
        node.next_sibling.add_child(ExpectClose())
    conversations["incorrect SNI"] = conversation

    # SNI name with NULL
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    # names MUST be valid DNS host names
    sni = SNIExtension().create(bytearray(hostname[:-1], 'utf-8') +
                                bytearray(b'\x00') +
                                bytearray(hostname[-1:], 'utf-8'))
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())

    conversations["SNI name with NULL"] = conversation

    # SNI name with special character
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    # names MUST be valid DNS host names
    sni = SNIExtension().create(bytearray(hostname[:-1], 'utf-8') +
                                bytearray(b'\x07') +
                                bytearray(hostname[-1:], 'utf-8'))
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())

    conversations["SNI name with BEL"] = conversation

    # SNI name with UTF-8 character
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    # names MUST be valid DNS host names
    sni = SNIExtension().create(bytearray(hostname[:-1], 'utf-8') +
                                bytearray(b'\xc4\x85') +
                                bytearray(hostname[-1:], 'utf-8'))
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())

    conversations["SNI name with UTF-8"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    # names MUST be valid DNS host names
    sni = SNIExtension().create(bytearray(hostname, 'utf-8') +
                                bytearray(b'\x1b[31mBAD\x1b[0;37m'))
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())

    conversations["SNI name with ANSI color escapes code"] = conversation


    # malformed extension
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.server_name: lambda _:TLSExtension().create(0, bytearray(b'\xff'*4))}
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["malformed overall length"] = conversation

    # multiple names in SNI
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    # RFC 6066 client MUST NOT send two names of the same type
    sni = SNIExtension().create(hostNames=[bytearray(hostname, 'utf-8'),
                                           bytearray(b'www.') +
                                           bytearray(hostname, 'utf-8')])
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["multiple host_names in SNI, RFC 6066 compliance"] = conversation

    # multiple types in SNI
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    names = [SNIExtension.ServerName(NameType.host_name,
                                     bytearray(hostname, 'utf-8')),
             # some unknown SNI type, should be ignored by server
             SNIExtension.ServerName(NameType.host_name + 1,
                                     bytearray(range(0, 24)))]
    sni = SNIExtension().create(serverNames=names)
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertDescription.close_notify))
    node = node.add_child(ExpectClose())
    node.next_sibling = ExpectAlert(AlertLevel.warning,
                                    AlertDescription.close_notify)
    node.next_sibling.add_child(ExpectClose())
    conversations["multiple types in SNI, host_name first"] = conversation

    # multiple types in SNI, host_name last
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create([
             (getattr(HashAlgorithm, x),
              SignatureAlgorithm.rsa) for x in ['sha512', 'sha384', 'sha256',
                                                'sha224', 'sha1']]),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    names = [# some unknown SNI type, should be ignored by server
             SNIExtension.ServerName(NameType.host_name + 1,
                                     bytearray(range(0, 24))),
             # actual SNI payload
             SNIExtension.ServerName(NameType.host_name,
                                     bytearray(hostname, 'utf-8'))]
    sni = SNIExtension().create(serverNames=names)
    ext[ExtensionType.server_name] = sni
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(b"GET / HTTP/1.0\n\n"))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertDescription.close_notify))
    node = node.add_child(ExpectClose())
    node.next_sibling = ExpectAlert(AlertLevel.warning,
                                    AlertDescription.close_notify)
    node.next_sibling.add_child(ExpectClose())
    # hangs gnutls-serv
    conversations["multiple types in SNI, host_name last"] = conversation


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

    print("SNI extension test")

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
