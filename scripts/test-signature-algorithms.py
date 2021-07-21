# Author: Hubert Kario, (c) 2016
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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, Close, \
        fuzz_message
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType, SignatureScheme, \
        GroupName
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension, SupportedGroupsExtension
from tlsfuzzer.helpers import RSA_SIG_ALL, SIG_ALL, ECDSA_SIG_ALL
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.utils.lists import natural_sort_keys


version = 6


def help_msg():
    print("Usage: <script-name> [-h hostname] [OPTIONS] [[probe-name] ...]")
    print(" --alert name   name of the expected alert for malformed messages")
    print("                decode_error by default (as per standard)")
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
    print(" --no-sha1      expect conversations with explicit/implicit sha1")
    print("                to fail")
    print(" --ecdsa        Use ecdsa sigalgs instead of rsa.")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    fatal_alert = "decode_error"
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    no_sha1 = False
    expected_signature = SignatureAlgorithm.rsa
    expected_sig_list = RSA_SIG_ALL

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:x:X:", ["help", "alert=", "no-sha1", "ecdsa"])
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
        elif opt == '--alert':
            fatal_alert = arg
        elif opt == '--no-sha1':
            no_sha1 = True
        elif opt == '--ecdsa':
            expected_signature = SignatureAlgorithm.ecdsa
            expected_sig_list = ECDSA_SIG_ALL
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
    groups = [GroupName.secp256r1]
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
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
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ext = {}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3), extensions=ext))
    if no_sha1:
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node.next_sibling.add_child(ExpectClose())
        alt = node.next_sibling
        node = node.add_child(ExpectCertificate())
        node.add_child(alt)
    else:
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        # implicit SHA-1 check from Client Hello ext
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
    conversations["implicit SHA-1 check"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sigs = [(HashAlgorithm.sha1, expected_signature)]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    if no_sha1:
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.handshake_failure))
        node = node.add_child(ExpectClose())
    else:
        node = node.add_child(ExpectServerHello(version=(3, 3)))
        node = node.add_child(ExpectCertificate())
        # implicit SHA-1 check from Client Hello ext
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
    conversations["explicit SHA-1+RSA/ECDSA"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sigs = [(HashAlgorithm.sha256, expected_signature)]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    # implicit SHA-256 check from Client Hello ext
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
    conversations["explicit SHA-256+RSA or ECDSA"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sigs = [(0, expected_signature),
            (HashAlgorithm.sha256, expected_signature)]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
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
    conversations["tolerance none+RSA or ECDSA"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sigs = [(10, expected_signature),
            (HashAlgorithm.sha256, expected_signature)]
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
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
    conversations["tolerance 10+RSA or ECDSA method"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sigs = list(chain(
        ((i, expected_signature) for i in range(10, 224)),
        [(HashAlgorithm.sha256, expected_signature)]))
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
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
    conversations["tolerance 215 RSA or ECDSA methods"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sigs = list(chain(
        ((i, j) for i in range(10, 224) for j in range(10, 21)),
        [(HashAlgorithm.sha256, expected_signature)]))
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    # OpenSSL sends the list of advertised and it doesn't fit a single
    # application data
    node = node.add_child(Close())
    conversations["tolerance 2355 RSA or ECDSA methods"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sigs = list(chain(
        ((i, j) for i in range(10, 224) for j in range(21, 59)),
        [(HashAlgorithm.sha256, expected_signature)]))
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(Close())  # OpenSSL lists them, which makes the response huge
    conversations["tolerance 8132 RSA or ECDSA methods"] = conversation


    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sig_alg = SignatureAlgorithmsExtension()
    sig_alg.create(list(chain(
        ((i, j) for i in range(10, 224) for j in range(10, 121)),
        [(HashAlgorithm.sha256, expected_signature)])))
    ext = {ExtensionType.signature_algorithms: sig_alg}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(Close())  # OpenSSL lists them, which makes the response huge
    conversations["tolerance 23754 RSA or ECDSA methods"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sig_alg = SignatureAlgorithmsExtension()
    # generate maximum number of methods (4 bytes for extensions header,
    # 2 bytes for length of list inside extension, leaving 65528 bytes)
    sig_alg.create(list(chain(
        ((i, j) for i in range(10, 224) for j in range(10, 163)),
        ((i, 163) for i in range(10, 27)),
        [(HashAlgorithm.sha256, expected_signature)])))
    ext = {ExtensionType.signature_algorithms: sig_alg}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(Close())  # OpenSSL lists them, which makes the response huge
    conversations["tolerance max (32760) number of methods"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    # generate maximum number of methods for 2 extensions
    # (4 bytes for extensions header, 2 bytes for length of list inside
    # extension leaving 65522 bytes)
    sigs = list(chain(
        ((i, j) for i in range(10, 224) for j in range(10, 86)),
        ((i, 163) for i in range(10, 123)),
        [(HashAlgorithm.sha256, expected_signature)]))
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(sigs)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(Close())  # OpenSSL lists them, which makes the response huge
    conversations["tolerance 32758 methods with sig_alg_cert"] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    # generate maximum number of methods for 2 extensions
    # (4 bytes for extensions header, 2 bytes for length of list inside
    # extension leaving 65522 bytes)
    n = 32757
    n = n - 1  # this is the mandatory method in the end
    n = n - len(expected_sig_list)  # number of methods in sig_alg_cert extension
    sigs = list(chain(
        ((i, j) for i in range(10, 224) for j in range(10, (n // 214) + 10)),
        ((i, 163) for i in range(10, (n % 214) + 10)),
        [(HashAlgorithm.sha256, expected_signature)]))
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    valid = [(HashAlgorithm.sha256, expected_signature)]
    node = node.add_child(ExpectServerKeyExchange(valid_sig_algs=valid))
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(Close())  # OpenSSL lists them, which makes the response huge
    conversations["tolerance max {0} number of methods with sig_alg_cert".format(n)] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    sigs = []
    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(SIG_ALL)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
    .create(groups)
    hello = ClientHelloGenerator(ciphers, version=(3, 3),
                                 extensions=ext)
    node = node.add_child(hello)
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      getattr(AlertDescription, fatal_alert)))
    node = node.add_child(ExpectClose())
    conversations["empty list of signature methods"] = \
            conversation

    # generate maximum number of methods for 2 extensions
    # (4 bytes for extensions header, 2 bytes for length of list inside
    # extension leaving 65522 bytes)
    for n in [215, 2355, 8132, 23754, 32757]:
        conversation = Connect(host, port)
        node = conversation
        groups = [GroupName.secp256r1]
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        n = n - 1  # this is the mandatory method in the end
        n = n - len(expected_sig_list)  # number of methods in sig_alg_cert extension
        sigs = [(HashAlgorithm.sha1, SignatureAlgorithm.dsa)] * n
        sigs += [(HashAlgorithm.sha256, expected_signature)]
        ext = {ExtensionType.signature_algorithms :
               SignatureAlgorithmsExtension().create(sigs),
               ExtensionType.signature_algorithms_cert :
               SignatureAlgorithmsCertExtension().create(expected_sig_list)}
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
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

        # ApplicationData message may show up 1 to many times
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                              AlertDescription.close_notify))
        cycle_alert = ExpectAlert()
        node = node.add_child(cycle_alert)
        node.next_sibling = ExpectApplicationData()
        node.next_sibling.add_child(cycle_alert)
        node.next_sibling.next_sibling = ExpectClose()

        conversations["duplicated {0} non-rsa schemes".format(n)] = conversation

    conversation = Connect(host, port)
    node = conversation
    groups = [GroupName.secp256r1]
    ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    # Add all supported sig_algs, put rsa(or ecdsa if --ecdsa used) at the end
    first = 'ecdsa'
    last = 'rsa'
    if expected_signature == SignatureAlgorithm.ecdsa:
        first = 'rsa'
        last = 'ecdsa'
    sig_algs = []
    for sig_alg in [first, 'dsa']:
        sig_algs += [(getattr(HashAlgorithm, x), getattr(SignatureAlgorithm, sig_alg))\
                      for x in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']]
    sig_algs += [SignatureScheme.rsa_pss_rsae_sha256,
                 SignatureScheme.rsa_pss_rsae_sha384,
                 SignatureScheme.rsa_pss_rsae_sha512,
                 SignatureScheme.rsa_pss_pss_sha256,
                 SignatureScheme.rsa_pss_pss_sha384,
                 SignatureScheme.rsa_pss_pss_sha512] 
    # ed25519(0x0807), ed448(0x0808)
    sig_algs += [(8, 7), (8, 8)]
    sig_algs += [(getattr(HashAlgorithm, x), getattr(SignatureAlgorithm, last))\
                 for x in ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']]

    ext = {ExtensionType.signature_algorithms :
           SignatureAlgorithmsExtension().create(sig_algs),
           ExtensionType.signature_algorithms_cert :
           SignatureAlgorithmsCertExtension().create(expected_sig_list)}
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
    .create(groups)
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
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

    # ApplicationData message may show up 1 to many times
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                          AlertDescription.close_notify))
    cycle_alert = ExpectAlert()
    node = node.add_child(cycle_alert)
    node.next_sibling = ExpectApplicationData()
    node.next_sibling.add_child(cycle_alert)
    node.next_sibling.next_sibling = ExpectClose()

    conversations["unique and well-known sig_algs, {0} algorithm last".format(last)] = conversation

    for i in range(1, 0x100):
        conversation = Connect(host, port)
        node = conversation
        groups = [GroupName.secp256r1]
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        sig_alg = SignatureAlgorithmsExtension()
        sig_alg.create([(HashAlgorithm.sha256, expected_signature),
                        (HashAlgorithm.sha1, expected_signature)])
        ext = OrderedDict()
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
        ext[ExtensionType.signature_algorithms] = sig_alg
        hello = ClientHelloGenerator(ciphers, version=(3, 3),
                                     extensions=ext)
        node = node.add_child(fuzz_message(hello, xors={-5:i}))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          getattr(AlertDescription, fatal_alert)))
        node = node.add_child(ExpectClose())
        conversations["fuzz length inside extension to {0}".format(4^i)] = \
                conversation

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
                good+=1
                print("OK")
            else:
                bad+=1
                failed.append(c_name)

    print("Signature Algorithms in TLS 1.2")
    print("Check if valid signature algorithm extensions are accepted and")
    print("invalid properly rejected by the TLS 1.2 server.\n")
    print("")
    print("NOTE: For 'unique and well-known sig_algs..' conversation, the server")
    print("must be configured to support only rsa_pkcs1_sha512 in case of an RSA")
    print("certificate and ecdsa+sha512 in case of an ECDSA certificate.")

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
