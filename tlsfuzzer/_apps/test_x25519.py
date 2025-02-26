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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        TCPBufferingEnable, TCPBufferingFlush, \
        TCPBufferingDisable
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, HashAlgorithm, SignatureAlgorithm, GroupName, \
        ECPointFormat
from tlslite.utils.x25519 import X25519_ORDER_SIZE, X448_ORDER_SIZE
from tlslite.extensions import SignatureAlgorithmsExtension, TLSExtension, \
        SupportedGroupsExtension, ECPointFormatsExtension, \
        SignatureAlgorithmsCertExtension
from tlslite.utils.cryptomath import numberToByteArray
from tlsfuzzer.helpers import RSA_SIG_ALL
from tlsfuzzer.utils.lists import natural_sort_keys


version = 5


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [-g] [[probe-name] ...]")
    print(" -h hostname         name of the host to run the test against")
    print("                     localhost by default")
    print(" -p port             port number to use for connection, 4433 by default")
    print(" probe-name          if present, will run only the probes with given")
    print("                     names and not all of them, e.g \"sanity\"")
    print(" -e probe-name       exclude the probe from the list of the ones run")
    print("                     may be specified multiple times")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" --no-default-group  expect that sending no curves means accepting none")
    print("                     (violates RFC4492#section-4 in a sane and trendy way:")
    print("                      see https://github.com/openssl/openssl/pull/1597)")
    print(" --help              this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None

    no_default_group = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:x:X:", ["help", "no-default-group"])
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
        elif opt == '--no-default-group':
            no_default_group = True
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    # check if server selects ECDHE when fully specified
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.secp256r1,
              GroupName.secp384r1,
              GroupName.secp521r1]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    node = node.add_child(ExpectServerHello(version=(3, 3),
                                            cipher=cipher))
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

    if not no_default_group:
        # check if server selects compatible group if none is selected
        conversation = Connect(host, port)
        node = conversation
        sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
                (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
                (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
        ext = {ExtensionType.signature_algorithms:
                SignatureAlgorithmsExtension().create(sigs),
               ExtensionType.signature_algorithms_cert:
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        node = node.add_child(ExpectServerHello(version=(3, 3),
                                                cipher=cipher))
        node = node.add_child(ExpectCertificate())
        groups = [GroupName.secp256r1]
        node = node.add_child(ExpectServerKeyExchange(valid_groups=groups))
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
        conversations["default to P-256 when no groups specified"] = conversation

        # check if server selects compatible group and hash when none specified
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers))
        cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        node = node.add_child(ExpectServerHello(version=(3, 3),
                                                cipher=cipher))
        node = node.add_child(ExpectCertificate())
        groups = [GroupName.secp256r1]
        node = node.add_child(ExpectServerKeyExchange(valid_groups=groups))
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
        conversations["default to P-256/sha-1 when no extensions specified"] = conversation

    else:

        # check if server treats the absence of 'supported_groups' as
        # 'nothing is supported'; see, for example,
        # https://github.com/openssl/openssl/pull/1597#issuecomment-248302514
        conversation = Connect(host, port)
        node = conversation
        sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
                (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
                (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
        ext = {ExtensionType.signature_algorithms:
                SignatureAlgorithmsExtension().create(sigs),
               ExtensionType.signature_algorithms_cert:
                SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        node = node.add_child(ExpectServerHello(version=(3, 3),
                                                cipher=cipher))
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
        conversations["fallback to DHE when no groups specified"] = conversation

        # check if server selects compatible group and hash when none specified
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers))
        cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
        node = node.add_child(ExpectServerHello(version=(3, 3),
                                                cipher=cipher))
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
        conversations["fallback to DHE when no extensions specified"] = conversation

    # check if server will fallback to to other cipher when no groups
    # are acceptable
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.sect163k1]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    node = node.add_child(ExpectServerHello(version=(3, 3),
                                            cipher=cipher))
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
    conversations["only secp163k1 group - fallback to DHE"] = conversation

    # check if server will fallback to to other cipher when no groups
    # are defined
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [11200]  # unknown ECDHE group
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    node = node.add_child(ExpectServerHello(version=(3, 3),
                                            cipher=cipher))
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
    conversations["only unknown group - fallback to DHE"] = conversation

    # check if server will abort if no group is acceptable and no fallback
    # is possible
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [11200]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.handshake_failure))
    node = node.add_child(ExpectClose())
    conversations["only unknown group - no fallback to DHE"] = conversation

    # check if server will not negotiate x25519
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519,
              GroupName.x448]
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
    conversations["only x25519 and x448 groups - allow for DHE fallback"] = conversation

    # check if server will abort if x25519 is not support
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519,
              GroupName.x448]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
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
    conversations["only x25519 and x448 groups - no fallback to DHE possible"] = conversation

    # check if server will negotiate X25519 with compression supported
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.ec_point_formats] = \
            ECPointFormatsExtension().create([ECPointFormat.ansiX962_compressed_prime,
                                              ECPointFormat.ansiX962_compressed_char2,
                                              ECPointFormat.uncompressed])
    groups = [GroupName.x25519]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
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
    conversations["EC point format - all types - x25519"] = conversation

    # check if server will negotiate X25519 with typical EC point format ext
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    ext[ExtensionType.ec_point_formats] = \
            ECPointFormatsExtension().create([ECPointFormat.uncompressed])
    groups = [GroupName.x25519]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
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
    conversations["EC point format - only uncompressed - x25519"] = conversation

    # check if server will negotiate X25519
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
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
    conversations["sanity - negotiate x25519"] = conversation

    # check if server will negotiate X448
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x448]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
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
    conversations["sanity - negotiate x448"] = conversation

    # check if server will reject too small x25519 share
    # (one with too few bytes in the key share)
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=bytearray([55] * (X25519_ORDER_SIZE - 1))))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["too small x25519 key share"] = conversation

    # check if server will reject empty x25519 share
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(ecdh_Yc=bytearray()))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    # since the ECPoint is defined as <1..2^8-1>, zero length value is an
    # incorrect encoding
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["empty x25519 key share"] = conversation

    # check if server will reject too big x25519 share
    # (one with too many bytes in the key share)
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=bytearray([55] * (X25519_ORDER_SIZE + 1))))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["too big x25519 key share"] = conversation

    # check if server will reject x25519 share with high order bit set
    # per draft-ietf-tls-rfc4492bis:
    #
    # Since there are some implementation of the X25519 function that
    # impose this restriction on their input and others that don't,
    # implementations of X25519 in TLS SHOULD reject public keys when the
    # high-order bit of the final byte is set
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519]  # ecdh_x25519
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=bytearray([55] * (X25519_ORDER_SIZE - 1) + [0x80])))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    # Because we are sending a key exchange with a public value for which
    # we do not know the private valye, the Finished message will be encrypted
    # using incorrect keys, so expect a failure that shows that
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.bad_record_mac))
    node = node.add_child(ExpectClose())
    conversations["x25519 key share with high bit set"] = conversation

    # check if server will reject empty x448 share
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x448]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(ecdh_Yc=bytearray()))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    # since the ECPoint is defined as <1..2^8-1>, zero length value is an
    # incorrect encoding
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["empty x448 key share"] = conversation

    # check if server will reject too small x448 share
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x448]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=bytearray([55] * (X448_ORDER_SIZE - 1))))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["too small x448 key share"] = conversation

    # check if server will reject too big x448 share
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x448]  # ecdh_x448
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=bytearray([55] * (X448_ORDER_SIZE + 1))))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["too big x448 key share"] = conversation

    # check if server will reject an all-zero key share for x25519
    # (it should result in all-zero shared secret)
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=bytearray(X25519_ORDER_SIZE)))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["all zero x25519 key share"] = conversation

    # check if server will reject an all-zero key share for x448
    # (it should result in all-zero shared secret)
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x448]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=bytearray(X448_ORDER_SIZE)))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["all zero x448 key share"] = conversation

    # check if server will reject a key share or 1 for x25519
    # (it should result in all-zero shared secret)
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x25519]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=numberToByteArray(1, X25519_ORDER_SIZE, "little")))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["x25519 key share of \"1\""] = conversation

    # check if server will reject a key share of 1 for x448
    # (it should result in all-zero shared secret)
    conversation = Connect(host, port)
    node = conversation
    sigs = [(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            (HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
    ext = {ExtensionType.signature_algorithms:
            SignatureAlgorithmsExtension().create(sigs),
           ExtensionType.signature_algorithms_cert:
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)}
    groups = [GroupName.x448]
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=ext))
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        ecdh_Yc=numberToByteArray(1, X448_ORDER_SIZE, "little")))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.illegal_parameter))
    node = node.add_child(ExpectClose())
    conversations["x448 key share of \"1\""] = conversation


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

    print("Basic test to verify that server selects sane ECDHE parameters and")
    print("ciphersuites when x25519 curve is an option\n")

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
