# Author: Hubert Kario, (c) 2016
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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import RSA_SIG_ALL


version = 2


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" --tls-1.3      server does support TLS 1.3")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    run_exclude = set()
    dhe = False
    tls13 = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:d", ["help", "tls-1.3"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-d':
            dhe = True
        elif opt == '--tls-1.3':
            tls13 = True
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
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    conversation = Connect(host, port)
    node = conversation
    if dhe:
        ext = {}
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2),
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(version=(3, 2), extensions=ext))
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
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity - TLSv1.1"] = conversation

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
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 4),
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity - SSL3.4 version negotiation"] = conversation

    conversation = Connect(host, port, version=(3, 3))
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
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["record TLSv1.2 hello TLSv1.2"] = conversation

    conversation = Connect(host, port, version=(3, 2))
    node = conversation
    if dhe:
        ext = {}
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2),
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(version=(3, 2), extensions=ext))
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
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["record TLSv1.1 hello TLSv1.1"] = conversation

    conversation = Connect(host, port, version=(3, 4))
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
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                   CipherSuite.TLS_AES_128_GCM_SHA256]
    node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 4),
                                               extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
    node.next_sibling = ExpectClose()
    conversations["record SSL3.4 hello SSL3.4"] = conversation

    # test with FALLBACK_SCSV
    if dhe:
        positions = (0, 1, 2, 3)
    else:
        positions = (0, 1, 2)
    for place in positions:
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
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        else:
            ext = None
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                                   extensions=ext))
        if tls13:
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.inappropriate_fallback))
            node = node.add_child(ExpectClose())
        else:
            ext = {ExtensionType.renegotiation_info: None}
            node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
            node.next_sibling = ExpectClose()
        conversations["FALLBACK - hello TLSv1.2 - pos {0}".format(place)] = conversation

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
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        else:
            ext = None
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2),
                                                   extensions=ext))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.inappropriate_fallback))
        node = node.add_child(ExpectClose())
        conversations["FALLBACK - hello TLSv1.1 - pos {0}".format(place)] = conversation

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
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        else:
            ext = None
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 4),
                                                   extensions=ext))
        if tls13:
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.inappropriate_fallback))
            node = node.add_child(ExpectClose())
        else:
            ext = {ExtensionType.renegotiation_info: None}
            node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
            node = node.add_child(AlertGenerator(AlertLevel.warning,
                                                 AlertDescription.close_notify))
            node = node.add_child(ExpectAlert())
            node.next_sibling = ExpectClose()
        conversations["FALLBACK - hello SSL3.4 - pos {0}".format(place)] = conversation

        conversation = Connect(host, port, version=(3, 3))
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
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        else:
            ext = None
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 3),
                                                   extensions=ext))
        if tls13:
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.inappropriate_fallback))
            node = node.add_child(ExpectClose())
        else:
            ext = {ExtensionType.renegotiation_info: None}
            node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
            node = node.add_child(AlertGenerator(AlertLevel.warning,
                                                 AlertDescription.close_notify))
            node = node.add_child(ExpectAlert())
            node.next_sibling = ExpectClose()
        conversations["FALLBACK - record TLSv1.2 hello TLSv1.2 - pos {0}".format(place)] = conversation

        conversation = Connect(host, port, version=(3, 2))
        node = conversation
        if dhe:
            ext = {}
            groups = [GroupName.secp256r1,
                      GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        else:
            ext = None
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 2),
                                                   extensions=ext))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.inappropriate_fallback))
        node = node.add_child(ExpectClose())
        conversations["FALLBACK - record TLSv1.1 hello TLSv1.1 - pos {0}".format(place)] = conversation

        conversation = Connect(host, port, version=(3, 4))
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
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        else:
            ext = None
            ciphers = [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                       CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_AES_128_GCM_SHA256]
        ciphers.insert(place, CipherSuite.TLS_FALLBACK_SCSV)
        node = node.add_child(ClientHelloGenerator(ciphers, version=(3, 4),
                                                   extensions=ext))
        if tls13:
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.inappropriate_fallback))
            node = node.add_child(ExpectClose())
        else:
            ext = {ExtensionType.renegotiation_info: None}
            node = node.add_child(ExpectServerHello(version=(3, 3), extensions=ext))
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
            node.next_sibling = ExpectClose()
        conversations["FALLBACK - record SSL3.4 hello SSL3.4 - pos {0}".format(place)] = conversation


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

    print("Check if server correctly handles FALLBACK_SCSV\n")
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
