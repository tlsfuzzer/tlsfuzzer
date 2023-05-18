# Author: Hubert Kario, (c) 2021
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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        ResetHandshakeHashes, Close
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange


from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import SIG_ALL, AutoEmptyExtension


version = 3


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (\"sanity\" tests are always executed)")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" --sig-algs-drop-ok Don't expect connection abort for connections that advertise")
    print("                signature_algorithms_cert but no signature_algorithms")
    print(" --no-renego    Expect that the server does not support renegotiation")
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
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    sig_algs_drop_ok = False
    no_renego = False
    ems = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:dM",
                               ["help", "sig-algs-drop-ok", "no-renego",
                                "ems"])
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
        elif opt == '--sig-algs-drop-ok':
            sig_algs_drop_ok = True
        elif opt == '--no-renego':
            no_renego = True
        elif opt == "-M" or opt == "--ems":
            ems = True
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
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
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
    # some servers incorrectly send reply in multiple records,
    # leaking length of headers as a result,
    # they also may or may not close the connection after sending data
    # so just expect one record and then just close the connection
    node = node.add_child(ExpectApplicationData())
    node.add_child(Close())
    conversations["sanity"] = conversation

    # check if renegotiation is supported
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = dict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # paylod
    renego_exts[ExtensionType.renegotiation_info] = None
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts,
        session_id=bytearray(0)))
    if no_renego:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.no_renegotiation))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    else:
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(
            extensions=srv_ext))
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
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    conversations["sanity - renegotiation"] = conversation

    # check if renegotiation with resumption is supported
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = dict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # payload
    renego_exts[ExtensionType.renegotiation_info] = None
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts))
    if no_renego:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.no_renegotiation))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    else:
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(
            extensions=srv_ext,
            resume=True))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())

        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    conversations["sanity - renegotiation with session_id resumption"] = conversation

    # no sig_algs and sig_algs_cert
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
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
    # some servers incorrectly send reply in multiple records,
    # leaking length of headers as a result,
    # they also may or may not close the connection after sending data
    # so just expect one record and then just close the connection
    node = node.add_child(ExpectApplicationData())
    node.add_child(Close())
    conversations["without signature_algorithms and signature_algorithms_cert ext"] = conversation

    # no sig_algs
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    if sig_algs_drop_ok:
        node = node.add_child(ExpectServerHello())
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
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    else:
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.handshake_failure))
        node.next_sibling = ExpectClose()
    conversations["without signature_algorithms ext"] = conversation

    # drop the sig_algs on renegotiated handshake
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = dict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # paylod
    renego_exts[ExtensionType.renegotiation_info] = None
    del renego_exts[ExtensionType.signature_algorithms]
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts,
        session_id=bytearray(0)))
    if no_renego:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.no_renegotiation))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    elif not sig_algs_drop_ok:
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.handshake_failure))
        node.next_sibling = ExpectClose()
    else:
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(
            extensions=srv_ext))
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
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    conversations["renegotiation without signature_algorithms ext"] = conversation

    # drop the sig_algs_cert on renegotiated handshake
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = dict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # paylod
    renego_exts[ExtensionType.renegotiation_info] = None
    del renego_exts[ExtensionType.signature_algorithms_cert]
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts,
        session_id=bytearray(0)))
    if no_renego:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.no_renegotiation))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    else:
        srv_ext = {ExtensionType.renegotiation_info: None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(
            extensions=srv_ext))
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
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    conversations["renegotiation without signature_algorithms_cert ext"] = conversation

    # drop the sig_algs and sig_algs_cert on renegotiated handshake
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = dict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # paylod
    renego_exts[ExtensionType.renegotiation_info] = None
    del renego_exts[ExtensionType.signature_algorithms]
    del renego_exts[ExtensionType.signature_algorithms_cert]
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts,
        session_id=bytearray(0)))
    if no_renego:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.no_renegotiation))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    else:
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(
            extensions=srv_ext))
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
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    conversations["renegotiation without signature_algorithms and sig_algs_cert ext"] = conversation

    # check if renegotiation with resumption with missing sig_algs works
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = dict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # paylod
    renego_exts[ExtensionType.renegotiation_info] = None
    del renego_exts[ExtensionType.signature_algorithms]
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts))
    if no_renego:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.no_renegotiation))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    else:
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(
            extensions=srv_ext,
            resume=True))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())

        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    conversations["renegotiation with session_id resumption without signature_algorithms ext"] = conversation

    # check if renegotiation with resumption with missing sig_algs and sig_algs_cert works
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = dict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # paylod
    renego_exts[ExtensionType.renegotiation_info] = None
    del renego_exts[ExtensionType.signature_algorithms]
    del renego_exts[ExtensionType.signature_algorithms_cert]
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts))
    if no_renego:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.no_renegotiation))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    else:
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(
            extensions=srv_ext,
            resume=True))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())

        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    conversations["renegotiation with session_id resumption without signature_algorithms and signature_algorithms_cert ext"] = conversation

    # check if renegotiation with resumption with missing sig_algs_cert works
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = dict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # paylod
    renego_exts[ExtensionType.renegotiation_info] = None
    del renego_exts[ExtensionType.signature_algorithms_cert]
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts))
    if no_renego:
        node = node.add_child(ExpectAlert(AlertLevel.warning,
                                          AlertDescription.no_renegotiation))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    else:
        srv_ext = {ExtensionType.renegotiation_info:None}
        if ems:
            srv_ext[ExtensionType.extended_master_secret] = None
        node = node.add_child(ExpectServerHello(
            extensions=srv_ext,
            resume=True))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())

        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        # some servers incorrectly send reply in multiple records,
        # leaking length of headers as a result,
        # they also may or may not close the connection after sending data
        # so just expect one record and then just close the connection
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())
    conversations["renegotiation with session_id resumption without signature_algorithms_cert ext"] = conversation

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

    print("Check how server handles signature_algorithms extension in")
    print("different renegotiation and resumption scenarios\n")

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
