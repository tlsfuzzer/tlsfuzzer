# Author: Hubert Kario, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme, \
        PskKeyExchangeMode
from tlslite.extensions import ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, PskKeyExchangeModesExtension, \
        SignatureAlgorithmsCertExtension

from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        Close, ResetHandshakeHashes, ResetRenegotiationInfo, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket, srv_ext_handler_supp_vers, \
        gen_srv_ext_handler_psk, srv_ext_handler_key_share, \
        ExpectServerHelloDone, ExpectServerKeyExchange
from tlsfuzzer.helpers import key_share_gen, psk_session_ext_gen, \
        psk_ext_updater, RSA_SIG_ALL, SIG_ALL, AutoEmptyExtension, \
        cipher_suite_to_id


version = 7


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
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" -M | --ems     Advertise support for Extended Master Secret")
    print(" --tls1.2-cipher ciph Use specified ciphersuite for TLSv1.2.")
    print("                Either numerical value or IETF name.")
    print(" --tls1.3-cipher ciph Use specified ciphersuite for TLSv1.3.")
    print("                Either numerical value or IETF name.")
    print(" --client-pke   A comma seperated list of PSK Key Exchange(PKE)")
    print("                Modes to be added to the clientHello message. Can")
    print("                be specified multiple times. The order will be")
    print("                respected. Available psk_dhe_ke and psk_ke.")
    print("                Default psk_dhe_ke,psk_ke.")
    print(" --server-preferred-pke The preferred PKE of the server. If not ")
    print("                specified it will get the first from the client")
    print("                PKE list. Available psk_dhe_ke and psk_ke.")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    ciphers_1_2 = None
    ciphers_1_3 = None
    ems = False
    client_pke_list = []
    server_preferred_pke = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:dM", ["help",
                                                        "tls1.2-cipher=",
                                                        "tls1.3-cipher=",
                                                        "client-pke=",
                                                        "server-preferred-pke="])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-d':
            dhe = True
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-M' or opt == '--ems':
            ems = True
        elif opt == '--tls1.2-cipher':
            ciphers_1_2 = [cipher_suite_to_id(arg)]
        elif opt == '--tls1.3-cipher':
            ciphers_1_3 = [cipher_suite_to_id(arg)]
        elif opt == '--client-pke':
            for pke_arg in arg.split(','):
                try:
                    pke_arg = getattr(PskKeyExchangeMode, pke_arg)
                    if not pke_arg in client_pke_list:
                        client_pke_list.append(pke_arg)
                except AttributeError:
                    raise ValueError(
                        "Unknown PKE argument {0}. ".format(pke_arg) +
                        "Please use psk_dhe_ke or psk_ke"
                    )
        elif opt == '--server-preferred-pke':
            try:
                server_preferred_pke = getattr(PskKeyExchangeMode, arg)
            except AttributeError:
                raise ValueError(
                    "Unknown PKE argument {0}. ".format(arg) +
                    "Please use psk_dhe_ke or psk_ke"
                )
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if ciphers_1_2:
        ciphers_1_2 += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        if not dhe:
            # by default send minimal set of extensions, but allow user
            # to override it
            dhe = ciphers_1_2[0] in CipherSuite.ecdhAllSuites or \
                    ciphers_1_2[0] in CipherSuite.dhAllSuites
    else:
        if dhe:
            ciphers_1_2 = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                           CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                           CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                           CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ciphers_1_2 = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                           CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]

    if ciphers_1_3:
        ciphers_1_3 += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers_1_3 = [CipherSuite.TLS_AES_128_GCM_SHA256,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]


    if not client_pke_list:
        client_pke_list = [
            PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke]

    if server_preferred_pke is None:
        server_preferred_pke = client_pke_list[0]

    conversations = {}

    # basic connection
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    node = node.add_child(ClientHelloGenerator(ciphers_1_3, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    # ensure that the server sends at least one NST always
    node = node.add_child(ExpectNewSessionTicket())

    # but multiple ones are OK too
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(
        AlertGenerator(AlertLevel.warning,
                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())
    conversations["sanity"] = conversation

    # check if TLS 1.2 works
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.session_ticket] = AutoEmptyExtension()
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers_1_2, extensions=ext))
    ext_srv = {}
    ext_srv[ExtensionType.session_ticket] = None
    ext_srv[ExtensionType.renegotiation_info] = None
    if ems:
        ext_srv[ExtensionType.extended_master_secret] = None
    node = node.add_child(ExpectServerHello(extensions=ext_srv))
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectNewSessionTicket())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity - TLS 1.2"] = conversation

    if len(client_pke_list) > 1:
        for pke in client_pke_list:
            conversation = Connect(host, port)
            node = conversation
            ext = {}
            groups = [GroupName.secp256r1]
            key_shares = []
            for group in groups:
                key_shares.append(key_share_gen(group))
            ext[ExtensionType.key_share] = ClientKeyShareExtension()\
                .create(key_shares)
            ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
                .create([TLS_1_3_DRAFT, (3, 3)])
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                        SignatureScheme.rsa_pss_pss_sha256]
            ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
                .create(sig_algs)
            ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
                .create(RSA_SIG_ALL)
            ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
                .create([pke])
            node = node.add_child(ClientHelloGenerator(
                ciphers_1_3, extensions=ext))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectEncryptedExtensions())
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectCertificateVerify())
            node = node.add_child(ExpectFinished())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ApplicationDataGenerator(
                bytearray(b"GET / HTTP/1.0\r\n\r\n")))
            # ensure that the server sends at least one NST always
            node = node.add_child(ExpectNewSessionTicket())

            # but multiple ones are OK too
            cycle = ExpectNewSessionTicket()
            node = node.add_child(cycle)
            node.add_child(cycle)

            node.next_sibling = ExpectApplicationData()
            node = node.next_sibling.add_child(
                AlertGenerator(AlertLevel.warning,
                               AlertDescription.close_notify))

            node = node.add_child(ExpectAlert(AlertLevel.warning,
                                              AlertDescription.close_notify))
            # server can close connection without sending alert
            close = ExpectClose()
            node.next_sibling = close
            node = node.add_child(close)
            node = node.add_child(Close())
            node = node.add_child(Connect(host, port))

            # start the second handshake
            node = node.add_child(ResetHandshakeHashes())
            node = node.add_child(ResetRenegotiationInfo())
            ext = OrderedDict(ext)
            ext[ExtensionType.pre_shared_key] = psk_session_ext_gen()
            mods = []
            mods.append(psk_ext_updater())
            node = node.add_child(ClientHelloGenerator(ciphers_1_3,
                                                       extensions=ext,
                                                       modifiers=mods))
            ext = {}
            ext[ExtensionType.supported_versions] = srv_ext_handler_supp_vers
            ext[ExtensionType.pre_shared_key] = gen_srv_ext_handler_psk()
            if pke == PskKeyExchangeMode.psk_dhe_ke:
                ext[ExtensionType.key_share] = srv_ext_handler_key_share
            node = node.add_child(ExpectServerHello(extensions=ext))
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectEncryptedExtensions())
            node = node.add_child(ExpectFinished())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ApplicationDataGenerator(
                bytearray(b"GET / HTTP/1.0\r\n\r\n")))
            # ensure that the server sends at least one NST always
            node = node.add_child(ExpectNewSessionTicket())

            # but multiple ones are OK too
            cycle = ExpectNewSessionTicket()
            node = node.add_child(cycle)
            node.add_child(cycle)

            node.next_sibling = ExpectApplicationData()
            node = node.next_sibling.add_child(
                AlertGenerator(AlertLevel.warning,
                               AlertDescription.close_notify))

            node = node.add_child(ExpectAlert(AlertLevel.warning,
                                              AlertDescription.close_notify))
            node.next_sibling = ExpectClose()
            node.add_child(ExpectClose())
            pke_name = "PSK_WITH_DHE"
            if pke == PskKeyExchangeMode.psk_ke:
                pke_name = "PSK_ONLY"
            conversation_name = "session resumption - {0}".format(pke_name)
            conversations[conversation_name] = conversation

    # resume a session
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create(client_pke_list)
    node = node.add_child(ClientHelloGenerator(ciphers_1_3, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    # ensure that the server sends at least one NST always
    node = node.add_child(ExpectNewSessionTicket())

    # but multiple ones are OK too
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(
        AlertGenerator(AlertLevel.warning,
                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    # server can close connection without sending alert
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(close)
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))

    # start the second handshake
    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    ext = OrderedDict(ext)
    ext[ExtensionType.pre_shared_key] = psk_session_ext_gen()
    mods = []
    mods.append(psk_ext_updater())
    node = node.add_child(ClientHelloGenerator(ciphers_1_3, extensions=ext,
                                               modifiers=mods))
    ext = {}
    ext[ExtensionType.supported_versions] = srv_ext_handler_supp_vers
    ext[ExtensionType.pre_shared_key] = gen_srv_ext_handler_psk()
    if server_preferred_pke == PskKeyExchangeMode.psk_dhe_ke:
        ext[ExtensionType.key_share] = srv_ext_handler_key_share
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    # ensure that the server sends at least one NST always
    node = node.add_child(ExpectNewSessionTicket())

    # but multiple ones are OK too
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(
        AlertGenerator(AlertLevel.warning,
                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())
    conversations["session resumption"] = conversation

    # see if the TLS 1.2 session can't be used for TLS 1.3
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    ext[ExtensionType.session_ticket] = AutoEmptyExtension()
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers_1_2, extensions=ext))
    ext_srv = {}
    ext_srv[ExtensionType.session_ticket] = None
    ext_srv[ExtensionType.renegotiation_info] = None
    if ems:
        ext_srv[ExtensionType.extended_master_secret] = None
    node = node.add_child(ExpectServerHello(extensions=ext_srv,
                                            description="first"))
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectNewSessionTicket())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())

    # start the second handshake
    ext = OrderedDict(ext)
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create(client_pke_list)
    ext[ExtensionType.pre_shared_key] = psk_session_ext_gen()
    mods = []
    mods.append(psk_ext_updater())
    node = node.add_child(ClientHelloGenerator(ciphers_1_3, extensions=ext,
                                               modifiers=mods))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    # ensure that the server sends at least one NST always
    #node = node.add_child(ExpectNewSessionTicket())

    # but multiple ones are OK too
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(
        AlertGenerator(AlertLevel.warning,
                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

    conversations["use TLS 1.2 ticket in TLS 1.3"] = conversation

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

    print("Basic session resumption test with TLS 1.3 server\n")

    print("Test end")
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
