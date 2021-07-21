# Author: Hubert Kario, (c) 2018
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
        SetRecordVersion, TCPBufferingEnable, TCPBufferingDisable, \
        TCPBufferingFlush, ch_cookie_handler, split_message, \
        PlaintextMessageGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket, ExpectHelloRetryRequest, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme, \
        PskKeyExchangeMode, ContentType
from tlslite.utils.cryptomath import getRandomNumber, getRandomBytes
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, PskKeyExchangeModesExtension, \
        PreSharedKeyExtension, PskIdentity, TLSExtension, \
        SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import key_share_gen, RSA_SIG_ALL
from tlsfuzzer.utils.ordered_dict import OrderedDict


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
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" --num-bytes num Amount of bytes to send in the early data records")
    print("                16384 by default")
    print(" --cookie       expect cookie extension in HRR message")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    num_bytes = 2**14
    cookie = False
    dhe = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:d", ["help", "num-bytes=",
                                                  "cookie"])
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
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '--num-bytes':
            num_bytes = int(arg)
        elif opt == '--cookie':
            cookie = True
        elif opt == '-d':
            dhe = True
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    # sanity check
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
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
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # sanity check with PSK binders
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
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
    iden = PskIdentity().create(getRandomBytes(320), 0)
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["handshake with invalid PSK"] = conversation

    # fake 0-RTT resumption with HRR and early data after second client hello
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
    groups = [0x1300, GroupName.secp256r1]
    key_shares = [KeyShareEntry().create(0x1300, bytearray(b'\xab'*32))]
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
    ext[ExtensionType.early_data] = \
        TLSExtension(extType=ExtensionType.early_data)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    iden = PskIdentity().create(getRandomBytes(320),
                                getRandomNumber(2**30, 2**32))
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(SetRecordVersion((3, 3)))
    node = node.add_child(ApplicationDataGenerator(getRandomBytes(num_bytes)))
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())

    ext = {}
    if cookie:
        ext[ExtensionType.cookie] = None
    ext[ExtensionType.key_share] = None
    ext[ExtensionType.supported_versions] = None
    node = node.add_child(ExpectHelloRetryRequest(extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())

    ext = OrderedDict()
    key_shares = []
    for group in [GroupName.secp256r1]:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    if cookie:
        ext[ExtensionType.cookie] = ch_cookie_handler
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [getRandomBytes(32)])

    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))

    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(PlaintextMessageGenerator(
        ContentType.application_data,
        getRandomBytes(64)))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.bad_record_mac)
    node.next_sibling.add_child(ExpectClose())
    conversations["handshake with 0-RTT, HRR and early data after 2nd Client Hello"]\
        = conversation

    # fake 0-RTT resumption with HRR
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
    groups = [0x1300, GroupName.secp256r1]
    key_shares = [KeyShareEntry().create(0x1300, bytearray(b'\xab'*32))]
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
    ext[ExtensionType.early_data] = \
        TLSExtension(extType=ExtensionType.early_data)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    iden = PskIdentity().create(getRandomBytes(320),
                                getRandomNumber(2**30, 2**32))
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(SetRecordVersion((3, 3)))
    node = node.add_child(ApplicationDataGenerator(getRandomBytes(num_bytes)))
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())

    ext = {}
    if cookie:
        ext[ExtensionType.cookie] = None
    ext[ExtensionType.key_share] = None
    ext[ExtensionType.supported_versions] = None
    node = node.add_child(ExpectHelloRetryRequest(extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())

    ext = OrderedDict()
    key_shares = []
    for group in [GroupName.secp256r1]:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    if cookie:
        ext[ExtensionType.cookie] = ch_cookie_handler
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [getRandomBytes(32)])

    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))

    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["handshake with invalid 0-RTT and HRR"] = conversation

    # fake 0-RTT resumption with fragmented early data
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
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
    ext[ExtensionType.early_data] = \
        TLSExtension(extType=ExtensionType.early_data)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    iden = PskIdentity().create(getRandomBytes(320),
                                getRandomNumber(2**30, 2**32))
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(SetRecordVersion((3, 3)))
    node = node.add_child(ApplicationDataGenerator(
        getRandomBytes(num_bytes // 2)))
    node = node.add_child(ApplicationDataGenerator(
        getRandomBytes(num_bytes // 2)))
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["handshake with invalid 0-RTT with fragmented early data"]\
        = conversation

    # fake 0-RTT and early data spliced into the Finished message
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
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
    ext[ExtensionType.early_data] = \
        TLSExtension(extType=ExtensionType.early_data)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    iden = PskIdentity().create(getRandomBytes(320),
                                getRandomNumber(2**30, 2**32))
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(SetRecordVersion((3, 3)))
    node = node.add_child(ApplicationDataGenerator(getRandomBytes(num_bytes)))
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    finished_fragments = []
    node = node.add_child(split_message(FinishedGenerator(),
                                        finished_fragments,
                                        16))
    # early data spliced into the Finished message
    node = node.add_child(PlaintextMessageGenerator(
        ContentType.application_data,
        getRandomBytes(64)))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.bad_record_mac)

    node.next_sibling.add_child(ExpectClose())
    conversations["undecryptable record later in handshake together with early_data"]\
        = conversation

    # fake 0-RTT resumption and CCS between fake early data
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
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
    ext[ExtensionType.early_data] = \
        TLSExtension(extType=ExtensionType.early_data)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    iden = PskIdentity().create(getRandomBytes(320),
                                getRandomNumber(2**30, 2**32))
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(SetRecordVersion((3, 3)))
    node = node.add_child(
        ApplicationDataGenerator(getRandomBytes(num_bytes//2)))
    node = node.add_child(ChangeCipherSpecGenerator(fake=True))
    node = node.add_child(
        ApplicationDataGenerator(getRandomBytes(num_bytes//2)))
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["handshake with invalid 0-RTT and CCS between early data records"]\
        = conversation

    # fake 0-RTT resumption and CCS
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
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
    ext[ExtensionType.early_data] = \
        TLSExtension(extType=ExtensionType.early_data)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    iden = PskIdentity().create(getRandomBytes(320),
                                getRandomNumber(2**30, 2**32))
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(SetRecordVersion((3, 3)))
    node = node.add_child(ChangeCipherSpecGenerator(fake=True))
    node = node.add_child(ApplicationDataGenerator(getRandomBytes(num_bytes)))
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["handshake with invalid 0-RTT and CCS"] = conversation

    # fake 0-RTT resumption with unknown version
    conversation = Connect(host, port)
    node = conversation
    ext = OrderedDict()
    groups = [GroupName.secp256r1,
              GroupName.ffdhe2048]
    if dhe:
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([(3, 5), (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    ext[ExtensionType.early_data] = \
        TLSExtension(extType=ExtensionType.early_data)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    iden = PskIdentity().create(getRandomBytes(320),
                                getRandomNumber(2**30, 2**32))
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(SetRecordVersion((3, 3)))
    node = node.add_child(ApplicationDataGenerator(getRandomBytes(num_bytes)))
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectServerHello(version=(3, 3)))
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    # section D.3 of draft 28 states that client that receives TLS 1.2
    # ServerHello as a reply to 0-RTT Client Hello MUST fail a connection
    # consequently, the server does not need to be able to ignore early data
    # in TLS 1.2 mode
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.unexpected_message))
    node.add_child(ExpectClose())
    conversations["handshake with invalid 0-RTT and unknown version (downgrade to TLS 1.2)"] = conversation

    # fake 0-RTT resumption
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = OrderedDict()
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
    ext[ExtensionType.early_data] = \
        TLSExtension(extType=ExtensionType.early_data)
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    iden = PskIdentity().create(getRandomBytes(320),
                                getRandomNumber(2**30, 2**32))
    bind = getRandomBytes(32)
    ext[ExtensionType.pre_shared_key] = PreSharedKeyExtension().create(
        [iden], [bind])
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(SetRecordVersion((3, 3)))
    node = node.add_child(ApplicationDataGenerator(getRandomBytes(num_bytes)))
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["handshake with invalid 0-RTT"] = conversation


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

    print("Basic check if TLS 1.3 server can handle 0-RTT handshake")
    print("Verify that the server can handle a 0-RTT handshake from client")
    print("even if (or rather, especially if) it doesn't support 0-RTT.\n")

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
