# Author: Robert Kolcun, (c) 2018
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
        SetMaxRecordSize, TCPBufferingEnable, \
        TCPBufferingDisable, TCPBufferingFlush, PlaintextMessageGenerator, \
        fuzz_encrypted_message, SetPaddingCallback
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme, \
        PskKeyExchangeMode, ContentType
from tlslite.keyexchange import ECDHKeyExchange
from tlslite.utils.cryptomath import getRandomNumber, getRandomBytes
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
        TLSExtension, PskKeyExchangeModesExtension, PreSharedKeyExtension, \
        PskIdentity, PreSharedKeyExtension, PaddingExtension
from tlsfuzzer.helpers import key_share_gen, RSA_SIG_ALL, key_share_ext_gen


version = 4


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(50)")
    print("                (excluding \"sanity\" tests)")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = 50
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:", ["help"])
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
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}
    conversations_long = {}

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

    for cipher in [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_CHACHA20_POLY1305_SHA256]:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
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
        node = node.add_child(SetMaxRecordSize(2**16 - 1))
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(FinishedGenerator())
        data = bytearray(b"GET / HTTP/1.0\r\n" +
                        b"X-test: " + b"A" * (2**14 - 28) +
                        b"\r\n\r\n")
        assert len(data) == 2**14
        node = node.add_child(ApplicationDataGenerator(data))

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectApplicationData()
        node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                            AlertDescription.close_notify))

        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["max size payload in app_data, cipher {0}".format(
            CipherSuite.ietfNames[cipher])] = conversation

        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
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
        node = node.add_child(SetMaxRecordSize(2**16 - 1))
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(FinishedGenerator())
        data = bytearray(b"GET / HTTP/1.0\r\n" +
                        b"X-test: " + b"A" * (2**14 - 28 + 1) +
                        b"\r\n\r\n")
        assert len(data) == 2**14 + 1
        node = node.add_child(ApplicationDataGenerator(data))

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.record_overflow)
        node.next_sibling.add_child(ExpectClose())
        conversations["too big payload in app_data, data size: 2**14 + 1, "
                      "cipher {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
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
        node = node.add_child(SetMaxRecordSize(2**16 - 1))
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(FinishedGenerator())
        data = bytearray(b"GET / HTTP/1.0\r\n" +
                            b"X-test: " + b"A" * (2**14 - 28 - 8) +
                            b"\r\n\r\n")
        assert len(data) == 2**14 - 8
        padding_size = 2**14 + 2 - len(data) - 1
        node = node.add_child(SetPaddingCallback(
            SetPaddingCallback.add_fixed_padding_cb(padding_size)))
        node = node.add_child(ApplicationDataGenerator(data))

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.record_overflow)
        node.next_sibling.add_child(ExpectClose())
        conversations["too big plaintext, size: 2**14 - 8, with an additional"
                      " {0} bytes of padding, cipher {1}".format(
                        padding_size, CipherSuite.ietfNames[cipher])] = conversation

        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
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
        node = node.add_child(SetMaxRecordSize(2**16 - 1))
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        # Finished msg will add 32 bytes
        # 3 bytes for msg length
        # 1 byte for content type
        padding_left = 2**14 - 32 - 4
        node = node.add_child(FinishedGenerator(pad_left=padding_left))

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.decode_error)
        node.next_sibling.add_child(ExpectClose())
        conversations["max size payload (2**14) of Finished msg, with {0} bytes"
                      " of left padding, cipher {1}".format(
                          padding_left, CipherSuite.ietfNames[cipher])] = conversation

        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
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
        node = node.add_child(SetMaxRecordSize(2**16 - 1))
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        # Finished msg will add 32 bytes
        # 3 bytes for msg length
        # 1 byte for content type
        padding_left = 2**14 - 32 - 4 + 1
        node = node.add_child(FinishedGenerator(pad_left=padding_left))

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.record_overflow)
        node.next_sibling.add_child(ExpectClose())
        conversations["too big payload (2**14 + 1) of Finished msg, with {0} bytes"
                      " of left padding, cipher {1}".format(
                        padding_left, CipherSuite.ietfNames[cipher])] = conversation

        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
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
        node = node.add_child(SetMaxRecordSize(2**16 - 1))
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        # 32 bytes added as finished msg payload
        # 16 bytes added after encryption
        # 3 bytes for msg length
        # 1 byte for content type
        padding_size = 2**14 + 256 - 32 - 16 - 5
        node = node.add_child(SetPaddingCallback(
            SetPaddingCallback.add_fixed_padding_cb(padding_size)))
        node = node.add_child(FinishedGenerator())

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.record_overflow)
        node.next_sibling.add_child(ExpectClose())
        conversations["max size of Finished msg, with {0} bytes of record layer"
                      " padding {1}".format(
                        padding_size, CipherSuite.ietfNames[cipher])] = conversation

        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
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
        node = node.add_child(SetMaxRecordSize(2**16 - 1))
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        # 32 bytes added as finished msg payload
        # 16 bytes added after encryption
        # 3 bytes for msg length
        # 1 byte for content type
        padding_size = 2**14 + 256 - 32 - 16 - 5 + 1
        node = node.add_child(SetPaddingCallback(
            SetPaddingCallback.add_fixed_padding_cb(padding_size)))
        node = node.add_child(FinishedGenerator())

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.record_overflow)
        node.next_sibling.add_child(ExpectClose())
        conversations["too big Finished msg, with {0} bytes of record layer"
                      " padding, cipher {1}".format(
                        padding_size, CipherSuite.ietfNames[cipher])] = conversation

    # AEAD tag fuzzed
    for val in [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]:
        for pos in range(-1, -17, -1):
            conversation = Connect(host, port)
            node = conversation
            ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {}
            groups = [GroupName.secp256r1]
            ext[ExtensionType.key_share] = key_share_ext_gen(groups)
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
            node = node.add_child(SetMaxRecordSize(2**16 - 1))
            node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectEncryptedExtensions())
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectCertificateVerify())
            node = node.add_child(ExpectFinished())
            node = node.add_child(FinishedGenerator())
            data = bytearray(b"GET / HTTP/1.0\r\n" +
                             b"X-test: " + b"A" * (2**14 - 28 + 256 - 16) +
                             b"\r\n\r\n")
            assert len(data) == 2**14 + 256 - 16
            msg = ApplicationDataGenerator(data)
            node = node.add_child(fuzz_encrypted_message(msg, xors={pos:val}))

            # This message is optional and may show up 0 to many times
            cycle = ExpectNewSessionTicket()
            node = node.add_child(cycle)
            node.add_child(cycle)

            node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                            AlertDescription.record_overflow)
            node.next_sibling.add_child(ExpectClose())
            conversations_long["too big ciphertext with size 2**14 + 256 and"
                                "fuzzed tag with {0} on pos {1}".format(val, pos)] = conversation

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
    padding_size = 2**14 - 216 - 1
    ext[ExtensionType.client_hello_padding] = PaddingExtension().create(padding_size)
    node = node.add_child(SetMaxRecordSize(2**16 - 1))
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
    conversations["max size of ClientHello msg, with {0} bytes of padding".format(padding_size)] = conversation

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
    padding_size = 2**14 - 216
    ext[ExtensionType.client_hello_padding] = PaddingExtension().create(padding_size)
    node = node.add_child(SetMaxRecordSize(2**16 - 1))
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.record_overflow))
    node.add_child(ExpectClose())
    conversations["too big ClientHello msg, with {0} bytes of padding".format(padding_size)] = conversation

    # run the conversation
    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    if not num_limit:
        num_limit = len(conversations_long)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    if run_only:
        short_tests = [(k, v) for k, v in conversations.items() if k in run_only]
        long_tests = [(k, v) for k, v in conversations_long.items() if k in run_only]
    else:
        short_tests = [(k, v) for k, v in conversations.items() if
                        (k != 'sanity') and k not in run_exclude]
        long_tests = [(k, v) for k, v in conversations_long.items() if
                        k not in run_exclude]
    sampled_tests = sample(long_tests, min(num_limit, len(long_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, short_tests, sanity_tests)

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

    print("Verify that too big Application Data messages, with")
    print("different ciphers or fuzzed AEAD tag in TLS 1.3 communication ")
    print("are rejected with record_overflow alert.\n")
    print("Note that there are three limits: one for TLSCiphertext (encrypted")
    print("records, as visible on the line), a second one for")
    print("TLSInnertPlaintext (the data that the ciphertext decrypts to) and")
    print("a third one for TLSPlaintext (the records that are not encrypted,")
    print("like ClientHello).")
    print("This test checks all three of them.\n")
    print("See RFC 8446 Section 5.1, 5.2 and 5.4.\n")

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + len(short_tests) + 2*len(sanity_tests)))
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
