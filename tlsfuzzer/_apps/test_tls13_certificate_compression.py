# Author: George Pantelakis, (c) 2024
# Contributor: Alexander Sosedkin
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
    CertificateGenerator, CompressedCertificateGenerator, fuzz_message
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
    ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
    ExpectAlert, ExpectApplicationData, ExpectClose, \
    ExpectEncryptedExtensions, ExpectCertificateVerify, \
    ExpectNewSessionTicket, ExpectCompressedCertificate, \
    ExpectCertificateRequest, ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
    TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme, \
    CertificateCompressionAlgorithm, HashAlgorithm, SignatureAlgorithm
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
    SupportedVersionsExtension, SupportedGroupsExtension, \
    SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
    CompressedCertificateExtension, TLSExtension
from tlsfuzzer.helpers import key_share_gen, SIG_ALL, RSA_SIG_ALL, \
    AutoEmptyExtension, cipher_suite_to_id
from tlslite.utils.compression import compression_algo_impls


version = 3

KNOWN_ALGORITHMS = ('zlib', 'brotli', 'zstd')


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname              name of the host to run the test against")
    print("                          localhost by default")
    print(" -p port                  port number to use for connection,")
    print("                          4433 by default")
    print(" probe-name               if present, will run only the probes")
    print("                          with given names and not all of them,")
    print("                          e.g \"sanity\"")
    print(" -e probe-name            exclude the probe from the list of the")
    print("                          ones run may be specified multiple times")
    print(" -x probe-name            expect the probe to fail. When such")
    print("                          probe passes despite being marked like")
    print("                          this it will be reported in the test")
    print("                          summary and the whole script will fail.")
    print("                          May be specified multiple times.")
    print(" -X message               expect the `message` substring in")
    print("                          exception raised during execution of")
    print("                          preceding expected failure probe")
    print("                          usage: [-x probe-name] [-X exception]")
    print("                          order is compulsory!")
    print(" -n num                   run 'num' or all(if 0) tests instead of")
    print("                          default(all).")
    print("                          (\"sanity\" tests are always executed)")
    print(" -d                       negotiate (EC)DHE instead of RSA key")
    print("                          exchange, send additional extensions,")
    print("                          usually used for (EC)DHE ciphers")
    print("                          additional extensions, usually used for")
    print("                          (EC)DHE ciphers. Only effects TLS v1.2")
    print("                          tests.")
    print(" --tls1.2-cipher ciph     Use specified ciphersuite for TLSv1.2.")
    print("                          Either numerical value or IETF name.")
    print(" --tls1.3-cipher ciph     Use specified ciphersuite for TLSv1.3.")
    print("                          Either numerical value or IETF name.")
    print(" -M | --ems               Advertise support for Extended Master")
    print("                          Secret. Only effects TLS v1.2 tests.")
    print(" --algorithms algorithms  comma-separated list of compression")
    print("                          algorithms that will be used by the")
    print("                          script to test against the server.")
    print("                          The algorithms specified here should be")
    print("                          supported by the server.")
    print("                          Set to zlib,brotli,zstd by default")
    print(" --help                   this message")


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
    compression_algorithms_list = list(KNOWN_ALGORITHMS)

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:dC:M", ["algorithms=",
                                                          "ems", "help"])
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
        elif opt == '--tls1.2-cipher':
            ciphers_1_2 = [cipher_suite_to_id(arg)]
        elif opt == '--tls1.3-cipher':
            ciphers_1_3 = [cipher_suite_to_id(arg)]
        elif opt == '-M' or opt == '--ems':
            ems = True
        elif opt == '--algorithms':
            compression_algorithms_list = arg.split(',')
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

    compression_algorithms = {}

    for alg_name in compression_algorithms_list:
        try:
            compression_algorithms[alg_name] = \
                getattr(CertificateCompressionAlgorithm, alg_name)
        except KeyError:
            raise RuntimeError("unsupported algorithm `{0}`".format(alg_name))

    server_supported_compression_algorithms = \
        list(compression_algorithms.values())

    if (
        'brotli' in compression_algorithms
        and not compression_algo_impls["brotli_decompress"]
    ):
        print(
            "Warning: Unsupported algorithm `brotli`, skipping algorithm. "
            "Install Brotli python package if you want to test it."
        )
        compression_algorithms.pop('brotli')
    if (
        'zstd' in compression_algorithms
        and not compression_algo_impls["zstd_decompress"]
    ):
        print(
            "Warning: Unsupported algorithm `zstd`, skipping algorithm. "
            "Install zstandard python package if you want to test it."
        )
        compression_algorithms.pop('zstd')

    if not compression_algorithms:
        raise RuntimeError("No algorithms left to check.")

    conversations = {}

    # Sanity, no certificate compression
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
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.ed25519,
                SignatureScheme.ed448]
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
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

    # Sanity, certificate compression
    for alg_name, algorithm in compression_algorithms.items():
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
                ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
                SupportedVersionsExtension().create([TLS_1_3_DRAFT, (3, 3)])
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.ecdsa_secp256r1_sha256,
                    SignatureScheme.ed25519,
                    SignatureScheme.ed448]
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        compression_algs = [algorithm]
        ext[ExtensionType.compress_certificate] = \
            CompressedCertificateExtension().create(compression_algs)
        node = node.add_child(ClientHelloGenerator(
            ciphers_1_3, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        if algorithm in server_supported_compression_algorithms:
            node = node.add_child(ExpectCompressedCertificate(
                compression_algo=algorithm))
        else:
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
        conversations["smoke, {0}".format(alg_name)] = conversation

    # Extension is ignored in TLS-1.2
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
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)

    ext[ExtensionType.compress_certificate] = \
                CompressedCertificateExtension().create(
                    list(compression_algorithms.values())
                )
    node = node.add_child(ClientHelloGenerator(ciphers_1_2, extensions=ext))
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
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sending extension in TLS-1.2"] = conversation

    # zlib is preferred when first
    extra_algo = None
    if 'brotli' in compression_algorithms:
        extra_algo = compression_algorithms['brotli']
    elif 'zstd' in compression_algorithms:
        extra_algo = compression_algorithms['zstd']

    if "zlib" in compression_algorithms and extra_algo:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
                ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
                SupportedVersionsExtension().create([TLS_1_3_DRAFT, (3, 3)])
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.ecdsa_secp256r1_sha256,
                    SignatureScheme.ed25519,
                    SignatureScheme.ed448]
        ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        algorithms = [compression_algorithms["zlib"], extra_algo]
        ext[ExtensionType.compress_certificate] = \
                CompressedCertificateExtension().create(algorithms)
        node = node.add_child(ClientHelloGenerator(
            ciphers_1_3, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCompressedCertificate(
            compression_algo=compression_algorithms["zlib"]))
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
        conversations["zlib is preferred"] = conversation

    # bug found: https://github.com/openssl/openssl/pull/19600
    UNSUPPORTED_ALGORITHMS = set([ # Should not lead to certificate compression
        0,                         # reserved
        10,                        # Not supported / unknown algorithm
        256,                       # 0x0100: valid algorithm, wrong octet
        770,                       # 0x0302: valid algorithms in all octets
        16383,                     # not reserved, but unlikely to be used soon
        16384,                     # reserved
        16385,                     # reserved
        65534,                     # reserved
        65535,                     # reserved
    ])
    for unreasonable_compression_algorithm in UNSUPPORTED_ALGORITHMS:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
                ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
                SupportedVersionsExtension().create([TLS_1_3_DRAFT, (3, 3)])
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.ecdsa_secp256r1_sha256,
                    SignatureScheme.ed25519,
                    SignatureScheme.ed448]
        ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        compression_algs = [unreasonable_compression_algorithm]
        ext[ExtensionType.compress_certificate] = \
                CompressedCertificateExtension().create(compression_algs)
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

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectApplicationData()
        node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                           AlertDescription.close_notify))

        node = node.add_child(ExpectAlert())
        node.add_child(ExpectClose())
        name = "unreasonable algorithm {0} alone"\
               .format(unreasonable_compression_algorithm)
        conversations[name] = conversation

        if "zlib" in compression_algorithms:
            conversation = Connect(host, port)
            node = conversation
            ext = {}
            groups = [GroupName.secp256r1]
            key_shares = []
            for group in groups:
                key_shares.append(key_share_gen(group))
            ext[ExtensionType.key_share] = \
                    ClientKeyShareExtension().create(key_shares)
            ext[ExtensionType.supported_versions] = \
                    SupportedVersionsExtension().create([TLS_1_3_DRAFT,
                                                         (3, 3)])
            ext[ExtensionType.supported_groups] = \
                    SupportedGroupsExtension().create(groups)
            sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                        SignatureScheme.rsa_pss_pss_sha256,
                        SignatureScheme.ecdsa_secp256r1_sha256,
                        SignatureScheme.ed25519,
                        SignatureScheme.ed448]
            ext[ExtensionType.signature_algorithms] = \
                    SignatureAlgorithmsExtension().create(sig_algs)
            ext[ExtensionType.signature_algorithms_cert] = \
                    SignatureAlgorithmsCertExtension().create(SIG_ALL)
            ext[ExtensionType.signature_algorithms_cert] = \
                    SignatureAlgorithmsCertExtension().create(SIG_ALL)
            compression_algs = [unreasonable_compression_algorithm,
                                CertificateCompressionAlgorithm.zlib]
            ext[ExtensionType.compress_certificate] = \
                    CompressedCertificateExtension().create(compression_algs)
            node = node.add_child(ClientHelloGenerator(ciphers_1_3,
                                                       extensions=ext))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectEncryptedExtensions())
            node = node.add_child(ExpectCompressedCertificate(
                compression_algo=CertificateCompressionAlgorithm.zlib
            ))
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
            node = node.next_sibling.add_child(AlertGenerator(
                AlertLevel.warning, AlertDescription.close_notify
            ))

            node = node.add_child(ExpectAlert())
            node.next_sibling = ExpectClose()
            name = "unreasonable algorithm {0}, fall back to zlib"\
                   .format(unreasonable_compression_algorithm)
            conversations[name] = conversation

    # Empty list in extension
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.ed25519,
                SignatureScheme.ed448]
    ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    compression_algs = []
    ext[ExtensionType.compress_certificate] = \
        CompressedCertificateExtension().create(compression_algs)
    node = node.add_child(ClientHelloGenerator(ciphers_1_3, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["empty list"] = conversation

    # duplicated values in extension
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.ed25519,
                SignatureScheme.ed448]
    ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    compression_algs = [list(compression_algorithms.values())[0]] * 3
    ext[ExtensionType.compress_certificate] = \
        CompressedCertificateExtension().create(compression_algs)
    node = node.add_child(ClientHelloGenerator(ciphers_1_3, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCompressedCertificate(
        compression_algo=list(compression_algorithms.values())[0]))
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
    node.add_child(ExpectClose())
    conversations["duplicated algos"] = conversation

    # modified extension
    for name, new_len in [
        ("zero len in extension", 0),
        ("odd len of list", 5),
        ("truncated extension", 8),
        ("padded extension", 4)
    ]:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
                ClientKeyShareExtension().create(key_shares)
        ext[ExtensionType.supported_versions] = \
                SupportedVersionsExtension().create([TLS_1_3_DRAFT, (3, 3)])
        ext[ExtensionType.supported_groups] = \
                SupportedGroupsExtension().create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.ecdsa_secp256r1_sha256,
                    SignatureScheme.ed25519,
                    SignatureScheme.ed448]
        ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIG_ALL)
        compression_algs = [
            CertificateCompressionAlgorithm.zlib,
            CertificateCompressionAlgorithm.brotli,
            CertificateCompressionAlgorithm.zstd
        ]
        ext[ExtensionType.compress_certificate] = \
            CompressedCertificateExtension().create(compression_algs)
        msg = ClientHelloGenerator(ciphers_1_3, extensions=ext)
        node = node.add_child(fuzz_message(msg, substitutions={-7: new_len}))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decode_error))
        node = node.add_child(ExpectClose())
        conversations[name] = conversation

    # odd length
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
    ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.ed25519,
                SignatureScheme.ed448]
    ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
    ext[ExtensionType.compress_certificate] = TLSExtension(
        extType=ExtensionType.compress_certificate).create(
            bytearray(b'\x00\x07'  # length of array
                      b'\x00\x01'  # zlib
                      b'\x00\x02'  # brotli
                      b'\x00\x03'  # zstd
                      b'\x04'))    # the odd byte
    node = node.add_child(ClientHelloGenerator(ciphers_1_3, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                    AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["odd length of extension"] = conversation

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

    print("Basic communications with TLS 1.3 servers to test the")
    print("compressed_certificate extension. This test does NOT expect the")
    print("server to sent a RequestCertificate message.\n")


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
