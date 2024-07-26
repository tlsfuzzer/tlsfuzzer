# Author: George Pantelakis, (c) 2024
# Contributor: Alexander Sosedkin
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
import zlib
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
    ExpectCertificateRequest

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
    TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme, \
    CertificateCompressionAlgorithm
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
    SupportedVersionsExtension, SupportedGroupsExtension, \
    SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
    CompressedCertificateExtension, TLSExtension
from tlsfuzzer.helpers import key_share_gen, SIG_ALL
from tlslite.utils.compression import *


version = 1

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
    print(" -C ciph                  Use specified ciphersuite. Either")
    print("                          numerical value or IETF name.")
    print(" --algorithms algorithms  comma-separated list of compression")
    print("                          algorithms: zlib,brotli,zstd by default")
    print(" --skip-bombs             Skipping tests with compression bombs")
    print(" --bomb-size num          Size of the bomb in MB, accepts only")
    print("                          integers. Default value 100.")
    print(" --full-fuzzing           Will fully fuzz the compression message")
    print("                          with random bytes from 0 to 2**24.")
    print("                          Default is disabled and only run a")
    print("                          random sample is running. Enabling it is")
    print("                          time and memory expensive.")
    print(" --random-fuzz-size num   Specify the number of random samples to")
    print("                          run. Default 20. If 0 is provided,")
    print("                          fuzzing will be skipped. Overridden by")
    print("                          --full-fuzzing.")
    print(" --help                   this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    ciphers = None
    compression_algorithms_list = list(KNOWN_ALGORITHMS)
    run_bombs = True
    bomb_size_MB = 100
    full_fuzzing = False
    fuzzing_sample_size = 20

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:C:", ["algorithms=",
                                                        "skip-bombs",
                                                        "bomb-size=",
                                                        "full-fuzzing",
                                                        "random-fuzz-size=",
                                                        "help"])
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
        elif opt == '-C':
            if arg[:2] == '0x':
                ciphers = [int(arg, 16)]
            else:
                try:
                    ciphers = [getattr(CipherSuite, arg)]
                except AttributeError:
                    ciphers = [int(arg)]
        elif opt == '--algorithms':
            compression_algorithms_list = arg.split(',')
        elif opt == '--skip-bombs':
            run_bombs = False
        elif opt == '--bomb-size':
            bomb_size_MB = int(arg)
        elif opt == '--full-fuzzing':
            full_fuzzing = True
        elif opt == '--random-fuzz-size':
            fuzzing_sample_size = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if not ciphers:
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256]

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
    node = node.add_child(ClientHelloGenerator(
        ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(CertificateGenerator())
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

    # Check that certificate request sends correct extensions
    conversation = Connect(host, port)
    algorithm=list(compression_algorithms.values())[0]
    node = conversation
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = \
        ClientKeyShareExtension().create(key_shares)
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
    compression_algs = [algorithm]
    ext[ExtensionType.compress_certificate] = \
        CompressedCertificateExtension().create(compression_algs)
    node = node.add_child(ClientHelloGenerator(
        ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificateRequest(extensions={
        ExtensionType.compress_certificate:
            CompressedCertificateExtension().create(
                server_supported_compression_algorithms),
        ExtensionType.signature_algorithms: None
    }))
    node = node.add_child(ExpectCompressedCertificate(
        compression_algo=algorithm))
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(CompressedCertificateGenerator())
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
    conversations["Certificate request has correct extensions"] = conversation

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
        compression_algs = [algorithm]
        ext[ExtensionType.compress_certificate] = \
            CompressedCertificateExtension().create(compression_algs)
        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        if algorithm in server_supported_compression_algorithms:
            node = node.add_child(ExpectCompressedCertificate(
                compression_algo=algorithm))
        else:
            node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(CompressedCertificateGenerator())
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

    # messing with uncompressed_size
    for name, size in [
        ('wrong', 10), ('zero', 0), ('max', 2**24 - 1)
    ]:
        size_bytes = int.to_bytes(size, 3, "little")
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
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
        compression_algs = [algorithm]
        ext[ExtensionType.compress_certificate] = \
            CompressedCertificateExtension().create(compression_algs)
        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCompressedCertificate())
        node.next_sibling = ExpectCertificate()
        sibling_node = node.next_sibling
        node = node.add_child(ExpectCertificateVerify())
        sibling_node.add_child(node)
        node = node.add_child(ExpectFinished())
        node = node.add_child(fuzz_message(CompressedCertificateGenerator(),
            substitutions={
                6: size_bytes[2], 7: size_bytes[1], 8: size_bytes[0]}))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_certificate))
        node = node.add_child(ExpectClose())
        conversations["{0} uncompressed_size".format(name)] = conversation

    # use non advertized algorithm
    if server_supported_compression_algorithms != [
            CertificateCompressionAlgorithm.zlib,
            CertificateCompressionAlgorithm.brotli,
            CertificateCompressionAlgorithm.zstd]:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
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
        compression_algs = [algorithm]
        ext[ExtensionType.compress_certificate] = \
            CompressedCertificateExtension().create(compression_algs)
        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCompressedCertificate())
        node.next_sibling = ExpectCertificate()
        sibling_node = node.next_sibling
        node = node.add_child(ExpectCertificateVerify())
        sibling_node.add_child(node)
        node = node.add_child(ExpectFinished())
        node = node.add_child(CompressedCertificateGenerator(
            not_advertized_algorithm=True))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.illegal_parameter))
        node = node.add_child(ExpectClose())
        conversations["non advertized algorithm"] = conversation

    # change the compression algorithm used to compress to a different
    # supported one
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    groups = [GroupName.secp256r1]
    key_shares = []
    for group in groups:
        key_shares.append(key_share_gen(group))
    ext[ExtensionType.key_share] = \
        ClientKeyShareExtension().create(key_shares)
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
    compression_algs = [algorithm]
    ext[ExtensionType.compress_certificate] = \
        CompressedCertificateExtension().create(compression_algs)
    node = node.add_child(ClientHelloGenerator(
        ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
        extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectCompressedCertificate())
    node.next_sibling = ExpectCertificate()
    sibling_node = node.next_sibling
    node = node.add_child(ExpectCertificateVerify())
    sibling_node.add_child(node)
    node = node.add_child(ExpectFinished())
    node = node.add_child(fuzz_message(CompressedCertificateGenerator(
            algorithm=CertificateCompressionAlgorithm.zlib),
        substitutions={5: CertificateCompressionAlgorithm.brotli}
    ))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.bad_certificate))
    node = node.add_child(ExpectClose())
    conversations["override actual algorithm used"] = conversation

    # compress with zlib but override algorithm used with unreasonable one
    UNREASONABLE_ALGORITHMS = {  # Should not lead to certificate compression
        0,                       # reserved
        10,                      # Not supported / unknown algorithm
        256,                     # 0x0100: valid algorithm, wrong octet
        770,                     # 0x0302: valid algorithms in all octets
        16383,                   # not reserved, but unlikely to be used soon
        16384,                   # reserved
        16385,                   # reserved
        65534,                   # reserved
        65535,                   # reserved
    }
    for algo in UNREASONABLE_ALGORITHMS:
        algo_bytes = int.to_bytes(algo, 2, "little")
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
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
        compression_algs = [algorithm]
        ext[ExtensionType.compress_certificate] = \
            CompressedCertificateExtension().create(compression_algs)
        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCompressedCertificate())
        node.next_sibling = ExpectCertificate()
        sibling_node = node.next_sibling
        node = node.add_child(ExpectCertificateVerify())
        sibling_node.add_child(node)
        node = node.add_child(ExpectFinished())
        node = node.add_child(fuzz_message(CompressedCertificateGenerator(
                algorithm=CertificateCompressionAlgorithm.zlib),
            substitutions={4: algo_bytes[1], 5: algo_bytes[0]}
        ))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.illegal_parameter))
        node = node.add_child(ExpectClose())
        conversations["unreasonable algorithm, {0}".format(algo)] = \
            conversation

    # Send compression bombs
    if run_bombs:
        print("Log: Preparing compression bombs, this might take a while...")
        bombs = {}
        mb_of_zeroes = b'\0' * 2**20

        if 'zlib' in compression_algorithms:
            zlib_compressor = zlib.compressobj()
            bombs['zlib'] = b''
            for _ in range(bomb_size_MB):
                bombs['zlib'] += zlib_compressor.compress(mb_of_zeroes)
            bombs['zlib'] += zlib_compressor.flush()
            assert(len(bombs['zlib']) < 2**24)

        if 'brotli' in compression_algorithms:
            brotli_compressor = brotli.Compressor()
            bombs['brotli'] = b''
            for _ in range(bomb_size_MB):
                bombs['brotli'] += brotli_compressor.process(mb_of_zeroes)
            bombs['brotli'] += brotli_compressor.flush()
            assert(len(bombs['brotli']) < 2**24)

        if 'zstd' in compression_algorithms:
            import zstd
            # no streaming interface for the most popular zstd binding,
            # but not all hope is lost for Python 3
            if sys.version_info < (3, 0):
                many_bytes = b'\00' * (2**20 * bomb_size_MB)  # eats up RAM
            else:
                many_bytes = bytes(2**20 * bomb_size_MB)  # doesn't eat up RAM
            assert len(many_bytes) == 2**20 * bomb_size_MB
            bombs['zstd'] = zstd.ZSTD_compress(many_bytes)
            assert(len(bombs['zstd']) < 2**24)

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
            compression_algs = [algorithm]
            ext[ExtensionType.compress_certificate] = \
                CompressedCertificateExtension().create(compression_algs)
            node = node.add_child(ClientHelloGenerator(
                ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
                extensions=ext))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectEncryptedExtensions())
            node = node.add_child(ExpectCertificateRequest())
            node = node.add_child(ExpectCompressedCertificate())
            node.next_sibling = ExpectCertificate()
            sibling_node = node.next_sibling
            node = node.add_child(ExpectCertificateVerify())
            sibling_node.add_child(node)
            node = node.add_child(ExpectFinished())
            node = node.add_child(fuzz_message(CompressedCertificateGenerator(
                    certs=None,
                    algorithm=algorithm,
                    compressed_certificate_message=bombs[alg_name]),
                substitutions={6: 255, 7: 255, 8: 255}
            ))
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.bad_certificate))
            node.next_sibling = ExpectClose()
            conversations["{0} bomb".format(alg_name)] = conversation

    for alg_name, algo, after in [
        (alg_name, algo, after)
        for alg_name, algo in compression_algorithms.items()
        for after in [True, False]
    ]:
        compressed_msg = zlib.compress(bytearray(b'\x00\x00\x00\x00'))
        orig_comp_msg_len = len(compressed_msg)
        if after:
            # 2 more bytes at the end
            compressed_msg += b'\x00\x00'
        else:
            # 2 more bytes at the beginning
            compressed_msg = b'\x00\x00' + compressed_msg

        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
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
        compression_algs = [CertificateCompressionAlgorithm.zlib]
        ext[ExtensionType.compress_certificate] = \
            CompressedCertificateExtension().create(compression_algs)
        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCompressedCertificate(
            compression_algo=CertificateCompressionAlgorithm.zlib))
        node.next_sibling = ExpectCertificate()
        sibling_node = node.next_sibling
        node = node.add_child(ExpectCertificateVerify())
        sibling_node.add_child(node)
        node = node.add_child(ExpectFinished())
        node = node.add_child(fuzz_message(CompressedCertificateGenerator(
            certs=None,
            algorithm=CertificateCompressionAlgorithm.zlib,
            compressed_certificate_message=compressed_msg,
        ), substitutions={
            8: 4, - len(compressed_msg) - 1: orig_comp_msg_len}))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.decode_error))
        node.next_sibling = ExpectClose()
        name = (
            "Additional bytes, {0}, ".format(alg_name) +
            ( "after, " if after else "before, " ) + "unreflected in size"
        )
        conversations[name] = conversation

    # Fuzzing compressed message
    algorithm=list(compression_algorithms.values())[0]
    sizes = []
    if full_fuzzing:
        sizes = range(0, 2**24)
    elif fuzzing_sample_size > 0:
        # Handshake message can be up to 2**24 - 1 size so due to other
        # fields in the message we can generate up to the max_size amount
        max_size = 2**24 - 1 - 2 - 3 - 3
        if fuzzing_sample_size > 2:
            sizes = sample(range(1, max_size), fuzzing_sample_size - 2)
        sizes.append(0)
        sizes.append(max_size)

    for size in sizes:
        conversation = Connect(host, port)
        node = conversation
        ext = {}
        groups = [GroupName.secp256r1]
        key_shares = []
        for group in groups:
            key_shares.append(key_share_gen(group))
        ext[ExtensionType.key_share] = \
            ClientKeyShareExtension().create(key_shares)
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
        compression_algs = [algorithm]
        ext[ExtensionType.compress_certificate] = \
            CompressedCertificateExtension().create(compression_algs)
        node = node.add_child(ClientHelloGenerator(
            ciphers + [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV],
            extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest())
        node = node.add_child(ExpectCompressedCertificate(
            compression_algo=algorithm))
        node.next_sibling = ExpectCertificate()
        sibling_node = node.next_sibling
        node = node.add_child(ExpectCertificateVerify())
        sibling_node.add_child(node)
        node = node.add_child(ExpectFinished())
        node = node.add_child(fuzz_message(CompressedCertificateGenerator(
                certs=None,
                algorithm=CertificateCompressionAlgorithm.zlib,
                compressed_certificate_message=bytearray(size)),
            substitutions={6: 255, 7: 255, 8: 255}
        ))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_certificate))
        node.next_sibling = ExpectClose()
        conversations["fuzzing of {0:,} bytes".format(size)] = \
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
    print("compressed certificate message. This test DOES expect that the")
    print("server will sent a RequestCertificate message so the clint then")
    print("can send its certificate.\n")

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
