# Author: Hubert Kario, (c) 2021-2022
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Bleichenbacher attack test for Marvin workaround."""
from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.timing_runner import TimingRunner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
    ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
    FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
    TCPBufferingEnable, TCPBufferingDisable, TCPBufferingFlush, fuzz_mac, \
    fuzz_padding, fuzz_pkcs1_padding
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
    ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
    ExpectAlert, ExpectClose, ExpectApplicationData, ExpectNoMessage

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
    ExtensionType
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.extensions import SNIExtension, SignatureAlgorithmsCertExtension,\
    SignatureAlgorithmsExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.helpers import SIG_ALL, RSA_PKCS1_ALL
from tlslite.x509 import X509
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.utils.cryptomath import getRandomBytes, numBytes, secureHMAC, \
    numberToByteArray, numBits, secureHash


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(50)")
    print("                (excluding \"sanity\" tests)")
    print(" -a desc        the expected alert description for invalid Finished")
    print("                messages - 20 (bad_record_mac) by default")
    print("                Note: other values are NOT RFC compliant!")
    print(" -l level       the expected alert level for invalid Finished")
    print("                - 2 (fatal) by default")
    print("                Note: other values are NOT RFC compliant!")
    print(" -C cipher      specify cipher for connection. Use integer value")
    print("                or IETF name. Integer must be prefixed with '0x'")
    print("                if it is hexadecimal. By default uses")
    print("                TLS_RSA_WITH_AES_128_CBC_SHA ciphersuite.")
    print(" -i interface   Allows recording timing information")
    print("                on specified interface. Required to enable timing tests")
    print(" -o dir         Specifies output directory for timing information")
    print("                /tmp by default")
    print(" --repeat rep   How many timing samples should be gathered for each test")
    print("                100 by default")
    print(" --no-safe-renego  Allow the server not to support safe")
    print("                renegotiation extension")
    print(" --no-sni       do not send server name extension.")
    print("                Sends extension by default if the hostname is a")
    print("                valid DNS name, not an IP address")
    print(" --cpu-list     Set the CPU affinity for the tcpdump process")
    print("                See taskset(1) man page for the syntax of this")
    print("                option. Not used by default.")
    print(" --pms-len len  Generate ciphertexts that decrypt to specified")
    print("                number of bytes, 48 by default.")
    print(" --srv-key key  File with server private key.")
    print(" --srv-cert crt File with server certificate.")
    print(" --pms-tls-version ver Control the TLS version in the decrypted or")
    print("                synthethic plaintext. If left undefined the script")
    print("                will make sure not to generate message values that")
    print("                start with values appropriate for SSLv3, TLS 1.0,")
    print("                TLS 1.1, and TLS 1.2. If set, it should be a")
    print("                hex-encoded integer representing two bytes to be")
    print("                used as the version, e.g. \"0x0303\" for TLS 1.2")
    print("                Note: using this option will significantly increase")
    print("                the time to generate ciphertexts.")
    print(" --help         this message")


def _dec_prf(key, label, out_len):
    """PRF for deterministic generation of synthethic plaintext in RSA."""
    out = bytearray()

    if out_len % 8 != 0:
        raise ValueError("only multiples of 8 supported as output size")

    iterator = 0
    while len(out) < out_len // 8:
        out += secureHMAC(
            key,
            numberToByteArray(iterator, 2) + label +
            numberToByteArray(out_len, 2),
            "sha256")
        iterator += 1

    return out[:out_len//8]


def synthetic_plaintext_generator(priv_key, ciphertext):
    """Generate a synthethic plaintext.

    This will generate a plaintext for the given ciphertext to be used in case
    the decryption fails.

    We use it to know what kind of PMS will the TLS layer see when we send a
    malformed ciphertext.
    """
    n = priv_key.n

    max_sep_offset = numBytes(n) - 10

    if not hasattr(priv_key, '_key_hash') or not priv_key._key_hash:
        priv_key._key_hash = secureHash(
            numberToByteArray(priv_key.d, numBytes(n)), "sha256")

    kdk = secureHMAC(priv_key._key_hash, ciphertext, "sha256")

    length_randoms = _dec_prf(kdk, b"length", 128 * 2 * 8)

    message_random = _dec_prf(kdk, b"message", numBytes(n) * 8)

    synth_length = 0
    length_rand_iter = iter(length_randoms)
    length_mask = (1 << numBits(max_sep_offset)) - 1
    for high, low in zip(length_rand_iter, length_rand_iter):
        len_candidate = (high << 8) + low
        len_candidate &= length_mask

        if len_candidate < max_sep_offset:
            synth_length = len_candidate

    synth_msg_start = numBytes(n) - synth_length

    return message_random[synth_msg_start:]


def _encrypt_with_fuzzing(pub_key, plaintext, padding_subs, padding_byte):
    old_addPKCS1Padding = pub_key._addPKCS1Padding
    public_key = fuzz_pkcs1_padding(pub_key, padding_subs, None, padding_byte)
    ret = public_key.encrypt(plaintext)
    pub_key._addPKCS1Padding = old_addPKCS1Padding
    return ret



class MarvinCiphertextGenerator(object):
    """
    Generate a set of ciphertexts that should present the same timing behaviour
    from server.

    This will create either valid ciphertext that decrypt to specified length,
    or invalid ciphertexts that have synthethic ciphertexts of specified length.
    All ciphertexts will also require the same number of bytes to represent.

    If tls_version is None it will simply select PMS values for which the
    first two bytes of it can't be mistaken for a TLS version (it won't
    generate 0x0300, 0x0301, 0x0302, or 0x0303). Otherwise it will generate
    PMSs with the specified TLS version.
    """
    def __init__(self, priv_key, pub_key, pms_len, tls_version):
        self.priv_key = priv_key
        self.pub_key = pub_key
        self.pms_len = pms_len
        self.tls_version = tls_version
        self.forbidden = set(
            [b"\x03\x00", b"\x03\x01", b"\x03\x02", b"\x03\x03"])

    def _generate_ciphertext_with_fuzz(
            self, subs, padding_byte=None, pms=None):
        while True:
            if pms is None:
                rand_pms = getRandomBytes(self.pms_len)
            else:
                rand_pms = pms
            ciphertext = _encrypt_with_fuzzing(
                self.pub_key, rand_pms, subs, padding_byte)

            # since we use static probes, we don't want to see a difference
            # caused by publicly visible values (like can happen with
            # multiprecision integer arithmetic implementation that uses
            # clamping), so make sure that the ciphertext has
            # non-zero MSB
            if not ciphertext[0]:
                continue

            synth_plaintext = synthetic_plaintext_generator(
                self.priv_key, ciphertext)

            if len(synth_plaintext) != self.pms_len:
                continue

            if self.tls_version is None:
                if bytes(synth_plaintext[:2]) not in self.forbidden:
                    break
            else:
                if len(synth_plaintext) > 2 and \
                        synth_plaintext[0] == self.tls_version[0] and \
                        synth_plaintext[1] == self.tls_version[1]:
                    break
        assert synth_plaintext == self.priv_key.decrypt(ciphertext), \
            (synth_plaintext, self.priv_key.decrypt(ciphertext),
             self.priv_key._raw_private_key_op_bytes(ciphertext))
        return ciphertext

    def generate(self):
        ret = {}

        # first a random well-formed ciphertext canaries
        for i in range(1, 4):
            while True:
                if self.tls_version is None:
                    while True:
                        rand_pms = getRandomBytes(self.pms_len)
                        if bytes(rand_pms[:2]) not in self.forbidden:
                            break
                else:
                    rand_pms = getRandomBytes(self.pms_len)
                    rand_pms[0] = self.tls_version[0]
                    rand_pms[1] = self.tls_version[1]

                ciphertext = self.pub_key.encrypt(rand_pms)
                # make sure MSB is non zero to avoid public value clamping
                # side-channel
                if ciphertext[0]:
                    break

            assert rand_pms == self.priv_key.decrypt(ciphertext)
            ret["well formed - {0}".format(i)] = ciphertext

        # then invalid one, with version byte set to 1
        subs = {0: 1}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["invalid version number (1) in padding"] = ciphertext

        # then let's try ones that use padding value set to 0
        subs = {1: 0}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["invalid PKCS#1 type (0) in padding"] = ciphertext

        # then let's try ones that use padding value set to 1
        subs = {1: 1}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["invalid PKCS#1 type (1) in padding"] = ciphertext

        # then let's try ones that use padding value set to 2
        subs = {1: 3}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["invalid PKCS#1 type (3) in padding"] = ciphertext

        # actually use padding type 1
        subs = {1: 1}
        ciphertext = self._generate_ciphertext_with_fuzz(subs, 0xff)
        ret["use PKCS#1 type 1 padding"] = ciphertext

        # actually use padding type 0
        subs = {1: 0}
        ciphertext = self._generate_ciphertext_with_fuzz(subs, 0)
        ret["use PKCS#1 type 0 padding"] = ciphertext

        # set padding to all zero bytes
        ciphertext = self._generate_ciphertext_with_fuzz(None, 0)
        ret["use 0 as padding byte"] = ciphertext

        # create too long plaintext by 8 bytes
        subs = {2: 0}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["zero byte in first byte of padding"] = ciphertext

        # create too long plaintext by 7 bytes
        subs = {3: 0}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["zero byte in second byte of padding"] = ciphertext

        # create too long plaintext by 6 bytes
        subs = {4: 0}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["zero byte in third byte of padding"] = ciphertext

        # create too long plaintext by 1 bytes
        subs = {9: 0}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["zero byte in eight byte of padding"] = ciphertext

        # no zero byte separator
        subs = {-1:1}
        ciphertext = self._generate_ciphertext_with_fuzz(subs, pms=b"")
        ret["no null separator"] = ciphertext

        # completely random plaintext
        subs = {0: 0x3, 1: 0x27, -1: 0x12}
        ciphertext = self._generate_ciphertext_with_fuzz(subs, pms=b"")
        ret["random plaintext"] = ciphertext

        # too short PKCS padding
        subs = {1: 0, 2: 2}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["too short PKCS#1 padding"] = ciphertext

        # very short PKCS padding
        subs = {}
        for i in range(41):
            subs[i] = 0
        subs[41] = 2
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["very short PKCS#1 padding (40 bytes short)"] = ciphertext

        # too long PKCS padding
        subs = {0: 2}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["too long PKCS#1 padding"] = ciphertext

        # low Hamming weight RSA plaintext
        while True:
            if self.tls_version is None:
                while True:
                    rand_pms = getRandomBytes(self.pms_len)
                    if bytes(rand_pms[:2]) not in self.forbidden:
                        break
            else:
                rand_pms = getRandomBytes(self.pms_len)
                rand_pms[0] = self.tls_version[0]
                rand_pms[1] = self.tls_version[1]
            ciphertext = _encrypt_with_fuzzing(self.pub_key, rand_pms, None, 1)
            # make sure MSB is non-zero to avoid side-channel based on public
            # value clamping
            if ciphertext[0]:
                break
        assert rand_pms == self.priv_key.decrypt(ciphertext)
        ret["use 1 as the padding byte (low Hamming weight plaintext)"] = ciphertext

        # valid with very long synthethic (unused) plaintext
        while True:
            if self.tls_version is None:
                while True:
                    rand_pms = getRandomBytes(self.pms_len)
                    if bytes(rand_pms[:2]) not in self.forbidden:
                        break
            else:
                rand_pms = getRandomBytes(self.pms_len)
                rand_pms[0] = self.tls_version[0]
                rand_pms[1] = self.tls_version[1]

            ciphertext = self.pub_key.encrypt(rand_pms)
            # make sure MSB is non-zero to avoid side-channel based on public
            # value clamping
            if not ciphertext[0]:
                continue

            synth_plaintext = synthetic_plaintext_generator(
                self.priv_key, ciphertext)
            if len(synth_plaintext) == numBytes(self.pub_key.n) - 11:
                break

        assert rand_pms == self.priv_key.decrypt(ciphertext)
        ret["well formed with very long synthethic PMS"] = ciphertext

        # valid with short synthethic (unused) plaintext
        while True:
            if self.tls_version is None:
                while True:
                    rand_pms = getRandomBytes(self.pms_len)
                    if bytes(rand_pms[:2]) not in self.forbidden:
                        break
            else:
                rand_pms = getRandomBytes(self.pms_len)
                rand_pms[0] = self.tls_version[0]
                rand_pms[1] = self.tls_version[1]

            ciphertext = self.pub_key.encrypt(rand_pms)
            # make sure MSB is non-zero to avoid side-channel based on public
            # value clamping
            if not ciphertext[0]:
                continue

            synth_plaintext = synthetic_plaintext_generator(
                self.priv_key, ciphertext)
            if synth_plaintext == b"":
                break

        assert rand_pms == self.priv_key.decrypt(ciphertext)
        ret["well formed with empty synthethic PMS"] = ciphertext

        return ret


def main():
    """Check if server implements Marvin workaround correctly."""
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    alert = AlertDescription.bad_record_mac
    level = AlertLevel.fatal
    srv_extensions = {ExtensionType.renegotiation_info: None}
    no_sni = False
    repetitions = 100
    interface = None
    timing = False
    outdir = "/tmp"
    cipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    affinity = None
    pms_len = 48
    srv_key = None
    srv_cert = None
    pms_tls_version = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv,
                               "h:p:e:x:X:n:a:l:l:o:i:C:",
                               ["help",
                                "no-safe-renego",
                                "no-sni",
                                "repeat=",
                                "cpu-list=",
                                "pms-len=",
                                "srv-key=",
                                "srv-cert=",
                                "pms-tls-version="])
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
                cipher = int(arg, 16)
            else:
                try:
                    cipher = getattr(CipherSuite, arg)
                except AttributeError:
                    cipher = int(arg)
        elif opt == '-a':
            alert = int(arg)
        elif opt == '-l':
            level = int(arg)
        elif opt == "-i":
            timing = True
            interface = arg
        elif opt == '-o':
            outdir = arg
        elif opt == "--repeat":
            repetitions = int(arg)
        elif opt == "--no-safe-renego":
            srv_extensions = None
        elif opt == "--no-sni":
            no_sni = True
        elif opt == "--cpu-list":
            affinity = arg
        elif opt == "--pms-len":
            pms_len = int(arg)
        elif opt == "--srv-key":
            with open(arg, "rb") as f:
                text_key = f.read()
            if sys.version_info[0] >= 3:
                text_key = str(text_key, "utf-8")
            srv_key = parsePEMKey(text_key, private=True)
        elif opt == "--srv-cert":
            with open(arg, "rb") as f:
                text_cert = f.read()
            if sys.version_info[0] >= 3:
                text_cert = str(text_cert, "utf-8")
            srv_cert = X509()
            srv_cert.parse(text_cert)
        elif opt == "--pms-tls-version":
            int_ver = int(arg, 16)
            pms_tls_version = divmod(int_ver, 256)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if not srv_cert or not srv_key:
        print("You must provide server private key and certificate")
        exit(1)

    print("Generating ciphertexts...")
    marvin_gen = MarvinCiphertextGenerator(
        srv_key, srv_cert.publicKey, pms_len, pms_tls_version)
    ciphertexts = marvin_gen.generate()
    print("Ciphertexts generated.")

    if args:
        run_only = set(args)
    else:
        run_only = None

    cln_extensions = {ExtensionType.renegotiation_info: None}
    if is_valid_hostname(host) and not no_sni:
        cln_extensions[ExtensionType.server_name] = \
            SNIExtension().create(bytearray(host, 'ascii'))
    cln_extensions[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_PKCS1_ALL)
    cln_extensions[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)

    # RSA key exchange check
    if cipher not in CipherSuite.certSuites:
        print("Ciphersuite has to use RSA key exchange.")
        exit(1)

    conversations = OrderedDict()

    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity"] = conversation

    # verify that we have the correct server certificate
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    secret = bytearray([3, 3] + [0x11] * 46)
    enc_secret = srv_cert.publicKey.encrypt(secret)
    node = node.add_child(ClientKeyExchangeGenerator(
        encrypted_premaster=enc_secret,
        premaster_secret=secret,
        reuse_encrypted_premaster=True))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity (opaque encrypt)"] = conversation


    for name, enc_pms in ciphertexts.items():
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))

        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(
            encrypted_premaster=enc_pms))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations[name] = conversation

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
    if num_limit < len(conversations):
        sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    else:
        sampled_tests = regular_tests
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    print("Running tests for {0}".format(CipherSuite.ietfNames[cipher]))

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
                if expected_failures[c_name] is not None and \
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

    print("Test end")
    print(20 * '=')
    print("""Tests for handling of malformed encrypted values in CKE

This test script checks if the server implements the Marvin workaround
correctly. That is, it expects that it leaks both the length of the encrypted
pre-master secret and the encrypted TLS version in it, but that PMS does not
depend on correctness of PKCS#1 padding.
When executed with `-i` it will also verify that different errors
are rejected in the same amount of time; it checks for timing
sidechannel.
The script executes tests without \"sanity\" in name multiple
times to estimate server response time.

Quick reminder: when encrypting a value using PKCS#1 v1.5 standard
the plaintext has the following structure, starting from most
significant byte:
- one byte, the version of the encryption, must be 0
- one byte, the type of encryption, must be 2 (is 1 in case of
  signature)
- one or more bytes of random padding, with no zero bytes. The
  count must equal the byte size of the public key modulus less
  size of encrypted value and 3 (for version, type and separator)
  For signatures the bytes must equal 0xff.
  Minimal length of padding is 8 bytes.
- one zero byte that acts as separator between padding and
  encrypted value
- one or more bytes that are the encrypted value, for TLS it must
  be 48 bytes long and the first two bytes need to equal the
  TLS version advertised in Client Hello.""")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + 2 * len(sanity_tests)))
    print("SKIP: {0}".format(len(run_exclude.intersection(conversations.keys()))))
    print("PASS: {0}".format(good))
    print("XFAIL: {0}".format(xfail))
    print("FAIL: {0}".format(bad))
    print("XPASS: {0}".format(xpass))
    print(20 * '=')
    sort = sorted(xpassed, key=natural_sort_keys)
    if len(sort):
        print("XPASSED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))
    sort = sorted(failed, key=natural_sort_keys)
    if len(sort):
        print("FAILED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))

    if bad > 0:
        sys.exit(1)
    elif timing:
        # if regular tests passed, run timing collection and analysis
        if TimingRunner.check_tcpdump():
            timing_runner = TimingRunner("{0}_v{1}_{2}".format(
                                            sys.argv[0],
                                            version,
                                            CipherSuite.ietfNames[cipher]),
                                         sampled_tests,
                                         outdir,
                                         host,
                                         port,
                                         interface,
                                         affinity)
            print("Running timing tests...")
            timing_runner.generate_log(run_only, run_exclude, repetitions)
            ret_val = timing_runner.run()
            if ret_val == 0:
                print("No statistically significant difference detected")
            elif ret_val == 1:
                print("Statisticaly significant difference detected at alpha="
                      "0.05")
            else:
                print("Statistical analysis exited with {0}".format(ret_val))
        else:
            print("Could not run timing tests because tcpdump is not present!")
            sys.exit(1)
        print(20 * '=')


if __name__ == "__main__":
    main()