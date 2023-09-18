# Author: Hubert Kario, (c) 2023
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Utilities for testing RSA implementations."""

from tlsfuzzer.messages import fuzz_pkcs1_padding
from tlslite.utils.cryptomath import secureHMAC, numberToByteArray, numBytes,\
        getRandomBytes, numBits


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

    def _get_random_pms(self):
        if self.tls_version is None:
            while True:
                rand_pms = getRandomBytes(self.pms_len)
                if bytes(rand_pms[:2]) not in self.forbidden:
                    break
        else:
            rand_pms = getRandomBytes(self.pms_len)
            rand_pms[0] = self.tls_version[0]
            rand_pms[1] = self.tls_version[1]
        return rand_pms

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
        """Create a dict() with test cases, where keys are descriptions and
        values are the ciphertexts."""
        ret = {}

        # first a random well-formed ciphertext canaries
        for i in range(1, 4):
            while True:
                rand_pms = self._get_random_pms()

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
            rand_pms = self._get_random_pms()
            ciphertext = _encrypt_with_fuzzing(self.pub_key, rand_pms, None, 1)
            # make sure MSB is non-zero to avoid side-channel based on public
            # value clamping
            if ciphertext[0]:
                break
        assert rand_pms == self.priv_key.decrypt(ciphertext)
        ret["use 1 as the padding byte (low Hamming weight plaintext)"] = ciphertext

        # valid with very long synthethic (unused) plaintext
        while True:
            rand_pms = self._get_random_pms()

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
            rand_pms = self._get_random_pms()

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
