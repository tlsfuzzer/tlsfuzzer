# Author: Hubert Kario, (c) 2023
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Utilities for testing RSA implementations."""

from tlsfuzzer.messages import fuzz_pkcs1_padding
from tlslite.utils.cryptomath import secureHMAC, numberToByteArray, numBytes,\
        getRandomBytes, numBits
from tlslite.utils.compat import int_to_bytes, bytes_to_int


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


def _calc_lengths(kdk, max_sep_offset):
    length_randoms = _dec_prf(kdk, b"length", 128 * 2 * 8)

    lengths = []
    length_rand_iter = iter(length_randoms)
    length_mask = (1 << numBits(max_sep_offset)) - 1
    for high, low in zip(length_rand_iter, length_rand_iter):
        len_candidate = (high << 8) + low
        len_candidate &= length_mask

        lengths.append(len_candidate)
    return lengths


def _calc_kdk(priv_key, ciphertext):
    if not hasattr(priv_key, '_key_hash') or not priv_key._key_hash:
        priv_key._key_hash = secureHash(
            numberToByteArray(priv_key.d, numBytes(priv_key.n)), "sha256")

    return secureHMAC(priv_key._key_hash, ciphertext, "sha256")


def synthetic_plaintext_generator(priv_key, ciphertext):
    """Generate a synthethic plaintext.

    This will generate a plaintext for the given ciphertext to be used in case
    the decryption fails.

    We use it to know what kind of PMS will the TLS layer see when we send a
    malformed ciphertext.
    """
    n_len = numBytes(priv_key.n)

    max_sep_offset = n_len - 10

    kdk = _calc_kdk(priv_key, ciphertext)

    message_random = _dec_prf(kdk, b"message", n_len * 8)

    lengths = _calc_lengths(kdk, max_sep_offset)

    synth_length = 0
    for length in lengths:
        if length < max_sep_offset:
            synth_length = length

    synth_msg_start = n_len - synth_length

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
    or invalid ciphertexts that have synthethic ciphertexts of specified
    length. All ciphertexts will also require the same number of bytes to
    store.

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
        self._pub_key_n_bytes = int_to_bytes(pub_key.n)

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

        # first random well-formed ciphertext canaries
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
        ciphertext = self._generate_ciphertext_with_fuzz({0: 1})
        ret["invalid version number (1) in padding"] = ciphertext

        # then let's try ones that use padding value set to 0
        ciphertext = self._generate_ciphertext_with_fuzz({1: 0})
        ret["invalid PKCS#1 type (0) in padding"] = ciphertext

        # then let's try ones that use padding value set to 1
        ciphertext = self._generate_ciphertext_with_fuzz({1: 1})
        ret["invalid PKCS#1 type (1) in padding"] = ciphertext

        # then let's try ones that use padding value set to 3
        ciphertext = self._generate_ciphertext_with_fuzz({1: 3})
        ret["invalid PKCS#1 type (3) in padding"] = ciphertext

        if self.pms_len > 2:
            # we need a source of entropy in the encrypted value
            # to actually get randomsied values we like,
            # with less than 2**16 possible
            # values (since there's no randomness in padding),
            # that's unlikely to happen, so skip those probes for small PMS
            # lengths

            # actually use padding type 1
            ciphertext = self._generate_ciphertext_with_fuzz({1: 1}, 0xff)
            ret["use PKCS#1 type 1 padding"] = ciphertext

            # actually use padding type 0
            ciphertext = self._generate_ciphertext_with_fuzz({1: 0}, 0)
            ret["use PKCS#1 type 0 padding"] = ciphertext

            # set padding to all zero bytes
            ciphertext = self._generate_ciphertext_with_fuzz(None, 0)
            ret["use 0 as padding byte"] = ciphertext

        # place zero byte in the first bytes of padding
        ciphertext = self._generate_ciphertext_with_fuzz({2: 0})
        ret["zero byte in first byte of padding"] = ciphertext

        # place zero byte in the first bytes of padding
        ciphertext = self._generate_ciphertext_with_fuzz({3: 0})
        ret["zero byte in second byte of padding"] = ciphertext

        # place zero byte in the first bytes of padding
        ciphertext = self._generate_ciphertext_with_fuzz({4: 0})
        ret["zero byte in third byte of padding"] = ciphertext

        # create too long plaintext by 1 bytes
        ciphertext = self._generate_ciphertext_with_fuzz({9: 0})
        ret["zero byte in eight byte of padding"] = ciphertext

        # no zero byte separator
        ciphertext = self._generate_ciphertext_with_fuzz({-1: 1}, pms=b"")
        ret["no null separator"] = ciphertext

        # completely random plaintext
        subs = dict()
        # first randomise the separator
        while True:
            a = getRandomBytes(1)
            if a[0] != 0:
                subs[-1] = a[0]
                break
        # then randomise the first two bytes of padding
        while True:
            a = getRandomBytes(2)
            if len(self.pub_key) % 8:
                a[0] &= 2 ** (len(self.pub_key) % 8) - 1
            if a[0] > self._pub_key_n_bytes[0] or \
                    a[0] == self._pub_key_n_bytes[0] and \
                    a[1] >= self._pub_key_n_bytes[1]:
                continue
            # don't make it start with a valid type 2 padding
            # while it's semi-unlikely with modulus bit size that's a
            # multiple of 8, a modulus size of 2049 bits make it quite
            # probable, so reject those
            if a[0] == 0 and a[1] == 2:
                continue
            break
        subs[0] = a[0]
        subs[1] = a[1]

        ciphertext = self._generate_ciphertext_with_fuzz(subs, pms=b"")
        ret["random plaintext"] = ciphertext

        # too short PKCS padding
        ciphertext = self._generate_ciphertext_with_fuzz({1: 0, 2: 2})
        ret["too short PKCS#1 padding"] = ciphertext

        # very short PKCS padding
        subs = dict(enumerate([0] * 41 + [2]))
        if numBytes(self.pub_key.n) - 42 < self.pms_len:
            # we need to change the padding bytes to get short padding,
            # thus we need to have enough padding; in case there's not
            # enough, just don't encrypt anything; this is about the
            # length of the returned synthethic message anyway...
            pms = b""
        else:
            pms = None
        ciphertext = self._generate_ciphertext_with_fuzz(subs, pms=pms)
        ret["very short PKCS#1 padding (40 bytes short)"] = ciphertext

        # too long PKCS padding
        if len(self.pub_key) % 8 == 1:
            subs = {0: 1}
        else:
            subs = {0: 2}
        ciphertext = self._generate_ciphertext_with_fuzz(subs)
        ret["too long PKCS#1 padding"] = ciphertext

        if self.pms_len > 2:
            # we need a source of entropy in the encrypted value
            # to actually get randomsied values we like,
            # with less than 2**16 possible
            # values (since there's no randomness in padding),
            # that's unlikely to happen, so skip those probes for small PMS
            # lengths

            # low Hamming weight RSA plaintext
            while True:
                rand_pms = self._get_random_pms()
                ciphertext = _encrypt_with_fuzzing(
                    self.pub_key, rand_pms, None, 1
                )
                # make sure MSB is non-zero to avoid side-channel based on
                # public value clamping
                if ciphertext[0]:
                    break
            assert rand_pms == self.priv_key.decrypt(ciphertext)
            ret["use 1 as the padding byte (low Hamming weight plaintext)"] = \
                ciphertext

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

        while True:
            ciphertext = getRandomBytes(numBytes(self.pub_key.n))
            ciphertext = int_to_bytes(
                bytes_to_int(ciphertext, "big") % self.pub_key.n,
                numBytes(self.pub_key.n)
            )
            if ciphertext[0] == 0:
                # don't want fake side-channel signal from ciphertext to
                # int conversion
                continue

            kdk = _calc_kdk(self.priv_key, ciphertext)
            max_sep_offset = numBytes(self.priv_key.n) - 10
            lengths = _calc_lengths(kdk, max_sep_offset)
            if lengths[-1] < max_sep_offset or lengths[-2] != self.pms_len:
                continue

            dec = self.priv_key._raw_private_key_op_bytes(ciphertext)
            if dec[0] == 0 or dec[1] == 2:
                continue

            dec = self.priv_key.decrypt(ciphertext)

            assert len(dec) != lengths[-1] and len(dec) == lengths[-2]

            break

        ret["random plaintext second to last length"] = ciphertext

        return ret
