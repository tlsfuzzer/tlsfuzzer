# Author: Alicja Kario, (c) 2025
# Released under Gnu GPL v2.0, see LICENSE file for detail

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
except ImportError:
    import unittest.mock as mock

from tlslite.utils.keyfactory import parsePEMKey
from tlslite.utils.cryptomath import secureHMAC, secureHash, \
        numberToByteArray, numBytes, numBits

from tlsfuzzer.utils.rsa import MarvinCiphertextGenerator


def calc_kdk(key, ciphertext):
    key_hash = secureHash(numberToByteArray(key.d, numBytes(key.n)), "sha256")

    kdk = secureHMAC(key_hash, ciphertext, "sha256")

    return kdk


def calc_lengths(key, kdk):
    lengths_bytes = key._dec_prf(kdk, b"length", 128 * 2 * 8)

    max_sep_offset = numBytes(key.n) - 10
    mask = (1 << numBits(max_sep_offset)) - 1

    lengths_iter = iter(lengths_bytes)

    lengths = [
        ((i << 8) + j) & mask
        for i, j in zip(lengths_iter, lengths_iter)
    ]
    return lengths


class TestMarvinCiphertext2048bitAnd48bytePMS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        priv_key = """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDIzIOXFAmNpWyq
I2QPk9yJl8FjcpaPwbDG31ETwclOiyHkitIpfmVBkBG05tj15zsbeLJXQAMh0e9r
YC1OyM6NFByUkF60rTBmOaSSBlNLbn8mB0I+l9/9EzyI1yE5ne+8fpbM3L1/Oq4f
6JJxK/tJKYF9URZmRAofrLeiCPXqFlkQrdij8tSXICNgzLYyAk8NBxacGRjzFveU
sUOu9U7IdSKkwCl4+WiZgL/79knDB+gYGb/4hAljjUi9lL4VK1n/ZJ+gvWKdD/oY
E8Or9LVr08LqVGXf+hRYkpKp2KJK0mvn7gUQdBtjgtQ8g9W/pApGYT0GK+RFUX28
rwy04adpAgMBAAECggEAFFUBDg8tWHZjpmam/xzNu/Dt2BAGRtAqAjkikImSxK05
5VZZKXJu9lCMOnEVjvC2/3UdOdB1gLstLwYyEEQtBgP/UNu9ezX+LJuxmkehr4Wk
wkkB4CyotYt5GbIO3zKqz79RrbS8S2G5t+loyqTVcPcO8Y2AYyKIk+R9Q578p5Ml
m88s0Qij2GiM3weOeseZlp8jOdLB9SK5aWhGKakzuq7CaBYl6rhPTlb0RH6diPua
GZz3ECPg4lexREGzPITTvGfKgDHSYSYYEDp6CkCEQmL3XYiQzWFuUfkDVIj9bgmd
6P9tZaT/EYJUgHyfWNL7uouhUdyMaL40nJd6IE4EwQKBgQD49a1rqCiTG+pFm4o/
bcBB0jSCQJwlcelj8x90hgKiVjcbOIPtRZ7PlwUmRZ7dFuBVIvWkXZR1Gy7C2vJy
x/iBalLADRgIAXFjTaiZ15cyIvUbk3YwVIaWqffYwkpZSXwe/NRVz7l+6G0rbTSX
KzMv2jA/BJmbTra1zAuzPndh3QKBgQDOei47SakLljMKEtxoK9+9+66N1twDthR6
771XV0Pw9tpNhiNQYbca/ZytLTQCXlashrD3dD6zXhrLyiN4lUJEZbcG7SIXXlcY
yMcLZwPqj2tRD5Rb5I5aNrs8PJFzK1id/AXXLYCQMZRFK9ohNIZH7HKUPxGoRuYv
rr6OtTaw/QKBgHb+FfGK4jnN8d9rRFykvGu5aNeIwhkzpPXc0oADPWcSBizAim3y
BMH70L5GMHRD5t1KZFY3VCnU4DjKJW+vHJvekcaxe3b4GZX5HEjLvrx78ONJTAg1
nk6M1qWH17ltYiH9fg+1xVdfCC7ld2l5gHGyu7SjIjgVG0cxS7ZUeQMRAoGBAJmI
SLBVSZoQCcvH0pSzax/98gIObnNkBT6U3hoADck0BYf34nJ29ozfYI11O2M3ewO2
9AhNLAJ8SziWCmIzup7Zc4t28Q6nW+RWB4v3AfZ8xrPz/cGG5kM2x2s3LoCRDsgL
CtzCPQL7muEEhqKCSAdbTqflbd/POILkUVYUcaKRAoGAZDv3RkKffYNmegZTAhNH
77/AXmNR+CGp3rtg4OzN5QBa2ensMeVY9+ksKTKOdFadfO98dMq8KzVe1AGhoJFL
Tjy7BkhOWBlgURae0UyqLvpuoETgVNJhRMwWKcVQEFWKBOEz9Et8JE2sJb+RPFe4
kO5J9UglnNY0BP72hZ3Pl1o=
-----END PRIVATE KEY-----
"""
        cls.priv_key = parsePEMKey(priv_key, private=True)

        pub_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyMyDlxQJjaVsqiNkD5Pc
iZfBY3KWj8Gwxt9RE8HJTosh5IrSKX5lQZARtObY9ec7G3iyV0ADIdHva2AtTsjO
jRQclJBetK0wZjmkkgZTS25/JgdCPpff/RM8iNchOZ3vvH6WzNy9fzquH+iScSv7
SSmBfVEWZkQKH6y3ogj16hZZEK3Yo/LUlyAjYMy2MgJPDQcWnBkY8xb3lLFDrvVO
yHUipMApePlomYC/+/ZJwwfoGBm/+IQJY41IvZS+FStZ/2SfoL1inQ/6GBPDq/S1
a9PC6lRl3/oUWJKSqdiiStJr5+4FEHQbY4LUPIPVv6QKRmE9BivkRVF9vK8MtOGn
aQIDAQAB
-----END PUBLIC KEY-----
"""
        cls.pub_key = parsePEMKey(pub_key, public=True)

        generator = MarvinCiphertextGenerator(
            cls.priv_key, cls.pub_key,
            pms_len=48, tls_version=None
        )

        cls.ciphertexts = generator.generate()

    def test_presence_of_all_expected(self):
        self.assertEqual(len(self.ciphertexts), 23)

        expected = set([
            "well formed - 1",
            "well formed - 2",
            "well formed - 3",
            "invalid version number (1) in padding",
            "invalid PKCS#1 type (0) in padding",
            "invalid PKCS#1 type (1) in padding",
            "invalid PKCS#1 type (3) in padding",
            "use PKCS#1 type 1 padding",
            "use PKCS#1 type 0 padding",
            "use 0 as padding byte",
            "zero byte in first byte of padding",
            "zero byte in second byte of padding",
            "zero byte in third byte of padding",
            "zero byte in eight byte of padding",
            "no null separator",
            "random plaintext",
            "too short PKCS#1 padding",
            "very short PKCS#1 padding (40 bytes short)",
            "too long PKCS#1 padding",
            "use 1 as the padding byte (low Hamming weight plaintext)",
            "well formed with very long synthethic PMS",
            "well formed with empty synthethic PMS",
            "random plaintext second to last length",
        ])

        self.assertEqual(set(self.ciphertexts.keys()), expected)

    def test_well_formed(self):
        self.assertIn("well formed - 1", self.ciphertexts)
        self.assertIn("well formed - 2", self.ciphertexts)
        self.assertIn("well formed - 3", self.ciphertexts)

        self.assertNotEqual(
            self.ciphertexts["well formed - 1"],
            self.ciphertexts["well formed - 2"]
        )
        self.assertNotEqual(
            self.ciphertexts["well formed - 1"],
            self.ciphertexts["well formed - 3"]
        )
        self.assertNotEqual(
            self.ciphertexts["well formed - 2"],
            self.ciphertexts["well formed - 3"]
        )

        for num in range(1, 4):
            name = "well formed - {0}".format(num)

            ciphertext = self.ciphertexts[name]

            plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

            self.assertEqual(plaintext[0:2], b'\x00\x02')
            self.assertTrue(all(plaintext[2:-49]))
            self.assertEqual(plaintext[-49], 0)

            msg = self.priv_key.decrypt(ciphertext)

            self.assertEqual(len(msg), 48)
            self.assertEqual(msg, plaintext[-48:])

    def test_invalid_version(self):
        ciphertext = self.ciphertexts["invalid version number (1) in padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x01\x02')
        self.assertTrue(all(plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_invalid_type_0(self):
        ciphertext = self.ciphertexts["invalid PKCS#1 type (0) in padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x00')
        self.assertTrue(all(plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_invalid_type_1(self):
        ciphertext = self.ciphertexts["invalid PKCS#1 type (1) in padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x01')
        self.assertTrue(all(plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_invalid_type_3(self):
        ciphertext = self.ciphertexts["invalid PKCS#1 type (3) in padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x03')
        self.assertTrue(all(plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_padding_type_1(self):
        ciphertext = self.ciphertexts["use PKCS#1 type 1 padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x01')
        self.assertTrue(all(i == 0xff for i in plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)
        self.assertTrue(any(plaintext[-48:]))

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_padding_type_0(self):
        ciphertext = self.ciphertexts["use PKCS#1 type 0 padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x00')
        self.assertTrue(all(i == 0x00 for i in plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)
        self.assertTrue(any(plaintext[-48:]))

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_0_as_padding_byte(self):
        ciphertext = self.ciphertexts["use 0 as padding byte"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(all(i == 0x00 for i in plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)
        self.assertTrue(any(plaintext[-48:]))

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_zero_in_first_byte(self):
        ciphertext = self.ciphertexts["zero byte in first byte of padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertEqual(plaintext[2], 0)
        self.assertTrue(all(plaintext[3:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_zero_in_second_byte(self):
        ciphertext = self.ciphertexts["zero byte in second byte of padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(plaintext[2])
        self.assertEqual(plaintext[3], 0)
        self.assertTrue(all(plaintext[4:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_zero_in_third_byte(self):
        ciphertext = self.ciphertexts["zero byte in third byte of padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(plaintext[2])
        self.assertTrue(plaintext[3])
        self.assertEqual(plaintext[4], 0)
        self.assertTrue(all(plaintext[5:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_zero_in_eight_byte(self):
        ciphertext = self.ciphertexts["zero byte in eight byte of padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(all(plaintext[2:9]))
        self.assertEqual(plaintext[9], 0)
        self.assertTrue(all(plaintext[10:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_no_null_separator(self):
        ciphertext = self.ciphertexts["no null separator"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(all(plaintext[2:]))

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_random_plaintext(self):
        ciphertext = self.ciphertexts["random plaintext"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertNotEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(all(plaintext[2:]))

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_too_short_padding(self):
        ciphertext = self.ciphertexts["too short PKCS#1 padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:3], b'\x00\x00\x02')
        self.assertTrue(all(plaintext[3:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_very_short_padding(self):
        ciphertext = self.ciphertexts["very short PKCS#1 padding (40 bytes short)"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertTrue(all(i == 0 for i in plaintext[0:41]))
        self.assertEqual(plaintext[41:42], b'\x02')
        self.assertTrue(all(plaintext[42:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_too_long_padding(self):
        ciphertext = self.ciphertexts["too long PKCS#1 padding"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:1], b'\x02')
        self.assertTrue(all(plaintext[1:-49]))
        self.assertEqual(plaintext[-49], 0)

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

    def test_use_low_hamming_weight_plaintext(self):
        ciphertext = self.ciphertexts["use 1 as the padding byte (low Hamming weight plaintext)"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(all(i == 1 for i in plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)
        self.assertTrue(any(plaintext[-48:]))

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertEqual(msg, plaintext[-48:])

    def test_good_with_long_synthethic(self):
        ciphertext = self.ciphertexts["well formed with very long synthethic PMS"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(all(plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)
        self.assertTrue(any(plaintext[-48:]))

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertEqual(msg, plaintext[-48:])

        kdk = calc_kdk(self.priv_key, ciphertext)

        lengths = calc_lengths(self.priv_key, kdk)

        # the length will generally be taken from the last one, but it's
        # not guaranteed
        for i in range(-1, -32, -1):
            if lengths[i] > 2048 // 8 - 1 - 1 - 8 - 1:
                continue
            self.assertEqual(lengths[i], 2048 // 8 - 1 - 1 - 8 - 1)
            break

    def test_good_with_empty_synthethic(self):
        ciphertext = self.ciphertexts["well formed with empty synthethic PMS"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertEqual(plaintext[0:2], b'\x00\x02')
        self.assertTrue(all(plaintext[2:-49]))
        self.assertEqual(plaintext[-49], 0)
        self.assertTrue(any(plaintext[-48:]))

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertEqual(msg, plaintext[-48:])

        kdk = calc_kdk(self.priv_key, ciphertext)

        lengths = calc_lengths(self.priv_key, kdk)

        # the length will generally be taken from the last one, but it's
        # not guaranteed
        for i in range(-1, -32, -1):
            if lengths[i] > 2048 // 8 - 1 - 1 - 8 - 1:
                continue
            self.assertEqual(lengths[i], 0)
            break

    def test_random_with_second_to_last_length(self):
        ciphertext = self.ciphertexts["random plaintext second to last length"]

        plaintext = self.priv_key._raw_private_key_op_bytes(ciphertext)

        self.assertNotEqual(plaintext[0:2], b'\x00\x02')

        msg = self.priv_key.decrypt(ciphertext)

        self.assertEqual(len(msg), 48)
        self.assertNotEqual(msg, plaintext[-48:])

        kdk = calc_kdk(self.priv_key, ciphertext)

        lengths = calc_lengths(self.priv_key, kdk)

        self.assertGreater(lengths[-1], 2048 // 8 - 1 - 1 - 8 - 1)
        self.assertEqual(lengths[-2], 48)
