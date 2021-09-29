# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call
import sys

from tlsfuzzer.expect import Expect, ExpectHandshake, ExpectServerHello, \
        ExpectCertificate, ExpectServerHelloDone, ExpectChangeCipherSpec, \
        ExpectFinished, ExpectAlert, ExpectApplicationData, \
        ExpectCertificateRequest, ExpectServerKeyExchange, \
        ExpectServerHello2, ExpectVerify, ExpectSSL2Alert, \
        ExpectCertificateStatus, ExpectNoMessage, srv_ext_handler_ems, \
        srv_ext_handler_etm, srv_ext_handler_sni, srv_ext_handler_renego, \
        srv_ext_handler_alpn, srv_ext_handler_ec_point, srv_ext_handler_npn, \
        srv_ext_handler_key_share, srv_ext_handler_supp_vers, \
        ExpectCertificateVerify, ExpectEncryptedExtensions, \
        ExpectNewSessionTicket, hrr_ext_handler_key_share, \
        hrr_ext_handler_cookie, ExpectHelloRetryRequest, \
        gen_srv_ext_handler_psk, srv_ext_handler_supp_groups, \
        srv_ext_handler_heartbeat, gen_srv_ext_handler_record_limit, \
        srv_ext_handler_status_request, ExpectHeartbeat, ExpectHelloRequest, \
        clnt_ext_handler_status_request, clnt_ext_handler_sig_algs, \
        ExpectKeyUpdate

from tlslite.constants import ContentType, HandshakeType, ExtensionType, \
        AlertLevel, AlertDescription, ClientCertificateType, HashAlgorithm, \
        SignatureAlgorithm, CipherSuite, CertificateType, SSL2HandshakeType, \
        SSL2ErrorDescription, GroupName, CertificateStatusType, ECPointFormat,\
        SignatureScheme, TLS_1_3_HRR, HeartbeatMode, \
        TLS_1_1_DOWNGRADE_SENTINEL, TLS_1_2_DOWNGRADE_SENTINEL, \
        HeartbeatMessageType, KeyUpdateMessageType
from tlslite.messages import Message, ServerHello, CertificateRequest, \
        ClientHello, Certificate, ServerHello2, ServerFinished, \
        ServerKeyExchange, CertificateStatus, CertificateVerify, \
        Finished, EncryptedExtensions, NewSessionTicket, Heartbeat, \
        KeyUpdate, HelloRequest, ServerHelloDone
from tlslite.extensions import SNIExtension, TLSExtension, \
        SupportedGroupsExtension, ALPNExtension, ECPointFormatsExtension, \
        NPNExtension, ServerKeyShareExtension, ClientKeyShareExtension, \
        SrvSupportedVersionsExtension, SupportedVersionsExtension, \
        HRRKeyShareExtension, CookieExtension, \
        SrvPreSharedKeyExtension, PskIdentity, PreSharedKeyExtension, \
        HeartbeatExtension, StatusRequestExtension
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509certchain import X509CertChain, X509
from tlslite.extensions import SNIExtension, SignatureAlgorithmsExtension
from tlslite.keyexchange import DHE_RSAKeyExchange, ECDHE_RSAKeyExchange
from tlslite.errors import TLSIllegalParameterException, TLSDecryptionFailed
from tlsfuzzer.runner import ConnectionState
from tlslite.extensions import RenegotiationInfoExtension, \
        RecordSizeLimitExtension
from tlsfuzzer.helpers import key_share_gen, psk_ext_gen
from tlslite.keyexchange import ECDHKeyExchange
from tlslite.mathtls import goodGroupParameters
from tlslite.utils.cryptomath import secureHash


srv_raw_key = str(
    "-----BEGIN RSA PRIVATE KEY-----\n"\
    "MIICXQIBAAKBgQDRCQR5qRLJX8sy1N4BF1G1fml1vNW5S6o4h3PeWDtg7JEn+jIt\n"\
    "M/NZekrGv/+3gU9C9ixImJU6U+Tz3kU27qw0X+4lDJAZ8VZgqQTp/MWJ9Dqz2Syy\n"\
    "yQWUvUNUj90P9mfuyDO5rY/VLIskdBNOzUy0xvXvT99fYQE+QPP7aRgo3QIDAQAB\n"\
    "AoGAVSLbE8HsyN+fHwDbuo4I1Wa7BRz33xQWLBfe9TvyUzOGm0WnkgmKn3LTacdh\n"\
    "GxgrdBZXSun6PVtV8I0im5DxyVaNdi33sp+PIkZU386f1VUqcnYnmgsnsUQEBJQu\n"\
    "fUZmgNM+bfR+Rfli4Mew8lQ0sorZ+d2/5fsM0g80Qhi5M3ECQQDvXeCyrcy0u/HZ\n"\
    "FNjIloyXaAIvavZ6Lc6gfznCSfHc5YwplOY7dIWp8FRRJcyXkA370l5dJ0EXj5Gx\n"\
    "udV9QQ43AkEA34+RxjRk4DT7Zo+tbM/Fkoi7jh1/0hFkU5NDHweJeH/mJseiHtsH\n"\
    "KOcPGtEGBBqT2KNPWVz4Fj19LiUmmjWXiwJBAIBs49O5/+ywMdAAqVblv0S0nweF\n"\
    "4fwne4cM+5ZMSiH0XsEojGY13EkTEon/N8fRmE8VzV85YmkbtFWgmPR85P0CQQCs\n"\
    "elWbN10EZZv3+q1wH7RsYzVgZX3yEhz3JcxJKkVzRCnKjYaUi6MweWN76vvbOq4K\n"\
    "G6Tiawm0Duh/K4ZmvyYVAkBppE5RRQqXiv1KF9bArcAJHvLm0vnHPpf1yIQr5bW6\n"\
    "njBuL4qcxlaKJVGRXT7yFtj2fj0gv3914jY2suWqp8XJ\n"\
    "-----END RSA PRIVATE KEY-----\n"\
    )

srv_raw_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"\
    "MIIB9jCCAV+gAwIBAgIJAMyn9DpsTG55MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\n"\
    "BAMMCWxvY2FsaG9zdDAeFw0xNTAxMjExNDQzMDFaFw0xNTAyMjAxNDQzMDFaMBQx\n"\
    "EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n"\
    "0QkEeakSyV/LMtTeARdRtX5pdbzVuUuqOIdz3lg7YOyRJ/oyLTPzWXpKxr//t4FP\n"\
    "QvYsSJiVOlPk895FNu6sNF/uJQyQGfFWYKkE6fzFifQ6s9kssskFlL1DVI/dD/Zn\n"\
    "7sgzua2P1SyLJHQTTs1MtMb170/fX2EBPkDz+2kYKN0CAwEAAaNQME4wHQYDVR0O\n"\
    "BBYEFJtvXbRmxRFXYVMOPH/29pXCpGmLMB8GA1UdIwQYMBaAFJtvXbRmxRFXYVMO\n"\
    "PH/29pXCpGmLMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAkOgC7LP/\n"\
    "Rd6uJXY28HlD2K+/hMh1C3SRT855ggiCMiwstTHACGgNM+AZNqt6k8nSfXc6k1gw\n"\
    "5a7SGjzkWzMaZC3ChBeCzt/vIAGlMyXeqTRhjTCdc/ygRv3NPrhUKKsxUYyXRk5v\n"\
    "g/g6MwxzXfQP3IyFu3a9Jia/P89Z1rQCNRY=\n"\
    "-----END CERTIFICATE-----\n"\
    )


srv_raw_pss_key = str(
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEugIBADALBgkqhkiG9w0BAQoEggSmMIIEogIBAAKCAQEApq5FnZRNmtJy+WjN\n"
    "RB8w0ol2+IEcATrUkZpz7HNqq8+EL/GN21m35luz5fcA8ifkm4pKxfwtxY7u912t\n"
    "AfsEavUr/UoyLScXQevhr6SLXR8UO3XE6ne1F88eZNpgKVpocDVKRLjIqKHSSbBN\n"
    "kG76mGKFYyNZXm3qRxaUSHVLnN/opOGfgVK8Vbj0v2EH5L5dGLQLV2ZfQ75I4OGr\n"
    "g8wse5fhgt2oczhhe72sEuMDc08WHGRp9744mMQvVYrtpWUHkP5tdD4i7/zYf3ni\n"
    "g21/G56JY20JpW+1J5fEn+PEqiJsv5prNJuPp/zdjD3uImqfXZzXUeRIQr9l1qXI\n"
    "6JPInwIDAQABAoIBAA0BqFkFi5C7P1GLBgl8zZiANZJqsL6/0nqSLN2UnAxQIyaC\n"
    "mOk29Qy6ty0Iu0AqMMKaZf9REFlMMAWJf8iZx9x4yTf4pDW1yTDRsUi9dEqN9Ew3\n"
    "gmgxcyYqeVqxV7OiZGftIKCAMthF2Fz7rvHIVzGw7muwBHdD6HYnouaMkJvrFLkW\n"
    "a41VKi2oJJA4ZXrxHORm9lfAfnvoJVIRvG9z9NDMvi+PBx/wSdFwlVXhSjVnYuTH\n"
    "laaYBUaH7D9BL8O1aVIRLCDw3Q/4ciTHGByI+6Iremk9nRZEO5igYlK427eKIRGW\n"
    "lvvy+/+EXPiVwWX9V11CDWm2hOTWYs8wNE7fsSECgYEA2h+gK81yGTpR3/SXxW3i\n"
    "ojRXXLVxZpi94ZUAvBmOgb+wZQeHWDO0dN37MwAhimHrWsaBEezVKVj6ntBU3Je2\n"
    "oC+MjLxDaTDvTsvuKvh4zhuiUGcY+XfP9yv9HX3U8Ys3GISJ4HdOBLsISA8zJs+D\n"
    "vNC6Be/ez9uORb9jfDBG9BcCgYEAw5/UZGWmZLFcwhO5QX8JytXAj9xiMANGBhJb\n"
    "wQBMEgRpSgHvKI2i32oUOuCQz7wcIgwtgmIhCBz8ld4ky6CYOfQXj+sW9V/drRTl\n"
    "4M9H+wdwOsB0/ELIZYlFZ82zMgMYJrEFGZR05DSFbeUHEzm8RG9hbsdxkRBtHQIv\n"
    "AJOoPLkCgYAJZUlZ+ayLh6aVNgz/lR8pC4Yj2TD8UWIEgI2ajKNF1YL8pxleZEPG\n"
    "sPUsGjpXoqYnr9tJcWExOcL56lFtex+DwOiV+1oQAuqcA07MDQ3vGuOgAQDjZhTQ\n"
    "OdXaWlw811lVNghWYe07aO8PY5A5gMDU9ky9CrsXSwbS3E6lv9KemwKBgBhjEm05\n"
    "ptairbecEdoyZhwdLZZBmRP3NIGJRFr5GIKefim1uATMM2O6q67zU9oxzygHcJzy\n"
    "cr+6LVrZiKjB6ng/D7jnS8NnIhFzq3ytGoIW2UzZtTvFb4oI5Ngd8prne9lG9CXO\n"
    "NgxE5+VdSdaBuhCl+fV/c47sB044eXeO8MgxAoGAQUL40ZtfXrbPHBjHwsEHf8hS\n"
    "XUPtd3cVyPZigz+6P3Cr54GvicRaoaYeUt2zrbjqgiX/bAW/Xq6Pu+UpDyCQ6Er5\n"
    "OvDrbz1v5sfhn3Eubh2a4LZy7EiKveTtOpmqFs6XZ1FYoMSdeMr44Mql8G2MGa2d\n"
    "n15sR5bRKF3dVy2qO0A=\n"
    "-----END PRIVATE KEY-----\n"
    )


srv_raw_pss_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDWzCCAhKgAwIBAgIJAM94DjB2Qf+GMD4GCSqGSIb3DQEBCjAxoA0wCwYJYIZI\n"
    "AWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIEAgIA3jAUMRIwEAYD\n"
    "VQQDDAlsb2NhbGhvc3QwHhcNMTcwMzA4MTMzMzU4WhcNMTcwNDA3MTMzMzU4WjAU\n"
    "MRIwEAYDVQQDDAlsb2NhbGhvc3QwggEgMAsGCSqGSIb3DQEBCgOCAQ8AMIIBCgKC\n"
    "AQEApq5FnZRNmtJy+WjNRB8w0ol2+IEcATrUkZpz7HNqq8+EL/GN21m35luz5fcA\n"
    "8ifkm4pKxfwtxY7u912tAfsEavUr/UoyLScXQevhr6SLXR8UO3XE6ne1F88eZNpg\n"
    "KVpocDVKRLjIqKHSSbBNkG76mGKFYyNZXm3qRxaUSHVLnN/opOGfgVK8Vbj0v2EH\n"
    "5L5dGLQLV2ZfQ75I4OGrg8wse5fhgt2oczhhe72sEuMDc08WHGRp9744mMQvVYrt\n"
    "pWUHkP5tdD4i7/zYf3nig21/G56JY20JpW+1J5fEn+PEqiJsv5prNJuPp/zdjD3u\n"
    "ImqfXZzXUeRIQr9l1qXI6JPInwIDAQABo1AwTjAdBgNVHQ4EFgQUcTYhLu7pODIv\n"
    "B6KhR6eyFBB5wacwHwYDVR0jBBgwFoAUcTYhLu7pODIvB6KhR6eyFBB5wacwDAYD\n"
    "VR0TBAUwAwEB/zA+BgkqhkiG9w0BAQowMaANMAsGCWCGSAFlAwQCAaEaMBgGCSqG\n"
    "SIb3DQEBCDALBglghkgBZQMEAgGiBAICAN4DggEBAKMgweHM6WTwlWEQHLG5K+7B\n"
    "hrAUEAsuK8F7sKGKzLEFzYdzZpkJw8LahE4dFayjx/7MD4rZ5IiHQhJcGCdHIVVv\n"
    "ocunlEUTgiKkMxTw4JxqSq0snvNBie04vnn+zUjD7FrctTUutzlH1yKftwbJpGk6\n"
    "CrTW6ctFTAIDwZHd+WX4RPewGY0LTfC+RjcMwWZBmbfVLxuJs0sidSUoNW6GgGE1\n"
    "DIDVeW2yKGeNhjK/3aDzfQWbz1J64aRfccVzXYMPsoABnNJnJgRETh1/Ci0sQ9Vd\n"
    "1OR6iS4hl88/1d7utc00MyFVk1sUIGf54EeCvrNB4bhKtawEJk8Q8AGIRhs93sk=\n"
    "-----END CERTIFICATE-----\n"
    )


srv_raw_ecdsa_key = str(
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCOZr0Ovs0eCmh+XM\n"
    "QWDYVpsQ+sJdjiq/itp/kYnWNSahRANCAATINGMQAl7cXlPrYzJluGOgmc8sYvae\n"
    "tO2EsXKYG6lnYhudZiepVYORP8vqLyxCF/bMIuuVKOPWSfsRGo/H8pnK\n"
    "-----END PRIVATE KEY-----\n"
    )


srv_raw_ecdsa_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBbTCCARSgAwIBAgIJAPM58cskyK+yMAkGByqGSM49BAEwFDESMBAGA1UEAwwJ\n"
    "bG9jYWxob3N0MB4XDTE3MTAyMzExNDI0MVoXDTE3MTEyMjExNDI0MVowFDESMBAG\n"
    "A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyDRjEAJe\n"
    "3F5T62MyZbhjoJnPLGL2nrTthLFymBupZ2IbnWYnqVWDkT/L6i8sQhf2zCLrlSjj\n"
    "1kn7ERqPx/KZyqNQME4wHQYDVR0OBBYEFPfFTUg9o3t6ehLsschSnC8Te8oaMB8G\n"
    "A1UdIwQYMBaAFPfFTUg9o3t6ehLsschSnC8Te8oaMAwGA1UdEwQFMAMBAf8wCQYH\n"
    "KoZIzj0EAQNIADBFAiA6p0YM5ZzfW+klHPRU2r13/IfKgeRfDR3dtBngmPvxUgIh\n"
    "APTeSDeJvYWVBLzyrKTeSerNDKKHU2Rt7sufipv76+7s\n"
    "-----END CERTIFICATE-----\n"
    )


srv_raw_ed25519_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBPDCB76ADAgECAhQkqENccCvOQyI4iKFuuOKwl860bTAFBgMrZXAwFDESMBAG\n"
    "A1UEAwwJbG9jYWxob3N0MB4XDTIxMDcyNjE0MjcwN1oXDTIxMDgyNTE0MjcwN1ow\n"
    "FDESMBAGA1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA1KMGmAZealfgakBuCx/E\n"
    "n69fo072qm90eM40ulGex0ajUzBRMB0GA1UdDgQWBBTHKWv5l/SxnkkYJhh5r3Pv\n"
    "ESAh1DAfBgNVHSMEGDAWgBTHKWv5l/SxnkkYJhh5r3PvESAh1DAPBgNVHRMBAf8E\n"
    "BTADAQH/MAUGAytlcANBAF/vSBfOHAdRl29sWDTkuqy1dCuSf7j7jKE/Be8Fk7xs\n"
    "WteXJmIa0HlRAZjxNfWbsSGLnTYbsGTbxKx3QU9H9g0=\n"
    "-----END CERTIFICATE-----\n"
    )


srv_raw_ed25519_key = str(
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIAjtEwCECqbot5RZxSmiNDWcPp+Xc9Y9WJcUhti3JgSP\n"
    "-----END PRIVATE KEY-----\n"
    )


srv_raw_ed448_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiDCCAQigAwIBAgIUZoaDDgE5Cy2GuAMtk4lnsmrPF04wBQYDK2VxMBQxEjAQ\n"
    "BgNVBAMMCWxvY2FsaG9zdDAeFw0yMTA3MjYxODAzMzhaFw0yMTA4MjUxODAzMzha\n"
    "MBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBDMAUGAytlcQM6AKxTNGJ39O4kUx7BopPK\n"
    "prb1Jkoo0csq0Cmpa+VhpDlbR9/gVsb3pchexzjxXyRkNv71naHmOkQvAKNTMFEw\n"
    "HQYDVR0OBBYEFBb153yRh5IZOfBxoakGVuviFKujMB8GA1UdIwQYMBaAFBb153yR\n"
    "h5IZOfBxoakGVuviFKujMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VxA3MAiXEqTPRb\n"
    "u+56ebfiGjdE++H+YvHVxxxycqKAIAikfsLFfw2LUGQVBMhl+nzS4zRDOKa34uGz\n"
    "DwEApFuOWurH/y8zqM5NFyXfwbHRlhG4xwUet52CbrtC7Dy1HYnvWdEjbKDSJXpJ\n"
    "MmNSiO0oBtQ62CsA\n"
    "-----END CERTIFICATE-----\n"
    )


srv_raw_ed448_key = str(
    "-----BEGIN PRIVATE KEY-----\n"
    "MEcCAQAwBQYDK2VxBDsEOWC42wrEHt4sse84L8oi/2LfqtYvT+Xwd5USLJuAUi6h\n"
    "Ht8RBuFGD/DoZIfwfBgBfemM56jAnbQIug==\n"
    "-----END PRIVATE KEY-----\n"
    )


class TestExpect(unittest.TestCase):
    def test___init__(self):
        exp = Expect(ContentType.handshake)

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = Expect(ContentType.handshake)

        with self.assertRaises(NotImplementedError):
            exp.process(None, None)


class TestExpectNoMessage(unittest.TestCase):
    def test___init__(self):
        timeout = mock.Mock()
        exp = ExpectNoMessage(timeout)

        self.assertIsNotNone(exp)
        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())
        self.assertIs(exp.timeout, timeout)

    def test_process(self):
        exp = ExpectNoMessage()

        exp.process(None, None)


class TestExpectHandshake(unittest.TestCase):
    def test_process(self):
        exp = ExpectHandshake(ContentType.handshake,
                              HandshakeType.client_hello)

        with self.assertRaises(NotImplementedError):
            exp.process(None, None)

    def test_is_match_with_empty_message(self):
        exp = ExpectHandshake(ContentType.handshake,
                              HandshakeType.client_hello)

        ret = exp.is_match(Message(ContentType.handshake, bytearray(0)))

        self.assertFalse(ret)

    def test__cmp_eq_or_in(self):
        ret = ExpectHandshake._cmp_eq_or_in([2, 3, 4], 3)

        self.assertIsNone(ret)

    def test__cmp_eq_or_in_with_None(self):
        ret = ExpectHandshake._cmp_eq_or_in(None, 3)

        self.assertIsNone(ret)

    def test__cmp_eq_or_in_not_matching(self):
        with self.assertRaises(AssertionError) as e:
            ExpectHandshake._cmp_eq_or_in([2, 3, 4], 1)

        self.assertIn("[2, 3, 4]", str(e.exception))
        self.assertIn("not in expected", str(e.exception))
        self.assertIn("1", str(e.exception))

    def test__cmp_eq_or_in_mismatch_with_type(self):
        with self.assertRaises(AssertionError) as e:
            ExpectHandshake._cmp_eq_or_in(
                [HandshakeType.client_hello,
                 HandshakeType.server_hello],
                HandshakeType.server_key_exchange,
                field_type=HandshakeType)

        self.assertIn("client_hello, server_hello", str(e.exception))
        self.assertIn("server_key_exchange", str(e.exception))

    def test__cmp_eq_or_in_mismatch_with_format_string(self):
        with self.assertRaises(AssertionError) as e:
            ExpectHandshake._cmp_eq_or_in([2, 3], 1,
                f_str="our: {0}, ext: {1}")

        self.assertIn("our: [2, 3], ext: 1", str(e.exception))

    def test__cmp_eq_list_no_type(self):
        ret = ExpectHandshake._cmp_eq_list((1, 2), (1, 2))

        self.assertIsNone(ret)

    def test__cmp_eq_list_no_type_mismatched_lists(self):
        with self.assertRaises(AssertionError) as e:
            ExpectHandshake._cmp_eq_list((1, 2), (2, 1))

        self.assertEqual("Expected: (1, 2), received: (2, 1)",
                         str(e.exception))


class TestServerExtensionProcessors(unittest.TestCase):
    def test_srv_ext_handler_ems(self):
        ext = TLSExtension(extType=ExtensionType.extended_master_secret)

        state = ConnectionState()

        srv_ext_handler_ems(state, ext)

        self.assertTrue(state.extended_master_secret)

    def test_srv_ext_handler_ems_with_malformed_extension(self):
        ext = TLSExtension(extType=ExtensionType.extended_master_secret)
        ext.create(bytearray(1))

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_ems(state, ext)


    def test_srv_ext_handler_etm(self):
        ext = TLSExtension(extType=ExtensionType.encrypt_then_mac)

        state = ConnectionState()

        srv_ext_handler_etm(state, ext)

        self.assertTrue(state.encrypt_then_mac)

    def test_srv_ext_handler_etm_with_malformed_extension(self):
        ext = TLSExtension(extType=ExtensionType.encrypt_then_mac)
        ext.create(bytearray(1))

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_etm(state, ext)


    def test_srv_ext_handler_sni(self):
        ext = SNIExtension()

        state = ConnectionState()

        srv_ext_handler_sni(state, ext)

    def test_srv_ext_handler_sni_with_malformed_extension(self):
        ext = SNIExtension().create(b'example.com')

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_sni(state, ext)

    def test_srv_ext_handler_status_request(self):
        ext = StatusRequestExtension()

        state = ConnectionState()

        srv_ext_handler_status_request(state, ext)

    def test_srv_ext_handler_status_request_with_malformed_extension(self):
        ext = StatusRequestExtension().create()

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_status_request(state, ext)

    def test_clnt_ext_handler_status_request(self):
        ext = StatusRequestExtension().create()

        clnt_ext_handler_status_request(None, ext)

    def test_clnt_ext_handler_status_request_with_empty_extension(self):
        ext = StatusRequestExtension().create()
        ext.responder_id_list = None

        with self.assertRaises(AssertionError):
            clnt_ext_handler_status_request(None, ext)

    def test_clnt_ext_handler_status_request_with_wrong_type(self):
        ext = StatusRequestExtension().create()
        ext.status_type = 0

        with self.assertRaises(AssertionError):
            clnt_ext_handler_status_request(None, ext)

    def test_srv_ext_handler_renego(self):
        ext = RenegotiationInfoExtension().create(bytearray(b'abba'))

        state = ConnectionState()
        state.key['client_verify_data'] = bytearray(b'ab')
        state.key['server_verify_data'] = bytearray(b'ba')

        srv_ext_handler_renego(state, ext)

    def test_srv_ext_handler_renego_with_malformed_extension(self):
        ext = RenegotiationInfoExtension()

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_renego(state, ext)

    def test_srv_ext_handler_alpn(self):
        ext = ALPNExtension().create([b'http/1.1'])

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = ALPNExtension().create([b'http/1.1', b'spdy2', b'h2'])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        srv_ext_handler_alpn(state, ext)

    def test_srv_ext_handler_alpn_with_malformed_extension(self):
        ext = ALPNExtension()

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = ALPNExtension().create([b'http/1.1', b'spdy2', b'h2'])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(AssertionError):
            srv_ext_handler_alpn(state, ext)

    def test_srv_ext_handler_alpn_with_wrong_protocol(self):
        ext = ALPNExtension().create([b'http/1.0'])

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = ALPNExtension().create([b'http/1.1', b'spdy2', b'h2'])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(AssertionError):
            srv_ext_handler_alpn(state, ext)

    def test_srv_ext_handler_ec_point(self):
        ext = ECPointFormatsExtension().create([ECPointFormat.uncompressed])

        state = ConnectionState()

        srv_ext_handler_ec_point(state, ext)

    def test_srv_ext_handler_ec_point_with_malformed_extension(self):
        ext = ECPointFormatsExtension()

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_ec_point(state, ext)

    def test_srv_ext_handler_npn(self):
        ext = NPNExtension().create([b'http/1.1'])

        state = ConnectionState()

        srv_ext_handler_npn(state, ext)

    def test_srv_ext_handler_npn_with_malformed_extension(self):
        ext = NPNExtension()

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_npn(state, ext)

    def test_srv_ext_handler_key_share(self):
        s_ks = key_share_gen(GroupName.secp256r1)
        s_private = s_ks.private
        s_ks.private = None

        ext = ServerKeyShareExtension().create(s_ks)

        state = ConnectionState()

        client_hello = ClientHello()
        c_ks = key_share_gen(GroupName.secp256r1)
        cln_ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        srv_ext_handler_key_share(state, ext)

        kex = ECDHKeyExchange(GroupName.secp256r1, (3, 4))
        shared = kex.calc_shared_key(s_private, c_ks.key_exchange)

        self.assertEqual(state.key['DH shared secret'], shared)

    def test_srv_ext_handler_key_share_bad_srv_group(self):
        s_ks = key_share_gen(GroupName.secp256r1)
        ext = ServerKeyShareExtension().create(s_ks)

        state = ConnectionState()

        client_hello = ClientHello()
        c_ks = key_share_gen(GroupName.x25519)
        cln_ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(AssertionError) as exc:
            srv_ext_handler_key_share(state, ext)

        self.assertIn("secp256r1", str(exc.exception))
        self.assertIn("didn't advertise", str(exc.exception))

    def test_srv_ext_handler_key_share_missing_private(self):
        s_ks = key_share_gen(GroupName.secp256r1)
        s_private = s_ks.private
        s_ks.private = None

        ext = ServerKeyShareExtension().create(s_ks)

        state = ConnectionState()

        client_hello = ClientHello()
        c_ks = key_share_gen(GroupName.secp256r1)
        c_ks.private = None
        cln_ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(ValueError) as exc:
            srv_ext_handler_key_share(state, ext)

        self.assertIn("secp256r1", str(exc.exception))
        self.assertIn("private", str(exc.exception))

    def test_srv_ext_handler_supp_vers(self):
        ext = SrvSupportedVersionsExtension().create((3, 4))

        state = ConnectionState()

        client_hello = ClientHello()
        cln_ext = SupportedVersionsExtension().create([(3, 4)])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        srv_ext_handler_supp_vers(state, ext)

        self.assertEqual(state.version, ext.version)

    def test_srv_ext_handler_supp_vers_with_wrong_version(self):
        ext = SrvSupportedVersionsExtension().create((3, 9))

        state = ConnectionState()

        client_hello = ClientHello()
        cln_ext = SupportedVersionsExtension().create([(3, 4), (3, 5)])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(AssertionError) as exc:
            srv_ext_handler_supp_vers(state, ext)

        self.assertIn("(3, 9)", str(exc.exception))
        self.assertIn("didn't advertise", str(exc.exception))

    def test_srv_ext_handler_supp_groups(self):
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        state = None

        srv_ext_handler_supp_groups(state, ext)

    def test_srv_ext_handler_supp_groups_with_empty_ext(self):
        ext = SupportedGroupsExtension().create([])
        state = None

        with self.assertRaises(AssertionError) as exc:
            srv_ext_handler_supp_groups(state, ext)

        self.assertIn("did not send", str(exc.exception))

    def test_srv_ext_handler_heartbeat_peer_allowed(self):
        ext = HeartbeatExtension().create(
            HeartbeatMode.PEER_ALLOWED_TO_SEND)
        state = None

        srv_ext_handler_heartbeat(state, ext)

    def test_srv_ext_handler_heartbeat_peer_not_allowed(self):
        ext = HeartbeatExtension().create(
            HeartbeatMode.PEER_NOT_ALLOWED_TO_SEND)
        state = None

        srv_ext_handler_heartbeat(state, ext)

    def test_srv_ext_handler_heartbeat_with_empty_ext(self):
        ext = HeartbeatExtension().create(None)
        state = None

        with self.assertRaises(AssertionError) as exc:
            srv_ext_handler_heartbeat(state, ext)

        self.assertIn("Empty mode", str(exc.exception))

    def test_srv_ext_handler_heartbeat_with_invalid_payload(self):
        ext = HeartbeatExtension().create(3)
        state = None

        with self.assertRaises(AssertionError) as exc:
            srv_ext_handler_heartbeat(state, ext)

        self.assertIn("Invalid mode", str(exc.exception))

    def test_gen_srv_ext_handler_psk(self):
        psk_settings = [(b'test', b'bad secret'),
                        (b'example', b'good secret')]
        ext = SrvPreSharedKeyExtension().create(1)

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = psk_ext_gen(psk_settings)
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        handler = gen_srv_ext_handler_psk(psk_settings)

        handler(state, ext)

        self.assertEqual(state.key['PSK secret'], b'good secret')

    def test_gen_srv_ext_handler_psk_with_invalid_srv_selected_id(self):
        psk_settings = [(b'test', b'bad secret'),
                        (b'example', b'good secret')]
        ext = SrvPreSharedKeyExtension().create(2)

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = psk_ext_gen(psk_settings)
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        handler = gen_srv_ext_handler_psk(psk_settings)

        with self.assertRaises(AssertionError) as e:
            handler(state, ext)

        self.assertIn("didn't send", str(e.exception))

    def test_gen_srv_ext_handler_psk_w_different_settings_to_ch_and_sh(self):
        psk_settings = [(b'test', b'bad secret'),
                        (b'example', b'good secret')]
        ext = SrvPreSharedKeyExtension().create(1)

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = psk_ext_gen(psk_settings)
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        psk_settings = [(b'test', b'bad secret')]
        handler = gen_srv_ext_handler_psk(psk_settings)

        with self.assertRaises(ValueError) as e:
            handler(state, ext)

        self.assertIn("missing identity", str(e.exception))

    def test_gen_srv_ext_handler_psk_with_session_ticket(self):
        ext = SrvPreSharedKeyExtension().create(0)

        state = ConnectionState()
        state.key['resumption master secret'] = bytearray(b'\x12'*48)
        state.session_tickets = [
            NewSessionTicket()
            .create(134, 0, bytearray(b'nonce'), bytearray(b'ticket value'),
                    [])]
        client_hello = ClientHello()
        psk_iden = PskIdentity().create(bytearray(b'ticket value'), 3333)
        cln_ext = PreSharedKeyExtension().create([psk_iden], [bytearray(48)])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        handler = gen_srv_ext_handler_psk()

        handler(state, ext)

        self.assertEqual(state.key['PSK secret'],
                bytearray(b"\'Rv\'\xbd\xb6Soh\xe6Y\xfb6w\xda+\xd5\x94$V\xfc"
                          b"\xdd\xac>\xbb\xeb\xa2\xd5\x8d\x00\xe6\x9a\x99{"
                          b"\x00\x98\x9b\xf9%\x1fAFz\x13\xfc\xc4\x11,"))

    def test_gen_srv_ext_handler_record_limit(self):
        ext = RecordSizeLimitExtension().create(2**14)

        state = ConnectionState()
        state.version = (3, 3)

        client_hello = ClientHello()
        cl_ext = RecordSizeLimitExtension().create(2**10)
        client_hello.extensions = [cl_ext]
        state.handshake_messages.append(client_hello)

        handler = gen_srv_ext_handler_record_limit()

        handler(state, ext)

        self.assertEqual(state._peer_record_size_limit, 2**14)
        self.assertEqual(state._our_record_size_limit, 2**10)

    def test_gen_srv_ext_handler_record_limit_with_minimal_value(self):
        ext = RecordSizeLimitExtension().create(64)

        state = ConnectionState()
        state.version = (3, 3)

        client_hello = ClientHello()
        cl_ext = RecordSizeLimitExtension().create(2**10)
        client_hello.extensions = [cl_ext]
        state.handshake_messages.append(client_hello)

        handler = gen_srv_ext_handler_record_limit()

        handler(state, ext)

        self.assertEqual(state._peer_record_size_limit, 64)
        self.assertEqual(state._our_record_size_limit, 2**10)

    def test_gen_srv_ext_handler_record_limit_too_large_value(self):
        # in tls 1.2 maximum size the server can select is 2**14
        ext = RecordSizeLimitExtension().create(2**14+1)

        state = ConnectionState()
        state.version = (3, 3)

        client_hello = ClientHello()
        cl_ext = RecordSizeLimitExtension().create(2**10)
        client_hello.extensions = [cl_ext]
        state.handshake_messages.append(client_hello)

        handler = gen_srv_ext_handler_record_limit()

        with self.assertRaises(AssertionError):
            handler(state, ext)

    def test_gen_srv_ext_handler_record_limit_in_TLS_1_3(self):
        ext = RecordSizeLimitExtension().create(2**14+1)

        state = ConnectionState()
        state.version = (3, 4)

        client_hello = ClientHello()
        cl_ext = RecordSizeLimitExtension().create(2**10+1)
        client_hello.extensions = [cl_ext]
        state.handshake_messages.append(client_hello)

        state.msg_sock = mock.MagicMock()

        handler = gen_srv_ext_handler_record_limit()

        handler(state, ext)

        self.assertEqual(state.msg_sock.recv_record_limit, 2**10)
        self.assertEqual(state.msg_sock.send_record_limit, 2**14)
        self.assertEqual(state.msg_sock.recordSize, 2**14)

    def test_gen_srv_ext_handler_record_limit_with_too_large_size_in_TLS_1_3(self):
        # in TLS 1.3 the maximum size supported is 2**14 + 1, check if we
        # reject sizes larger than that
        ext = RecordSizeLimitExtension().create(2**14+2)

        state = ConnectionState()
        state.version = (3, 4)

        client_hello = ClientHello()
        cl_ext = RecordSizeLimitExtension().create(2**10+1)
        client_hello.extensions = [cl_ext]
        state.handshake_messages.append(client_hello)

        state.msg_sock = mock.MagicMock()

        handler = gen_srv_ext_handler_record_limit()

        with self.assertRaises(AssertionError):
            handler(state, ext)

    def test_gen_srv_ext_handler_record_limit_with_unexpected_size(self):
        ext = RecordSizeLimitExtension().create(2**14+1)

        state = ConnectionState()
        state.version = (3, 4)

        client_hello = ClientHello()
        cl_ext = RecordSizeLimitExtension().create(2**10)
        client_hello.extensions = [cl_ext]
        state.handshake_messages.append(client_hello)

        state.msg_sock = mock.MagicMock()

        handler = gen_srv_ext_handler_record_limit(2**14)

        with self.assertRaises(AssertionError):
            handler(state, ext)

    def test_clnt_ext_handler_sig_algs(self):
        ext = SignatureAlgorithmsExtension().create(
            [SignatureScheme.rsa_pss_rsae_sha256])

        clnt_ext_handler_sig_algs(None, ext)

    def test_clnt_ext_handler_sig_algs_with_empty_list(self):
        ext = SignatureAlgorithmsExtension().create([])

        with self.assertRaises(AssertionError):
            clnt_ext_handler_sig_algs(None, ext)

    def test_clnt_ext_handler_sig_algs_with_no_payload(self):
        ext = SignatureAlgorithmsExtension().create(None)

        with self.assertRaises(AssertionError):
            clnt_ext_handler_sig_algs(None, ext)


class TestHRRExtensionProcessors(unittest.TestCase):
    def test_hrr_ext_handler_key_share(self):
        ext = HRRKeyShareExtension().create(GroupName.secp256r1)
        state = ConnectionState()

        ch_ext = SupportedGroupsExtension().create([GroupName.secp256r1,
                                                    GroupName.secp384r1])
        ch = ClientHello()
        ch.extensions = [ch_ext]

        state.handshake_messages.append(ch)

        hrr_ext_handler_key_share(state, ext)

    def test_hrr_ext_handler_with_wrong_group(self):
        ext = HRRKeyShareExtension().create(GroupName.x25519)
        state = ConnectionState()

        ch_ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        ch = ClientHello()
        ch.extensions = [ch_ext]

        state.handshake_messages.append(ch)

        with self.assertRaises(AssertionError) as e:
            hrr_ext_handler_key_share(state, ext)

        self.assertIn("didn't advertise", str(e.exception))

    def test_hrr_ext_handler_cookie(self):
        ext = CookieExtension().create(b'some payload')
        state = None

        hrr_ext_handler_cookie(state, ext)

    def test_hrr_ext_handler_cookie_with_empty_payload(self):
        ext = CookieExtension()
        state = None

        with self.assertRaises(AssertionError) as e:
            hrr_ext_handler_cookie(state, ext)

        self.assertIn("empty cookie", str(e.exception))


class TestExpectServerHello(unittest.TestCase):
    def test___init__(self):
        exp = ExpectServerHello()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectServerHello()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.server_hello]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectServerHello()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.server_hello]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectServerHello()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.client_hello]))

        self.assertFalse(exp.is_match(msg))

    def test_str_with_no_description(self):
        exp = ExpectServerHello()

        self.assertEqual("ExpectServerHello()", str(exp))

    def test_str_with_description(self):
        exp = ExpectServerHello(description="SH message")

        self.assertEqual("ExpectServerHello(description=\'SH message\')",
                         str(exp))

    def test_process_with_extensions(self):
        extension_process = mock.MagicMock()
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            extension_process})

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        extension_process.assert_called_once_with(state, ext)

    def test_process_with_automatic_extension_handling(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None})

        state = ConnectionState()
        client_hello = ClientHello()
        renego = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, renego]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_missing_extensions(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None})

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=None)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_missing_specified_extension(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None,
                                            ExtensionType.alpn: None})

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        ext = ALPNExtension().create([b'h2'])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_extra_extensions(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None})

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        ext = ALPNExtension().create([b'h2'])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = [RenegotiationInfoExtension().create(bytearray()),
                ALPNExtension().create([b'h2'])]

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_no_autohandler(self):
        exp = ExpectServerHello(extensions={1: None})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        ext = TLSExtension(extType=1).create(bytearray())
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = TLSExtension(extType=1).create(bytearray())

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_non_matching_example(self):
        exp = ExpectServerHello(extensions={1: TLSExtension(extType=1)})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        ext = TLSExtension(extType=1).create(bytearray())
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = TLSExtension(extType=1).create(bytearray(1))

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_incorrect_version(self):
        extension_process = mock.MagicMock()
        exp = ExpectServerHello(version=(3, 3))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 2),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_incorrect_cipher(self):
        exp = ExpectServerHello(cipher=5)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_unexpected_cipher(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=5)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_udefined_cipher(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=0xfff0)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_no_matching_extension(self):
        exps = {ExtensionType.renegotiation_info: None,
                ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])
               }
        exp = ExpectServerHello(extensions=exps)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create(None))
        exts.append(ALPNExtension().create([bytearray(b'http/1.2')]))
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_matching_extension(self):
        exps = {ExtensionType.renegotiation_info: None,
                ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])
               }
        exp = ExpectServerHello(extensions=exps)

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        ext = ALPNExtension().create([bytearray(b'http/1.1')])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create(bytearray()))
        exts.append(ALPNExtension().create([bytearray(b'http/1.1')]))
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)
        self.assertIsInstance(state.handshake_messages[1], ServerHello)

    def test_process_with_bad_extension_handler(self):
        exps = {ExtensionType.renegotiation_info: None,
                ExtensionType.alpn: 'BAD_EXTENSION'
               }
        exp = ExpectServerHello(extensions=exps)

        state = ConnectionState()
        client_hello = ClientHello()
        renego = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, renego]
        ext = ALPNExtension().create([bytearray(b'http/1.1')])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create(bytearray()))
        exts.append(ALPNExtension().create([bytearray(b'http/1.1')]))
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(ValueError):
            exp.process(state, msg)

    def test_process_with_unexpected_extensions(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                           None})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create(None))
        exts.append(SNIExtension().create())
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_resumption(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()
        state.session_id = bytearray(b'\xaa\xaa\xaa')
        state.cipher = 4

        self.assertFalse(state.resuming)

        msg = ServerHello()
        msg.create(version=(3, 3),
                   random=bytearray(32),
                   session_id=bytearray(b'\xaa\xaa\xaa'),
                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        self.assertTrue(state.resuming)

    def test_process_with_mandatory_resumption(self):
        exp = ExpectServerHello(resume=True)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()
        state.session_id = bytearray(b'\xaa\xaa\xaa')
        state.cipher = 4

        self.assertFalse(state.resuming)

        msg = ServerHello()
        msg.create(version=(3, 3),
                   random=bytearray(32),
                   session_id=bytearray(b'\xaa\xaa\xaa'),
                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        self.assertTrue(state.resuming)


    def test_process_with_mandatory_resumption_but_wrong_id(self):
        exp = ExpectServerHello(resume=True)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.session_id = bytearray(b'\xaa\xaa\xaa')
        state.cipher = 4

        self.assertFalse(state.resuming)

        msg = ServerHello()
        msg.create(version=(3, 3),
                   random=bytearray(32),
                   session_id=bytearray(b'\xbb\xbb\xbb'),
                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_extended_master_secret(self):
        exp = ExpectServerHello(
                extensions={ExtensionType.extended_master_secret:None})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        ext = TLSExtension(extType=ExtensionType.extended_master_secret)
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()
        self.assertFalse(state.extended_master_secret)

        ext = TLSExtension(extType=ExtensionType.extended_master_secret)
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        self.assertTrue(state.extended_master_secret)

    def test_process_with_tls13_settings(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = []
        client_hello.cipher_suites = [CipherSuite.TLS_AES_128_GCM_SHA256]
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        client_hello.extensions.append(ext)
        c_ks = key_share_gen(GroupName.secp256r1)
        ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions.append(ext)
        ext = SupportedVersionsExtension().create([(3, 3), (3, 4)])
        client_hello.extensions.append(ext)
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        s_ext = []
        s_ks = key_share_gen(GroupName.secp256r1)
        ext = ServerKeyShareExtension().create(s_ks)
        s_ext.append(ext)
        ext = SrvSupportedVersionsExtension().create((3, 4))
        s_ext.append(ext)
        server_hello = ServerHello().create(version=(3, 3),
                                            random=bytearray(32),
                                            session_id=bytearray(0),
                                            cipher_suite=
                                            CipherSuite.TLS_AES_128_GCM_SHA256,
                                            extensions=s_ext)

        exp.process(state, server_hello)

        state.msg_sock.calcTLS1_3PendingState.assert_called_once_with(
            state.cipher,
            state.key['client handshake traffic secret'],
            state.key['server handshake traffic secret'],
            None)
        state.msg_sock.changeReadState.assert_called_once_with()
        self.assertTrue(state.key['handshake secret'])
        self.assertTrue(state.key['client handshake traffic secret'])
        self.assertTrue(state.key['server handshake traffic secret'])
        self.assertEqual(state.version, (3, 4))
        self.assertTrue(state.msg_sock.tls13record)

    def test_process_with_tls13_unallowed_extension(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = []
        client_hello.cipher_suites = [CipherSuite.TLS_AES_128_GCM_SHA256]
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        client_hello.extensions.append(ext)
        c_ks = key_share_gen(GroupName.secp256r1)
        ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions.append(ext)
        ext = SupportedVersionsExtension().create([(3, 3), (3, 4)])
        client_hello.extensions.append(ext)
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        s_ext = []
        s_ks = key_share_gen(GroupName.secp256r1)
        ext = ServerKeyShareExtension().create(s_ks)
        s_ext.append(ext)
        ext = SrvSupportedVersionsExtension().create((3, 4))
        s_ext.append(ext)
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        s_ext.append(ext)
        server_hello = ServerHello().create(version=(3, 3),
                                            random=bytearray(32),
                                            session_id=bytearray(0),
                                            cipher_suite=
                                            CipherSuite.TLS_AES_128_GCM_SHA256,
                                            extensions=s_ext)

        with self.assertRaises(AssertionError):
            exp.process(state, server_hello)

    def test_process_with_tls_1_3_in_legacy_version(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()
        ext = []
        ext.append(SrvSupportedVersionsExtension().create((3, 4)))

        msg = ServerHello().create(version=(3, 4),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=ext)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(ValueError) as e:
            exp.process(state, msg)

        self.assertIn("invalid version in legacy_version", str(e.exception))

    def test_process_with_tls_1_3_no_downgrade_protection(self):
        # use default extension handlers
        exp = ExpectServerHello(version=(3, 3), server_max_protocol=(3, 4))

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = []
        client_hello.cipher_suites = [CipherSuite.TLS_AES_128_GCM_SHA256]
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        client_hello.extensions.append(ext)
        c_ks = key_share_gen(GroupName.secp256r1)
        ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions.append(ext)
        ext = SupportedVersionsExtension().create([(3, 3), (3, 4)])
        client_hello.extensions.append(ext)
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()
        ext = []
        ext.append(SrvSupportedVersionsExtension().create((3, 4)))

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=
                                   CipherSuite.TLS_AES_128_GCM_SHA256,
                                   extensions=ext)

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_default_settings_and_tls_1_3_reply_with_1_2_downgrade_sentinel(self):
        # check that if the server reply is obviously bogus (like when TLS 1.3
        # ServerHello indicates that we are downgrading to TLS 1.2), the
        # ServerHello is rejected
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = []
        client_hello.cipher_suites = [CipherSuite.TLS_AES_128_GCM_SHA256]
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        client_hello.extensions.append(ext)
        c_ks = key_share_gen(GroupName.secp256r1)
        ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions.append(ext)
        ext = SupportedVersionsExtension().create([(3, 3), (3, 4)])
        client_hello.extensions.append(ext)
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        rndbuf=bytearray(32)
        rndbuf[-8:] = TLS_1_2_DOWNGRADE_SENTINEL
        ext = []
        ext.append(SrvSupportedVersionsExtension().create((3, 4)))

        msg = ServerHello().create(version=(3, 3),
                                   random=rndbuf,
                                   session_id=bytearray(0),
                                   cipher_suite=
                                   CipherSuite.TLS_AES_128_GCM_SHA256,
                                   extensions=ext)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("downgrade protection sentinel but shouldn't",
                      str(e.exception))

    def test_process_with_default_settings_and_tls_1_3_reply_with_1_1_downgrade_sentinel(self):
        # check that if the server reply is obviously bogus (like when TLS 1.3
        # ServerHello indicates that we are downgrading to TLS 1.1), the
        # ServerHello is rejected
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = []
        client_hello.cipher_suites = [CipherSuite.TLS_AES_128_GCM_SHA256]
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        client_hello.extensions.append(ext)
        c_ks = key_share_gen(GroupName.secp256r1)
        ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions.append(ext)
        ext = SupportedVersionsExtension().create([(3, 3), (3, 4)])
        client_hello.extensions.append(ext)
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        rndbuf=bytearray(32)
        rndbuf[-8:] = TLS_1_1_DOWNGRADE_SENTINEL
        ext = []
        ext.append(SrvSupportedVersionsExtension().create((3, 4)))

        msg = ServerHello().create(version=(3, 3),
                                   random=rndbuf,
                                   session_id=bytearray(0),
                                   cipher_suite=
                                   CipherSuite.TLS_AES_128_GCM_SHA256,
                                   extensions=ext)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("downgrade protection sentinel but shouldn't",
                      str(e.exception))

    def test_process_with_tls_1_2_downgrade_protection(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None},
                                version=(3, 3), server_max_protocol=(3, 4))

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        rndbuf=bytearray(32)
        rndbuf[-8:] = TLS_1_2_DOWNGRADE_SENTINEL

        msg = ServerHello().create(version=(3, 3),
                                   random=rndbuf,
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_tls_1_2_missing_downgrade_protection(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None},
                                version=(3, 3), server_max_protocol=(3, 4))

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("failed to set downgrade protection sentinel",
                      str(e.exception))

    def test_process_with_tls_1_2_no_downgrade_protection(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None},
                                version=(3, 3), server_max_protocol=(3, 3))

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_tls_1_2_wrong_downgrade_protection(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None},
                                version=(3, 3), server_max_protocol=(3, 3))

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        rndbuf=bytearray(32)
        rndbuf[-8:] = TLS_1_2_DOWNGRADE_SENTINEL

        msg = ServerHello().create(version=(3, 3),
                                   random=rndbuf,
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("downgrade protection sentinel but shouldn't",
                      str(e.exception))

    def test_process_with_tls_1_1_downgrade_protection(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None},
                                server_max_protocol=(3, 4))

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        rndbuf=bytearray(32)
        rndbuf[-8:] = TLS_1_1_DOWNGRADE_SENTINEL

        msg = ServerHello().create(version=(3, 2),
                                   random=rndbuf,
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_tls_1_2_server_downgrade_protection(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None},
                                server_max_protocol=(3, 3))

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        rndbuf=bytearray(32)
        rndbuf[-8:] = TLS_1_1_DOWNGRADE_SENTINEL

        msg = ServerHello().create(version=(3, 2),
                                   random=rndbuf,
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_tls_1_1_no_downgrade_protection(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None},
                                server_max_protocol=(3, 2))

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        msg = ServerHello().create(version=(3, 2),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_tls_1_1_wrong_downgrade_protection(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None},
                                version=(3, 1), server_max_protocol=(3, 2))

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        rndbuf=bytearray(32)
        rndbuf[-8:] = TLS_1_1_DOWNGRADE_SENTINEL

        msg = ServerHello().create(version=(3, 1),
                                   random=rndbuf,
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("downgrade protection sentinel but shouldn't",
                      str(e.exception))


class TestExpectServerHelloWithHelloRetryRequest(unittest.TestCase):
    def setUp(self):
        self.exp = ExpectServerHello()

        state = ConnectionState()
        self.state = state
        state.msg_sock = mock.MagicMock()
        state.key['DH shared secret'] = bytearray()

        exts = [SupportedVersionsExtension().create([(3, 5), (3, 4), (3, 3)])]
        ch = ClientHello()
        ch.create((3, 3), bytearray(32), b'', [4, 5], extensions=exts)
        self.ch = ch
        state.handshake_messages.append(ch)

        exts = [SrvSupportedVersionsExtension().create((3, 4)),
                HRRKeyShareExtension().create(2)]
        hrr = ServerHello()
        hrr.create((3, 3), TLS_1_3_HRR, b'', 0x0004, extensions=exts)
        self.hrr = hrr
        state.handshake_messages.append(hrr)

        exts = [SrvSupportedVersionsExtension().create((3, 4))]
        sh = ServerHello()
        sh.create((3, 3), bytearray(32), b'', 0x0004, extensions=exts)
        self.sh = sh

    def test_with_hello_retry_request(self):
        self.exp.process(self.state, self.sh)

    def test_with_wrong_hrr_random(self):
        self.hrr.random = bytearray([12]*32)

        with self.assertRaises(SyntaxError):
            self.exp.process(self.state, self.hrr)

    def test_with_wrong_cipher_suite(self):
        self.sh.cipher_suite = 5

        with self.assertRaises(AssertionError) as e:
            self.exp.process(self.state, self.sh)

        self.assertIn("different cipher suite", str(e.exception))

    def test_with_wrong_version(self):
        self.sh.extensions[0].version = (3, 5)

        with self.assertRaises(AssertionError) as e:
            self.exp.process(self.state, self.sh)

        self.assertIn("different protocol version", str(e.exception))


class TestExpectHelloRetryRequest(unittest.TestCase):
    def test___init__(self):
        exp = ExpectHelloRetryRequest()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectHelloRetryRequest()

        # the difference between HRR and Server Hello is the random value,
        # not the content type or handshake type
        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.server_hello]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatched_handshake_type(self):
        exp = ExpectHelloRetryRequest()

        msg = Message(ContentType.handshake,
                      # this is legacy value, used in early drafts of TLS 1.3
                      bytearray([HandshakeType.hello_retry_request]))

        self.assertFalse(exp.is_match(msg))

    def test_process_with_extensions(self):
        state = ConnectionState()

        ch = ClientHello()
        ch.cipher_suites = [4]
        ch.extensions = [SupportedVersionsExtension().create([(3, 4)])]

        state.handshake_messages.append(ch)
        state.msg_sock = mock.MagicMock()

        exts = [CookieExtension().create(b'some payload'),
                SrvSupportedVersionsExtension().create((3, 4))]
        hrr = ServerHello()
        hrr.create((3, 3), TLS_1_3_HRR, b'', 0x0004, extensions=exts)

        exp = ExpectHelloRetryRequest()

        exp.process(state, hrr)

        self.maxDiff = None
        self.assertEqual(
            b'\x99\xb9\xa5O\x9d\x819\xfe\xd6\xf5\x8d\xce'
            b' bW\x1fO0[7\x04\x15\x89\xaeS\xcd8*3C\x9d\x01',
            state.handshake_hashes.digest('sha256'))

    def test_process_with_unexpected_extensions(self):
        state = ConnectionState()

        ch = ClientHello()
        ch.cipher_suites = [4]
        ch.extensions = [TLSExtension(extType=0x13ff)]
        state.handshake_messages.append(ch)
        state.msg_sock = mock.MagicMock()

        exts = [TLSExtension(extType=0x13ff)]
        hrr = ServerHello()
        hrr.create((3, 3), TLS_1_3_HRR, b'', 0x0004, extensions=exts)

        exp = ExpectHelloRetryRequest()

        with self.assertRaises(AssertionError) as e:
            exp.process(state, hrr)

        self.assertIn("No autohandler for 5119", str(e.exception))

    def test_process_with_tls13_unallowed_extension(self):
        exp = ExpectHelloRetryRequest()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = []
        client_hello.cipher_suites = [CipherSuite.TLS_AES_128_GCM_SHA256]
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        client_hello.extensions.append(ext)
        c_ks = key_share_gen(GroupName.secp256r1)
        ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions.append(ext)
        ext = SupportedVersionsExtension().create([(3, 3), (3, 4)])
        client_hello.extensions.append(ext)
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        s_ext = []
        ext = HRRKeyShareExtension().create(GroupName.secp256r1)
        s_ext.append(ext)
        ext = SrvSupportedVersionsExtension().create((3, 4))
        s_ext.append(ext)
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        s_ext.append(ext)
        hrr = ServerHello().create(version=(3, 3),
                                   random=TLS_1_3_HRR,
                                   session_id=bytearray(0),
                                   cipher_suite=
                                   CipherSuite.TLS_AES_128_GCM_SHA256,
                                   extensions=s_ext)

        with self.assertRaises(AssertionError):
            exp.process(state, hrr)


class TestExpectServerHello2(unittest.TestCase):
    def test___init__(self):
        exp = ExpectServerHello2()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectServerHello2()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        msg = ServerHello2()
        msg.session_id_hit = 1
        msg.session_id = bytearray(b'\x12')
        msg.certificate = X509().parse(srv_raw_certificate).writeBytes()

        ret = exp.process(state, msg)

        self.assertEqual(state.session_id, msg.session_id)

    def test_process_with_version(self):
        exp = ExpectServerHello2((2, 0))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        msg = ServerHello2()
        msg.session_id_hit = 1
        msg.session_id = bytearray(b'\x12')
        msg.server_version = (2, 0)
        msg.certificate = X509().parse(srv_raw_certificate).writeBytes()

        ret = exp.process(state, msg)

        self.assertEqual(state.session_id, msg.session_id)

class TestExpectCertificate(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCertificate()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectCertificate()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectCertificate()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.certificate]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectCertificate()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.client_hello]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        exp = ExpectCertificate()

        msg = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        exp.process(state, msg)


class TestExpectCertificateVerify(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCertificate()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectCertificateVerify()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate_verify]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectCertificateVerify()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.certificate_verify]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectCertificateVerify()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate]))

        self.assertFalse(exp.is_match(msg))

    def test_process_with_non_matching_pss_signature(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        mock_cert = mock.Mock()
        mock_cert.key_type = "rsa"
        state.get_server_public_key = mock.MagicMock(return_value=mock_cert)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        cert_verify = CertificateVerify((3, 4)).create(
            bytearray(b'x'*256), SignatureScheme.rsa_pss_pss_sha256)

        with self.assertRaises(AssertionError):
            exp.process(state, cert_verify)

    def test_process_with_non_matching_rsae_signature(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        mock_cert = mock.Mock()
        mock_cert.key_type = "rsa-pss"
        state.get_server_public_key = mock.MagicMock(return_value=mock_cert)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        cert_verify = CertificateVerify((3, 4)).create(
            bytearray(b'x'*256), SignatureScheme.rsa_pss_rsae_sha256)

        with self.assertRaises(AssertionError):
            exp.process(state, cert_verify)

    def test_process(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_rsae_sha384])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      "PSS",
                                      "sha384",
                                      48)
        scheme = SignatureScheme.rsa_pss_rsae_sha384
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    def test_process_with_expected_rsa_pss_sig_alg(self):
        exp = ExpectCertificateVerify(
            sig_alg=SignatureScheme.rsa_pss_pss_sha256)

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_pss_certificate)]))

        private_key = parsePEMKey(srv_raw_pss_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_pss_sha256])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      "PSS",
                                      "sha256",
                                      32)
        scheme = SignatureScheme.rsa_pss_pss_sha256
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    def test_process_with_ecdsa_sig_alg(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_ecdsa_certificate)]))

        private_key = parsePEMKey(srv_raw_ecdsa_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.ecdsa_secp256r1_sha256])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      "ecdsa",
                                      "sha256",
                                      32)
        scheme = SignatureScheme.ecdsa_secp256r1_sha256
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    def test_process_with_ecdsa_and_mismatches_algorithm(self):
        # in TLS 1.3 the curves are bound to hashes, see if that mismatch
        # is detected
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_ecdsa_certificate)]))

        private_key = parsePEMKey(srv_raw_ecdsa_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.ecdsa_secp256r1_sha256,
                    SignatureScheme.ecdsa_secp384r1_sha384])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha384')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.sign(secureHash(signature_context, "sha384")[:32],
                               "ecdsa",
                               "sha384")
        scheme = SignatureScheme.ecdsa_secp384r1_sha384
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        with self.assertRaises(AssertionError) as exc:
            exp.process(state, cer_verify)

        self.assertIn("Invalid signature type for NIST256p key, received: "
                      "ecdsa_secp384r1_sha384", str(exc.exception))

    def test_process_with_ed25519_sig_alg(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_ed25519_certificate)]))

        private_key = parsePEMKey(srv_raw_ed25519_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.ed25519])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      None,
                                      None,
                                      None)
        scheme = SignatureScheme.ed25519
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    def test_process_with_ed448_sig_alg(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_ed448_certificate)]))

        private_key = parsePEMKey(srv_raw_ed448_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.ed448])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      None,
                                      None,
                                      None)
        scheme = SignatureScheme.ed448
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    def test_process_eddsa_with_mismatched_signature(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_ed448_certificate)]))

        private_key = parsePEMKey(srv_raw_ed25519_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.ed25519])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      None,
                                      None,
                                      None)
        scheme = SignatureScheme.ed25519
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        with self.assertRaises(AssertionError) as e:
            exp.process(state, cer_verify)

        self.assertIn("Mismatched signature (ed25519) for used key (Ed448)",
                      str(e.exception))

    def test_process_with_expected_sig_alg(self):
        exp = ExpectCertificateVerify(
            sig_alg=SignatureScheme.rsa_pss_rsae_sha384)

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_rsae_sha384])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      "PSS",
                                      "sha384",
                                      48)
        scheme = SignatureScheme.rsa_pss_rsae_sha384
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    def test_process_with_invalid_signature(self):
        exp = ExpectCertificateVerify(
            sig_alg=SignatureScheme.rsa_pss_rsae_sha384)

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_rsae_sha384])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      "PSS",
                                      "sha384",
                                      48)
        sig[-1] ^= 1
        scheme = SignatureScheme.rsa_pss_rsae_sha384
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        with self.assertRaises(AssertionError) as exc:
            exp.process(state, cer_verify)

        self.assertIn("verification failed", str(exc.exception))


class TestExpectCertificateStatus(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCertificateStatus()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectCertificateStatus()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate_status]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectCertificateStatus()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.certificate_status]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        exp = ExpectCertificateStatus()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        msg = CertificateStatus().create(CertificateStatusType.ocsp,
                                         bytearray(10))

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)


class TestExpectServerHelloDone(unittest.TestCase):
    def test___init__(self):
        exp = ExpectServerHelloDone()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectServerHelloDone()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.server_hello_done]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectServerHelloDone()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.server_hello_done]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectServerHelloDone()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.client_hello]))

        self.assertFalse(exp.is_match(msg))

class TestExpectChangeCipherSpec(unittest.TestCase):
    def test___init__(self):
        exp = ExpectChangeCipherSpec()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectChangeCipherSpec()

        msg = Message(ContentType.change_cipher_spec,
                      bytearray([0]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectChangeCipherSpec()

        msg = Message(ContentType.application_data,
                      bytearray([0]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_arbitrary_data(self):
        exp = ExpectChangeCipherSpec()

        msg = Message(ContentType.change_cipher_spec,
                      bytearray([243]))

        self.assertTrue(exp.is_match(msg))

    def test_process(self):
        exp = ExpectChangeCipherSpec()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        msg = Message(ContentType.change_cipher_spec, bytearray([1]))

        exp.process(state, msg)

        state.msg_sock.calcPendingStates.assert_not_called()
        state.msg_sock.changeReadState.assert_called_once_with()

    def test_process_with_resumption(self):
        exp = ExpectChangeCipherSpec()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.resuming = True

        state.cipher = mock.Mock(name="cipher")
        state.key['master_secret'] = mock.Mock(name="master_secret")
        state.client_random = mock.Mock(name="client_random")
        state.server_random = mock.Mock(name="server_random")

        msg = Message(ContentType.change_cipher_spec, bytearray([1]))

        exp.process(state, msg)

        state.msg_sock.calcPendingStates.assert_called_once_with(
                state.cipher,
                state.key['master_secret'],
                state.client_random,
                state.server_random,
                None)
        state.msg_sock.changeReadState.assert_called_once_with()

class TestExpectFinished(unittest.TestCase):
    def test___init__(self):
        exp = ExpectFinished()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test___init___with_ssl2(self):
        exp = ExpectFinished(version=(2, 0))

        self.assertIsNotNone(exp)
        self.assertTrue(exp.is_expect())
        self.assertEqual(exp.version, (2, 0))

    def test_is_match(self):
        exp = ExpectFinished()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.finished]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectFinished()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.finished]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectFinished()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.client_hello]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        exp = ExpectFinished()
        # this probably should use mock objects to check if calcFinished
        # is called with them
        state = ConnectionState()
        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.finished, 0, 0, 12]) + 
                      bytearray(b"\xa3;\x9c\xc9\'E\xbc\xf6\xc7\x96\xaf\x7f"))

        exp.process(state, msg)

    def test_process_with_tls13(self):
        exp = ExpectFinished()
        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)
        state.key['handshake secret'] = bytearray(32)
        state.key['server handshake traffic secret'] = bytearray(32)
        state.msg_sock = mock.MagicMock()
        msg = Finished((3, 4), 32).create(
            bytearray(b'\x14\xa5e\xa67\xfe\xa3(\xd3\xac\x95\xecX\xb7\xc0\xd4'
                      b'u\xef\xb3V\x8f\xc7[\xcdD\xc8\xa4\x86\xcf\xd3\xc9\x0c'))

        exp.process(state, msg)

        state.msg_sock.changeWriteState.assert_called_once_with()

    def test_process_with_ssl2(self):
        exp = ExpectFinished((2, 0))
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        msg = ServerFinished().create(bytearray(range(12)))

        exp.process(state, msg)


class TestExpectEncryptedExtensions(unittest.TestCase):
    def test___init__(self):
        exp = ExpectEncryptedExtensions()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectEncryptedExtensions()

        ee = EncryptedExtensions().create([])

        state = ConnectionState()

        exp.process(state, ee)

        self.assertIn(ee, state.handshake_messages)

    def test_process_with_extensions(self):
        groups = [GroupName.secp256r1]
        sup_group_ext = SupportedGroupsExtension().create(groups)
        ext = {ExtensionType.supported_groups: sup_group_ext}

        exp = ExpectEncryptedExtensions(extensions=ext)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([sup_group_ext])

        exp.process(state, msg)

        self.assertIn(msg, state.handshake_messages)

    def test_process_with_unsupported_extensions(self):
        key_shares = [key_share_gen(GroupName.secp256r1)]
        key_share_ext = ClientKeyShareExtension().create(key_shares)

        exp = ExpectEncryptedExtensions()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [key_share_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([key_share_ext])

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_expect_any_supported_extensions(self):
        groups = [GroupName.secp256r1]
        sup_group_ext = SupportedGroupsExtension().create(groups)

        exp = ExpectEncryptedExtensions()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([sup_group_ext])

        exp.process(state, msg)

        self.assertIn(msg, state.handshake_messages)

    def test_process_with_expected_extension_but_empty_message(self):
        sup_group_ext = SupportedGroupsExtension().create(
            [GroupName.secp256r1])
        ext = {ExtensionType.supported_groups: sup_group_ext}

        exp = ExpectEncryptedExtensions(extensions=ext)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([])

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_missing_specified_extension(self):
        sup_group_ext = SupportedGroupsExtension().create(
            [GroupName.secp256r1])
        sni_ext = SNIExtension().create()
        ext = {ExtensionType.supported_groups: sup_group_ext,
               ExtensionType.server_name: sni_ext}

        exp = ExpectEncryptedExtensions(extensions=ext)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext, sni_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([sup_group_ext])

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_extra_extensions(self):
        sup_group_ext = SupportedGroupsExtension().create(
            [GroupName.secp256r1])
        sni_ext = SNIExtension().create()
        ext = {ExtensionType.supported_groups: sup_group_ext}

        exp = ExpectEncryptedExtensions(extensions=ext)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([sup_group_ext, sni_ext])

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_no_autohandler(self):
        exp = ExpectEncryptedExtensions(extensions={1: None})

        state = ConnectionState()
        client_hello = ClientHello()
        ext = TLSExtension(extType=1).create(bytearray())
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([ext])

        with self.assertRaises(ValueError):
            exp.process(state, msg)

    def test_process_with_non_matching_ext_payload(self):
        sup_group_ext = SupportedGroupsExtension().create(
            [GroupName.secp256r1])
        ext = {ExtensionType.supported_groups: sup_group_ext}

        exp = ExpectEncryptedExtensions(extensions=ext)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([SupportedGroupsExtension().create(
            [GroupName.secp521r1])])

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_bad_extension_handler(self):
        sup_group_ext = SupportedGroupsExtension().create(
            [GroupName.secp256r1])
        ext = {ExtensionType.supported_groups: sup_group_ext,
               ExtensionType.alpn: 'BAD_EXTENSION'}

        exp = ExpectEncryptedExtensions(extensions=ext)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext,
            ALPNExtension().create([bytearray(b'http/1.1')])]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([sup_group_ext,
            ALPNExtension().create([bytearray(b'http/1.1')])])

        with self.assertRaises(ValueError):
            exp.process(state, msg)

    def test_process_with_automatic_extension_handling(self):
        sup_group_ext = SupportedGroupsExtension().create(
            [GroupName.secp256r1])
        alpn_ext = ALPNExtension().create([bytearray(b'http/1.1')])

        ext = {ExtensionType.supported_groups: None,
               ExtensionType.alpn: None}
        exp = ExpectEncryptedExtensions(extensions=ext)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext, alpn_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([sup_group_ext, alpn_ext])

        exp.process(state, msg)

    def test_process_with_extension_missing_from_client_hello(self):
        sup_group_ext = SupportedGroupsExtension().create(
            [GroupName.secp256r1])
        sni_ext = SNIExtension().create()

        exp = ExpectEncryptedExtensions()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sni_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([sup_group_ext])

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_no_expected_extensions(self):
        sup_group_ext = SupportedGroupsExtension().create(
            [GroupName.secp256r1])
        alpn_ext = ALPNExtension().create([bytearray(b'http/1.1')])

        exp = ExpectEncryptedExtensions(extensions={})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = [sup_group_ext, alpn_ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = EncryptedExtensions().create([sup_group_ext, alpn_ext])

        with self.assertRaises(AssertionError):
            exp.process(state, msg)


class TestExpectNewSessionTicket(unittest.TestCase):
    def test___init__(self):
        exp = ExpectNewSessionTicket()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectNewSessionTicket()

        nst = NewSessionTicket().create(12, 44, b'abba', b'I am a ticket', [])

        state = ConnectionState()

        exp.process(state, nst)

        self.assertIn(nst, state.session_tickets)
        self.assertIsNotNone(state.session_tickets[0].time)

    def test___repr__(self):
        exp = ExpectNewSessionTicket()

        self.assertEqual("ExpectNewSessionTicket()", repr(exp))

    def test___repr___with_description(self):
        exp = ExpectNewSessionTicket(description="some string")

        self.assertEqual("ExpectNewSessionTicket(description='some string')",
                         repr(exp))


class TestExpectVerify(unittest.TestCase):
    def test___init__(self):
        exp = ExpectVerify()
        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectVerify()
        msg = Message(ContentType.handshake,
                      bytearray([SSL2HandshakeType.server_verify]))

        exp.process(None, msg)

class TestExpectAlert(unittest.TestCase):
    def test___init__(self):
        exp = ExpectAlert()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test___init___with_values(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.unknown_psk_identity)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectAlert()

        msg = Message(ContentType.alert,
                      bytearray(2))

        self.assertTrue(exp.is_match(msg))

    def test_process(self):
        exp = ExpectAlert()

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(2))

        exp.process(state, msg)

    def test_is_match_with_values(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.unknown_psk_identity)

        msg = Message(ContentType.alert,
                      bytearray(2))

        self.assertTrue(exp.is_match(msg))

    def test_process_with_values(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.unknown_psk_identity)

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\x01\x73'))

        exp.process(state, msg)

    def test_process_with_values_and_not_matching_level(self):
        exp = ExpectAlert(AlertLevel.fatal,
                          AlertDescription.unknown_psk_identity)

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\x01\x73'))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_multiple_values_one_matching_description(self):
        exp = ExpectAlert(AlertLevel.fatal,
                          [AlertDescription.record_overflow,
                           AlertDescription.decompression_failure])

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\x02\x16'))

        # does NOT raise exception
        exp.process(state, msg)

    def test_process_with_values_and_not_matching_description(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.bad_record_mac)

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\x01\x73'))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_values_not_matching_anything(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.bad_record_mac)
        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\xff\xff'))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertEqual(str(e.exception),
                         "Alert level 255 != 1, "
                         "Expected alert description "
                         "\"bad_record_mac\" does not match received "
                         "\"255\"")

    def test_process_with_multiple_values_not_matching_anything(self):
        exp = ExpectAlert(AlertLevel.warning,
                          [AlertDescription.bad_record_mac,
                           AlertDescription.illegal_parameter])
        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\xff\xff'))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertEqual(str(e.exception),
                         "Alert level 255 != 1, "
                         "Expected alert description "
                         "\"bad_record_mac\" or \"illegal_parameter\" does "
                         "not match received "
                         "\"255\"")

    def test___str__(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.illegal_parameter)

        self.assertEqual(str(exp), "ExpectAlert(level=1, description=47)")


class TestExpectSSL2Alert(unittest.TestCase):
    def test___init__(self):
        exp = ExpectSSL2Alert()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectSSL2Alert(SSL2ErrorDescription.bad_certificate)

        msg = Message(ContentType.handshake,
                      bytearray([SSL2HandshakeType.error,
                                 0x00,
                                 0x04]))
        exp.process(None, msg)

    def test_process_with_non_matching_alert(self):
        exp = ExpectSSL2Alert(SSL2ErrorDescription.bad_certificate)
        msg = Message(ContentType.handshake,
                      bytearray([SSL2HandshakeType.error,
                                 0x00,
                                 0x01]))

        with self.assertRaises(AssertionError):
            exp.process(None, msg)

class TestExpectApplicationData(unittest.TestCase):
    def test___init__(self):
        exp = ExpectApplicationData()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectApplicationData()

        msg = Message(ContentType.application_data,
                      bytearray(0))

        self.assertTrue(exp.is_match(msg))

    def test_process(self):
        exp = ExpectApplicationData()

        state = ConnectionState()
        msg = Message(ContentType.application_data,
                      bytearray(0))

        exp.process(state, msg)

    def test_process_with_non_matching_data(self):
        exp = ExpectApplicationData(bytearray(b"hello"))

        state = ConnectionState()
        msg = Message(ContentType.application_data,
                      bytearray(b"bye"))

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_size(self):
        exp = ExpectApplicationData(size=5)

        state = ConnectionState()
        msg = Message(ContentType.application_data, bytearray(b'hello'))

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_mismatched_size(self):
        exp = ExpectApplicationData(size=1024)

        state = ConnectionState()
        msg = Message(ContentType.application_data, bytearray(b'hello'))

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)


class TestExpectServerKeyExchange(unittest.TestCase):
    def test__init__(self):
        exp = ExpectServerKeyExchange()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.server_key_exchange]))

        self.assertTrue(exp.is_match(msg))

    def test_process(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SignatureAlgorithmsExtension().create(
            [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key)

        msg = srv_key_exchange.makeServerKeyExchange('sha256')

        exp.process(state, msg)

        self.assertEqual(goodGroupParameters[2][1],
                         state.key['ServerKeyExchange.dh_p'])

    def test_process_with_ECDHE_RSA(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SignatureAlgorithmsExtension().create(
            [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)]),
            SupportedGroupsExtension().create([GroupName.secp256r1])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = ECDHE_RSAKeyExchange(
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                [GroupName.secp256r1])

        msg = srv_key_exchange.makeServerKeyExchange('sha256')

        exp.process(state, msg)

    def test_process_with_ECDHE_RSA_bad_signature(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SignatureAlgorithmsExtension().create(
            [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)]),
            SupportedGroupsExtension().create([GroupName.secp256r1])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = ECDHE_RSAKeyExchange(
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                [GroupName.secp256r1])

        msg = srv_key_exchange.makeServerKeyExchange('sha256')
        msg.signature[-1] ^= 1

        print("Error printed below is expected", file=sys.stderr)
        with self.assertRaises(TLSDecryptionFailed):
            exp.process(state, msg)

    def test_process_with_default_signature_algorithm(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key)

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        exp.process(state, msg)

    def test_process_with_not_matching_signature_algorithms(self):
        exp = ExpectServerKeyExchange(valid_sig_algs=[(HashAlgorithm.sha256,
                                                       SignatureAlgorithm.rsa)])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key)

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        with self.assertRaises(TLSIllegalParameterException):
            exp.process(state, msg)

    def test_process_with_unknown_key_exchange(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))
        private_key = parsePEMKey(srv_raw_key, private=True)

        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SignatureAlgorithmsExtension().create(
            [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        state.version = server_hello.server_version
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        state.handshake_messages.append(cert)

        msg = ServerKeyExchange(state.cipher, state.version)
        msg.createSRP(1, 2, bytearray(3), 5)
        msg.signAlg = SignatureAlgorithm.rsa
        msg.hashAlg = HashAlgorithm.sha256
        hash_bytes = msg.hash(client_hello.random, server_hello.random)
        hash_bytes = private_key.addPKCS1Prefix(hash_bytes, 'sha256')
        msg.signature = private_key.sign(hash_bytes)

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_rcf7919_groups(self):
        exp = ExpectServerKeyExchange(valid_groups=[256])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SupportedGroupsExtension().create([256])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                dhGroups=range(256, 258))

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        exp.process(state, msg)

    def test_process_with_rcf7919_groups_required_not_provided(self):
        exp = ExpectServerKeyExchange(valid_groups=[256])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SupportedGroupsExtension().create([256])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                dhGroups=None)

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_specific_parameters(self):
        exp = ExpectServerKeyExchange(valid_params=[goodGroupParameters[0]])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = []
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                dhParams=goodGroupParameters[0])

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        exp.process(state, msg)

    def test_process_with_unexpected_parameters(self):
        exp = ExpectServerKeyExchange(valid_params=[goodGroupParameters[0]])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = []
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                dhParams=goodGroupParameters[1])

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("RFC5054 group 2", str(e.exception))

    def test_process_with_unrecognised_parameters(self):
        exp = ExpectServerKeyExchange(valid_params=[goodGroupParameters[0]])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = []
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                dhParams=(0xabc, goodGroupParameters[1][1]))

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("g:0xabc", str(e.exception))

    def test_with_mutually_exclusive_dh_settings(self):
        with self.assertRaises(ValueError):
            ExpectServerKeyExchange(valid_params=[goodGroupParameters[0]],
                                    valid_groups=[255])


class TestExpectCertificateRequest(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCertificateRequest()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test___init___with_both_extensions_and_sigalgs(self):
        with self.assertRaises(ValueError):
            ExpectCertificateRequest([], extensions=[])

    def test_is_match(self):
        exp = ExpectCertificateRequest()

        state = ConnectionState()
        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate_request]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectCertificateRequest()

        state = ConnectionState()
        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.certificate_request]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        exp = ExpectCertificateRequest()

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create([ClientCertificateType.rsa_sign,
                    ClientCertificateType.rsa_fixed_dh],
                   [],
                   [(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha384, SignatureAlgorithm.rsa)])
        msg = Message(ContentType.handshake,
                      msg.write())

        exp.process(state, msg)

    def test_sig_algs(self):
        sig_algs = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha384, SignatureAlgorithm.rsa)]
        exp = ExpectCertificateRequest(sig_algs=sig_algs)

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create([ClientCertificateType.rsa_sign,
                    ClientCertificateType.rsa_fixed_dh],
                   [],
                   sig_algs)
        msg = Message(ContentType.handshake, msg.write())

        exp.process(state, msg)

    def test_sig_algs_mismatched(self):
        sig_algs = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha384, SignatureAlgorithm.rsa)]
        exp = ExpectCertificateRequest(sig_algs=sig_algs[0:1])

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create([ClientCertificateType.rsa_sign,
                    ClientCertificateType.rsa_fixed_dh],
                   [],
                   sig_algs)
        msg = Message(ContentType.handshake, msg.write())

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("Got: (rsa_pkcs1_sha1, rsa_pkcs1_sha256, "
                      "rsa_pkcs1_sha384)", str(e.exception))

    def test_process_with_matching_cert_types(self):
        sig_algs = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
                    (HashAlgorithm.sha1, SignatureAlgorithm.dsa),
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.ed25519]
        cert_types= [ClientCertificateType.rsa_sign,
                     ClientCertificateType.ecdsa_sign,
                     ClientCertificateType.dss_sign]
        exp = ExpectCertificateRequest(cert_types=list(cert_types))

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create(list(cert_types),
                   [],
                   sig_algs)
        msg = Message(ContentType.handshake, msg.write())

        exp.process(state, msg)

        self.assertTrue(state.handshake_messages)

    def test_process_with_mismatched_cert_types(self):
        sig_algs = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha384, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.ecdsa)]
        cert_types= [ClientCertificateType.rsa_sign,
                     ClientCertificateType.ecdsa_sign]
        exp = ExpectCertificateRequest(cert_types=cert_types[:1])

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create(list(cert_types),
                   [],
                   sig_algs)
        msg = Message(ContentType.handshake, msg.write())

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("Got: (rsa_sign, ecdsa_sign)", str(e.exception))

    def test_process_with_rsa_sigs_with_missing_rsa_sign_cert(self):
        sig_algs = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa)]
        exp = ExpectCertificateRequest(sig_algs=sig_algs)

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create([ClientCertificateType.ecdsa_sign], [], sig_algs)

        msg = Message(ContentType.handshake, msg.write())

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertIn("RSA signature", str(e.exception))
        self.assertIn("rsa_sign", str(e.exception))

    def test_process_with_explicit_extension(self):
        ext = SignatureAlgorithmsExtension().create(
            [SignatureScheme.rsa_pss_rsae_sha256])

        state = ConnectionState()
        state.version = (3, 4)
        exp = ExpectCertificateRequest(
            extensions={ExtensionType.signature_algorithms: ext})

        msg = CertificateRequest((3, 4))
        msg.create(extensions=[ext])

        exp.process(state, msg)

    def test_with_mismatched_ext_values(self):
        ext = SignatureAlgorithmsExtension().create(
            [SignatureScheme.rsa_pss_rsae_sha256])

        exp = ExpectCertificateRequest(
            extensions={ExtensionType.signature_algorithms: ext})

        state = ConnectionState()
        state.version = (3, 4)
        msg = CertificateRequest((3, 4))
        ext = SignatureAlgorithmsExtension().create(
            [SignatureScheme.ecdsa_secp256r1_sha256])
        msg.create(extensions=[ext])

        with self.assertRaises(AssertionError) as exc:
            exp.process(state, msg)

        self.assertIn('Expected extension not matched', str(exc.exception))

    def test_process_with_implicit_handler(self):
        ext = SignatureAlgorithmsExtension().create(
            [SignatureScheme.rsa_pss_rsae_sha256])

        state = ConnectionState()
        state.version = (3, 4)
        exp = ExpectCertificateRequest()

        msg = CertificateRequest((3, 4))
        msg.create(extensions=[ext])

        exp.process(state, msg)

    def test_process_with_implicit_handler_and_malformed_ext(self):
        ext = SignatureAlgorithmsExtension().create([])

        state = ConnectionState()
        state.version = (3, 4)
        exp = ExpectCertificateRequest()

        msg = CertificateRequest((3, 4))
        msg.create(extensions=[ext])

        with self.assertRaises(AssertionError) as exc:
            exp.process(state, msg)

        self.assertIn("Empty or malformed signature_algorithms extension",
                      str(exc.exception))

    def test_process_grease_with_implicit_handler(self):
        ext = TLSExtension(extType=31354).create(b'')

        state = ConnectionState()
        state.version = (3, 4)
        exp = ExpectCertificateRequest()

        msg = CertificateRequest((3, 4))
        msg.create(extensions=[ext])

        exp.process(state, msg)

    def test_process_implicit_with_CR_forbidden_extension(self):
        ext = HeartbeatExtension().create(HeartbeatMode.PEER_ALLOWED_TO_SEND)

        state = ConnectionState()
        state.version = (3, 4)
        exp = ExpectCertificateRequest()

        msg = CertificateRequest((3, 4))
        msg.create(extensions=[ext])

        with self.assertRaises(AssertionError) as exc:
            exp.process(state, msg)

        self.assertIn("heartbeat", str(exc.exception))

    def test_process_ext_with_incorrect_handler(self):
        ext = TLSExtension(extType=31354).create(b'')

        state = ConnectionState()
        state.version = (3, 4)
        exp = ExpectCertificateRequest(extensions={31354: object()})

        msg = CertificateRequest((3, 4))
        msg.create(extensions=[ext])

        with self.assertRaises(ValueError):
            exp.process(state, msg)

    def test_process_with_context_set(self):
        ext = SignatureAlgorithmsExtension().create(
            [SignatureScheme.rsa_pss_rsae_sha256])

        state = ConnectionState()
        state.version = (3, 4)
        ctx = []
        exp = ExpectCertificateRequest(context=ctx)

        msg = CertificateRequest((3, 4))
        msg.create(extensions=[ext])

        exp.process(state, msg)

        self.assertEqual(ctx, [msg])


class TestExpectHeartbeat(unittest.TestCase):
    def test___init__(self):
        exp = ExpectHeartbeat()

        self.assertIsNotNone(exp)
        self.assertEqual(exp.message_type,
            HeartbeatMessageType.heartbeat_response)
        self.assertIsNone(exp.payload)
        self.assertIsNone(exp.padding_size)

    def test_process_with_defaults(self):
        hb = Heartbeat().create(
                HeartbeatMessageType.heartbeat_response,
                bytearray(b'test heartbeat'),
                16)

        exp = ExpectHeartbeat()

        exp.process(None, hb)

    def test_process_with_unexpected_type(self):
        hb = Heartbeat().create(
                HeartbeatMessageType.heartbeat_request,
                bytearray(b'test heartbeat'),
                16)

        exp = ExpectHeartbeat()

        with self.assertRaises(AssertionError) as e:
            exp.process(None, hb)

        self.assertIn("received: heartbeat_request", str(e.exception))

    def test_process_with_specified_payload(self):
        hb = Heartbeat().create(
                HeartbeatMessageType.heartbeat_response,
                bytearray(b'test heartbeat'),
                16)

        exp = ExpectHeartbeat(payload=bytearray(b'test heartbeat'))

        exp.process(None, hb)

    def test_process_with_unexpected_payload(self):
        hb = Heartbeat().create(
                HeartbeatMessageType.heartbeat_response,
                bytearray(b'unexpected'),
                16)

        exp = ExpectHeartbeat(payload=bytearray(b'test heartbeat'))

        with self.assertRaises(AssertionError) as e:
            exp.process(None, hb)

        self.assertIn("Unexpected payload", str(e.exception))
        self.assertIn("unexpected", str(e.exception))

    def test_process_with_too_small_padding(self):
        hb = Heartbeat().create(
                HeartbeatMessageType.heartbeat_response,
                bytearray(b'test heartbeat'),
                15)

        exp = ExpectHeartbeat()

        with self.assertRaises(AssertionError):
            exp.process(None, hb)

    def test_process_with_custom_size_of_padding(self):
        hb = Heartbeat().create(
                HeartbeatMessageType.heartbeat_response,
                bytearray(b'test heartbeat'),
                20)

        exp = ExpectHeartbeat(padding_size=20)

        exp.process(None, hb)

    def test_process_with_unexpected_size_of_padding(self):
        hb = Heartbeat().create(
                HeartbeatMessageType.heartbeat_response,
                bytearray(b'test heartbeat'),
                16)

        exp = ExpectHeartbeat(padding_size=20)

        with self.assertRaises(AssertionError) as e:
            exp.process(None, hb)

        self.assertIn("unexpected size of padding", str(e.exception))
        self.assertIn("received: 16", str(e.exception))


class TestExpectKeyUpdate(unittest.TestCase):
    def test__init__(self):
        exp = ExpectKeyUpdate()

        self.assertIsNotNone(exp)
        self.assertEqual(exp.message_type, None)

    def test_process_with_matching_type(self):
        ku = KeyUpdate().create(KeyUpdateMessageType.update_requested)

        exp = ExpectKeyUpdate(KeyUpdateMessageType.update_requested)
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        ret = mock.Mock()
        state.msg_sock.calcTLS1_3KeyUpdate_sender.return_value = (None, ret)
        cipher = mock.Mock()
        state.cipher = cipher
        cats = mock.Mock()
        state.key['client application traffic secret'] = cats
        sats = mock.Mock()
        state.key['server application traffic secret'] = sats

        exp.process(state, ku)

        state.msg_sock.calcTLS1_3PendingState.called_once_with(
            cipher, cats, sats)
        self.assertIs(state.key['server application traffic secret'], ret)

    def test_process_with_non_matching_type(self):
        ku = KeyUpdate().create(KeyUpdateMessageType.update_requested)

        exp = ExpectKeyUpdate(KeyUpdateMessageType.update_not_requested)

        with self.assertRaises(AssertionError):
            exp.process(None, ku)

    def test_process_with_undefined_value(self):
        ku = KeyUpdate().create(12)

        exp = ExpectKeyUpdate(KeyUpdateMessageType.update_not_requested)

        with self.assertRaises(AssertionError):
            exp.process(None, ku)


class TestExpectHelloRequest(unittest.TestCase):
    def setUp(self):
        self.exp = ExpectHelloRequest()

    def test___init__(self):
        self.assertIsNotNone(self.exp)
        self.assertIsInstance(self.exp, ExpectHelloRequest)
        self.assertTrue(self.exp.is_expect())
        self.assertFalse(self.exp.is_generator())
        self.assertFalse(self.exp.is_command())

    def test_test_description_in_init(self):
        exp = ExpectHelloRequest("first HelloRequest")

        self.assertEqual(exp.description, "first HelloRequest")
        self.assertEqual(repr(exp),
                         "ExpectHelloRequest(description='first HelloRequest')")

    def test_process_with_defaults(self):
        hr = HelloRequest().create()

        self.exp.process(None, hr)

    def test_process_with_wrong_message(self):
        hd = ServerHelloDone().create()

        with self.assertRaises(AssertionError):
            self.exp.process(None, hd)
