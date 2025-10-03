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
        ExpectKeyUpdate, ExpectCompressedCertificate

from tlslite.constants import ContentType, HandshakeType, ExtensionType, \
        AlertLevel, AlertDescription, ClientCertificateType, HashAlgorithm, \
        SignatureAlgorithm, CipherSuite, CertificateType, SSL2HandshakeType, \
        SSL2ErrorDescription, GroupName, CertificateStatusType, ECPointFormat,\
        SignatureScheme, TLS_1_3_HRR, HeartbeatMode, \
        TLS_1_1_DOWNGRADE_SENTINEL, TLS_1_2_DOWNGRADE_SENTINEL, \
        HeartbeatMessageType, KeyUpdateMessageType, \
        CertificateCompressionAlgorithm
from tlslite.messages import Message, ServerHello, CertificateRequest, \
        ClientHello, Certificate, ServerHello2, ServerFinished, \
        ServerKeyExchange, CertificateStatus, CertificateVerify, \
        Finished, EncryptedExtensions, NewSessionTicket, Heartbeat, \
        KeyUpdate, HelloRequest, ServerHelloDone, NewSessionTicket1_0, \
        CompressedCertificate
from tlslite.extensions import SNIExtension, TLSExtension, \
        SupportedGroupsExtension, ALPNExtension, ECPointFormatsExtension, \
        NPNExtension, ServerKeyShareExtension, ClientKeyShareExtension, \
        SrvSupportedVersionsExtension, SupportedVersionsExtension, \
        HRRKeyShareExtension, CookieExtension, \
        SrvPreSharedKeyExtension, PskIdentity, PreSharedKeyExtension, \
        HeartbeatExtension, StatusRequestExtension, \
        CompressedCertificateExtension
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
from tlslite.utils.compat import ML_DSA_AVAILABLE


if sys.version_info < (3, 0):
    BUILTIN_PRINT = "__builtin__.print"
else:
    BUILTIN_PRINT = "builtins.print"

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


srv_raw_mldsa44_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----\n"
    )


srv_raw_mldsa44_key = str(
    "-----BEGIN PRIVATE KEY-----\n"
    "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\n"
    "-----END PRIVATE KEY-----\n"
    )


srv_raw_mldsa65_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "-----END CERTIFICATE-----\n"
    )


srv_raw_mldsa65_key = str(
    "-----BEGIN PRIVATE KEY-----\n"
    "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\n"
    "K/dHvyhM9F63d0JwP2A4skfk\n"
    "-----END PRIVATE KEY-----\n"
    )


srv_raw_mldsa87_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "QURGUpywu9fgCVprcnuHprbDAAAKEx4mKTVASQ==\n"
    "-----END CERTIFICATE-----\n"
    )


srv_raw_mldsa87_key = str(
    "-----BEGIN PRIVATE KEY-----\n"
    "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\n"
    "q46chZyWQ7RDHadLFbM7WUqA\n"
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
        ext = StatusRequestExtension()

        srv_ext_handler_sni(None, ext)

    def test_clnt_ext_handler_status_request_with_non_empty_extension(self):
        ext = StatusRequestExtension().create()

        with self.assertRaises(AssertionError):
            srv_ext_handler_sni(None, ext)

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

    @unittest.skipIf(not ML_DSA_AVAILABLE, "Need dilithium_py present")
    def test_process_with_mldsa44_sig_alg(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_mldsa44_certificate)]))

        private_key = parsePEMKey(srv_raw_mldsa44_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.mldsa44])
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
        scheme = SignatureScheme.mldsa44
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    @unittest.skipIf(not ML_DSA_AVAILABLE, "Need dilithium_py present")
    def test_process_with_mldsa65_sig_alg(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_mldsa65_certificate)]))

        private_key = parsePEMKey(srv_raw_mldsa65_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.mldsa65])
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
        scheme = SignatureScheme.mldsa65
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    @unittest.skipIf(not ML_DSA_AVAILABLE, "Need dilithium_py present")
    def test_process_with_mldsa87_sig_alg(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_mldsa87_certificate)]))

        private_key = parsePEMKey(srv_raw_mldsa87_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.mldsa87])
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
        scheme = SignatureScheme.mldsa87
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    @unittest.skipIf(not ML_DSA_AVAILABLE, "Need dilithium_py present")
    def test_process_mldsa_with_mismatched_signature(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_mldsa87_certificate)]))

        private_key = parsePEMKey(srv_raw_mldsa65_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.mldsa65])
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
        scheme = SignatureScheme.mldsa65
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        with self.assertRaises(AssertionError) as e:
            exp.process(state, cer_verify)

        self.assertIn("Mismatched signature (mldsa65) for used key (mldsa87)",
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
        state.version = (3, 4)

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

    def test_process_in_TLS1_2(self):
        exp = ExpectNewSessionTicket()

        nst = NewSessionTicket1_0().create(3600, b'I am an old ticket')

        state = ConnectionState()
        state.version = (3, 3)

        exp.process(state, nst)

        self.assertIn(nst, state.session_tickets)
        self.assertIsNotNone(state.session_tickets[0].time)


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
        state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = ECDHE_RSAKeyExchange(
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                [GroupName.secp256r1])

        msg = srv_key_exchange.makeServerKeyExchange('sha256')

        exp.process(state, msg)

    @mock.patch(BUILTIN_PRINT)
    def test_process_with_ECDHE_RSA_bad_signature(self, mock_print):
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

        with self.assertRaises(TLSDecryptionFailed):
            exp.process(state, msg)

        self.assertIn("Bad signature", mock_print.call_args[0][0])

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

        state.msg_sock.calcTLS1_3KeyUpdate_sender.assert_called_once_with(
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

class TestExpectCompressedCertificate(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCompressedCertificate()
        self.assertIsNotNone(exp)
        self.assertIsInstance(exp, ExpectCompressedCertificate)
        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_generator())
        self.assertFalse(exp.is_command())
        self.assertEqual(exp.cert_type, CertificateType.x509)
        self.assertIsNone(exp._old_cert)
        self.assertIsNone(exp._old_cert_bytes)
        self.assertIsNone(exp._compression_algo)

    def test_compression_algo_in_init(self):
        exp = ExpectCompressedCertificate(
            compression_algo=CertificateCompressionAlgorithm.zlib)

        self.assertEqual(
            exp._compression_algo, CertificateCompressionAlgorithm.zlib)

    def test_process_with_defaults(self):
        exp = ExpectCompressedCertificate()

        state = ConnectionState()
        state.version = (3, 4)
        client_hello = ClientHello()
        client_hello.addExtension(CompressedCertificateExtension().create(
            [CertificateCompressionAlgorithm.zlib]))
        state.handshake_messages.append(client_hello)

        cc = CompressedCertificate(CertificateType.x509).create(
            CertificateCompressionAlgorithm.zlib,
            X509CertChain([X509().parse(srv_raw_certificate)]))

        exp.process(state, cc)

    def test_process_with_certificate(self):
        exp = ExpectCompressedCertificate()

        cert = Certificate(CertificateType.x509).create(
            X509CertChain([X509().parse(srv_raw_certificate)]))

        with self.assertRaises(AssertionError):
            exp.process(None, cert)

    def test_process_with_wrong_message(self):
        exp = ExpectCompressedCertificate()

        hd = ServerHelloDone().create()

        with self.assertRaises(AssertionError):
            exp.process(None, hd)

    def test_process_twice(self):
        exp = ExpectCompressedCertificate()

        state = ConnectionState()
        state.version = (3, 4)
        client_hello = ClientHello()
        client_hello.addExtension(CompressedCertificateExtension().create(
            [CertificateCompressionAlgorithm.zlib]))
        state.handshake_messages.append(client_hello)

        cc = CompressedCertificate(CertificateType.x509).create(
            CertificateCompressionAlgorithm.zlib,
            X509CertChain([X509().parse(srv_raw_certificate)]))

        self.assertIsNone(exp._old_cert)
        self.assertIsNone(exp._old_cert_bytes)

        exp.process(state, cc)

        self.assertIsNotNone(exp._old_cert)
        self.assertIsNotNone(exp._old_cert_bytes)
        previous_old_cert_bytes = exp._old_cert_bytes

        exp.process(state, cc)

        self.assertEqual(exp._old_cert_bytes, previous_old_cert_bytes)

    def test_process_not_advertized(self):
        exp = ExpectCompressedCertificate()

        state = ConnectionState()
        state.version = (3, 4)
        client_hello = ClientHello()
        client_hello.addExtension(CompressedCertificateExtension().create(
            [CertificateCompressionAlgorithm.brotli]))
        state.handshake_messages.append(client_hello)

        cc = CompressedCertificate(CertificateType.x509).create(
            CertificateCompressionAlgorithm.zlib,
            X509CertChain([X509().parse(srv_raw_certificate)]))

        with self.assertRaises(AssertionError):
            exp.process(state, cc)

    def test_process_with_compression_algorithm(self):
        exp = ExpectCompressedCertificate(
            compression_algo=CertificateCompressionAlgorithm.zlib)

        state = ConnectionState()
        state.version = (3, 4)
        client_hello = ClientHello()
        client_hello.addExtension(CompressedCertificateExtension().create(
            [CertificateCompressionAlgorithm.zlib]))
        state.handshake_messages.append(client_hello)

        cc = CompressedCertificate(CertificateType.x509).create(
            CertificateCompressionAlgorithm.zlib,
            X509CertChain([X509().parse(srv_raw_certificate)]))

        exp.process(state, cc)

    def test_process_with_wrong_compression_algorithm(self):
        exp = ExpectCompressedCertificate(
            compression_algo=CertificateCompressionAlgorithm.brotli)

        state = ConnectionState()
        state.version = (3, 4)
        client_hello = ClientHello()
        client_hello.addExtension(CompressedCertificateExtension().create(
            [CertificateCompressionAlgorithm.zlib]))
        state.handshake_messages.append(client_hello)

        cc = CompressedCertificate(CertificateType.x509).create(
            CertificateCompressionAlgorithm.zlib,
            X509CertChain([X509().parse(srv_raw_certificate)]))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, cc)

        self.assertIn("Compression algorithms doesn't much.", str(e.exception))
