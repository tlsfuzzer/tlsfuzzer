
from tlsfuzzer.badserver import BadServer, ServerSettings
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509certchain import X509CertChain
from tlslite.x509 import X509
from tlslite.constants import CipherSuite

import socket

def main():
    c_id = 0x009F
    CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = c_id
    CipherSuite.ietfNames[c_id] = 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
    CipherSuite.aes128GcmSuites.append(c_id)
    CipherSuite.sha256Suites.append(c_id)
    CipherSuite.dheCertSuites.append(c_id)
    CipherSuite.tls12Suites.append(c_id)
    CipherSuite.certAllSuites.append(c_id)
    CipherSuite.dhAllSuites.append(c_id)

    c_id = 0x009D
    CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 = c_id
    CipherSuite.ietfNames[c_id] = 'TLS_RSA_WITH_AES_256_GCM_SHA384'
    CipherSuite.aes128GcmSuites.append(c_id)
    CipherSuite.sha256Suites.append(c_id)
    CipherSuite.tls12Suites.append(c_id)
    CipherSuite.certSuites.append(c_id)
    CipherSuite.certAllSuites.append(c_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', 4433))

    sock.listen(5)

    with open("/tmp/localhost.pem", "rb") as cert_f:
        encoded_certificate = cert_f.read()

    encoded_certificate = str(encoded_certificate, "utf-8")
    cert_list = X509CertChain([X509().parse(encoded_certificate)])

    with open("/tmp/localhost.key", "rb") as key_f:
        encoded_key = key_f.read()
    encoded_key = str(encoded_key, "utf-8")
    priv_key = parsePEMKey(encoded_key, private=True)

    settings = ServerSettings()
    settings.error_handling = ServerSettings.ERROR_ALERT_GENERIC
    settings.cert_chain = cert_list
    settings.private_key = priv_key
    settings.cipher_ordering = ServerSettings.SERVER_SIDE

    server = BadServer(sock, settings)

    server.run()

if __name__ == "__main__":
    main()
