from tlsfuzzer.messages import Connect
root_node = Connect("localhost", 4433)
node = root_node

from tlslite.constants import CipherSuite
ciphers = [
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
]

extensions = {}

from tlslite.constants import GroupName
groups = [
    GroupName.secp256r1,
    GroupName.x25519
]

from tlslite.extensions import SupportedGroupsExtension
from tlslite.constants import ExtensionType
groups_ext = SupportedGroupsExtension().create(groups)
extensions[ExtensionType.supported_groups] = groups_ext

from tlslite.constants import (
    SignatureScheme,
    HashAlgorithm,
    SignatureAlgorithm
)
sig_algs = [
    SignatureScheme.ecdsa_secp521r1_sha512,
    SignatureScheme.ecdsa_secp384r1_sha384,
    SignatureScheme.ecdsa_secp256r1_sha256,
    SignatureScheme.rsa_pss_pss_sha512,
    SignatureScheme.rsa_pss_pss_sha384,
    SignatureScheme.rsa_pss_pss_sha256,
    SignatureScheme.rsa_pss_rsae_sha512,
    SignatureScheme.rsa_pss_rsae_sha384,
    SignatureScheme.rsa_pss_rsae_sha256,
    SignatureScheme.rsa_pkcs1_sha512,
    SignatureScheme.rsa_pkcs1_sha384,
    SignatureScheme.rsa_pkcs1_sha256,
    (HashAlgorithm.sha1, SignatureAlgorithm.ecdsa),
    SignatureScheme.rsa_pkcs1_sha1
]

from tlslite.extensions import SignatureAlgorithmsExtension
sig_algs_ext = SignatureAlgorithmsExtension().create(sig_algs)
extensions[ExtensionType.signature_algorithms] = sig_algs_ext

from tlslite.extensions import RenegotiationInfoExtension
renego_ext = RenegotiationInfoExtension().create(b'')
extensions[ExtensionType.renegotiation_info] = renego_ext

from tlsfuzzer.messages import ClientHelloGenerator
node = node.add_child(ClientHelloGenerator(ciphers, extensions=extensions))

from tlsfuzzer.expect import (
    ExpectServerHello, ExpectCertificate, ExpectServerKeyExchange,
    ExpectServerHelloDone
)
node = node.add_child(ExpectServerHello())
node = node.add_child(ExpectCertificate())
node = node.add_child(ExpectServerKeyExchange())
node = node.add_child(ExpectServerHelloDone())

from tlsfuzzer.messages import (
    ClientKeyExchangeGenerator,
    ChangeCipherSpecGenerator,
    FinishedGenerator
)
node = node.add_child(ClientKeyExchangeGenerator())
node = node.add_child(ChangeCipherSpecGenerator())
node = node.add_child(FinishedGenerator())

from tlsfuzzer.expect import (
    ExpectChangeCipherSpec,
    ExpectFinished
)
node = node.add_child(ExpectChangeCipherSpec())
node = node.add_child(ExpectFinished())

from tlsfuzzer.messages import ApplicationDataGenerator
from tlsfuzzer.expect import ExpectApplicationData
request = b"GET / HTTP/1.0\r\n\r\n"
node = node.add_child(ApplicationDataGenerator(request))
node = node.add_child(ExpectApplicationData())

from tlsfuzzer.messages import AlertGenerator
from tlslite.constants import AlertLevel, AlertDescription
node = node.add_child(AlertGenerator(AlertLevel.warning,
                                     AlertDescription.close_notify))

from tlsfuzzer.expect import ExpectAlert, ExpectClose

node = node.add_child(ExpectAlert())
node.next_sibling = ExpectClose()
node.add_child(ExpectClose())

from tlsfuzzer.runner import Runner
runner = Runner(root_node)

runner.run()
