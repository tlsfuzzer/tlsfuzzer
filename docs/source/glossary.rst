.. _glossary:

Glossary
========

.. glossary::
   :sorted:

   TLS
     Transport Layer Security is a cryptographic network protocol defined
     in a series of :term:`RFC` documents, newest of which is RFC8446.

   RFC
     Request For Comments are standards published by Internet Engineering Task
     Force, an open standards organisation.

   IETF
     Internet Engineering Task Force is an organisation responsible for
     providing specifications of protocols used over the Internet.

   SSL
     Secure Sockets Layer is an old cryptographic network protocol. It has
     orginated in Netscape in the early 1990's. Currently replaced by
     :term:`TLS`.

   SUT
     System Under Test is the device or implementation that
     the tests are verifying. Excludes tlsfuzzer itself or systems necessary
     to execute it or tlsfuzzer.

   RSA
     Rivest Shamir Adleman is an asymmetric cryptosystem commonly used for
     signing messages or encrypting keys.

   ECDSA
     Elliptic Curve Digital Signature Algorithm uses the Digital Signature
     Algorithm with elliptic curves instead of finite field groups.
     It's an asymmetric cryptosystem, similar to RSA.

   ECDHE
     Implementation of Diffie-Hellman key exchange algorithm over elliptic
     curves.

   AES
     Advanced Encryption Standard is a symmetric block cipher.

   AES-GCM
     Advanced Encryption Standard in Galois Counter Mode is an :term:`AEAD`
     cipher, it encrypts and authenticates data with one operation.
     In :term:`TLS` those ciphers require version 1.2 or 1.3.

   AES-CCM
     :term:`AEAD` mode of Advanced Encryption Standard (:term:`AES`) that
     combines counter mode with the CBC-MAC algorithm.
     In :term:`TLS` those ciphers require version 1.2 or 1.3.

   AES-CCM8
     :term:`AES-CCM` with 8 byte long authentication tag.

   AEAD
     Authenticated Encryption with Associated Data, a mode of operation
     for symmetric ciphers that processes messages and optional additional
     data as atomic objects: the decryption provides data only if
     integrity of data is verified, encryption provides ciphertext only
     when all the data was provided to the encryption function.

   PKIX
     Public Key Infrastructure for the Internet, described use of X.509
     certificates in Internet protocols.

   TCP
     Transport Control Protocol is a stream protocol that provides reliable
     delivery over the Internet Protocol.

   MAC
     Message Authentication Code is the generic name for data used to verify
     integrity of the received data. This data is called an authentication tag.
     There are many MACs defined: :term:`HMAC`, :term:`CMAC`, or :term:`GMAC`.

   HMAC
     Hash-based :term:`MAC`, commonly used with CBC mode ciphers in :term:`TLS`
     before version 1.3

   CMAC
     Cipher-based :term:`MAC`

   GMAC
     Galois :term:`MAC`, commonly used as part of the :term:`AES-GCM` cipher.

   IV
     Initialisation Vector, a value used to influence the generated ciphertext,
     unlike the key, it doesn't have to remain secret

   CBC
     Cipher Block Chaining, an encryption mode for block ciphers, used
     since SSLv2 until TLS 1.2.

   CI
     Continuous Integration is a development practice in which changes are
     merged to ``master`` branch, commonly after the test coverage for the
     project is executed.

   SNI
     Server Name Indication, also known as ``server_name``, is a :term:`TLS`
     extension for negotiatiating connections to "Virtual Hosts". It allows
     a server to distinguish requests for different hostnames sharing a
     single IP address.

   ALPN
     Application Layer Protocol Negotiation is a :term:`TLS` extension
     allowing for co-existence of multiple applications protocols on the same
     :term:`TCP` or :term:`UDP` port. Commonly used to negotiate HTTP/2 over
     HTTP/1.1.

   NPN
     Next Protocol Negotiation is a :term:`TLS` extension allowing for use
     of multiple application layer protocols on the same port. Not
     standardised. Obsoleted by :term:`ALPN`.

   HSM
     Hardware Security Module is usually an extension card that is tasked with
     secure storage of private keys. Some HSMs also provide hardware
     acceleration for cryptographic operations.

   PRF
     Pseudo-Random Function is used to sanitise random values to prepare them
     for use as keys in encryption. :term:`TLS` 1.0 and 1.1 uses combination
     of MD5 and SHA1. :term:`TLS` 1.2 and 1.3 use SHA-256 or SHA-384 based
     algorithms depending on cipher suite negotiated.
