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
