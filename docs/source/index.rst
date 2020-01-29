.. tlsfuzzer documentation master file, created by
   sphinx-quickstart on Wed Jan 22 18:09:38 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to tlsfuzzer!
=====================

``tlsfuzzer`` is a framework for testing SSL and TLS implementations.

It allows for testing standards-compliance of a given implementation, testing
for presence of known vulnerabilities as well as fuzzing of the SSL and TLS
connections.

Ready-to-use scripts are already provided for testing significant parts of
the TLS protocols.

This framework is commonly used to test OpenSSL, GnuTLS,
`NSS <https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS>`_ and many
other implementations.

While not all features standardised for TLS are supported (it's a work
in progress), the most common features are fully supported:
TLS 1.2, TLS 1.3, RSA certificates, ECDSA certificates, ECDHE key exchange,
client certificates, AES-GCM, Chacha20-Poly1305 ciphers, etc. See the
`issue tracker <https://github.com/tomato42/tlsfuzzer/issues>`_ on GitHub
to see wanted, but not yet implemented features.


.. toctree::
   :maxdepth: 2
   :caption: Contents:
   :hidden:

   installation
   modules


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
