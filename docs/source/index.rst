.. tlsfuzzer documentation master file, created by
   sphinx-quickstart on Wed Jan 22 18:09:38 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to tlsfuzzer!
=====================

``tlsfuzzer`` tests :term:`SSL` and :term:`TLS` implementations.

It allows for testing standards-compliance of a given implementation, testing
for presence of known vulnerabilities as well as fuzzing of the :term:`SSL`
and :term:`TLS` connections.

Ready-to-use scripts are already provided for testing significant parts of
the TLS protocols.

This framework is commonly used to test OpenSSL, GnuTLS,
`NSS <https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS>`_ and many
other implementations.

While not all features standardised for :term:`TLS` are supported (it's a work
in progress), the most common features are fully supported:
:term:`TLS` 1.2, :term:`TLS` 1.3, RSA certificates, ECDSA certificates, ECDHE
key exchange, client certificates, AES-GCM, Chacha20-Poly1305 ciphers, etc.
See the
`issue tracker <https://github.com/tomato42/tlsfuzzer/issues>`_ on GitHub
to see wanted, but not yet implemented features.


.. toctree::
   :maxdepth: 2
   :caption: Contents:
   :hidden:

   quickstart
   installation
   theory
   glossary
   modules


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`glossary`
* :ref:`search`
