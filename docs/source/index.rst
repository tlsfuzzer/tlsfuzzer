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

You can find ready to use scripts that test significant parts of :term:`TLS`
protocols in the source repository.

The testing of OpenSSL, GnuTLS,
`NSS <https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS>`_, and
other implementations commonly includes running tlsfuzzer test cases.

While tlsfuzzer doesn't support some features of :term:`TLS`,
it includes the most commonly used ones:
:term:`TLS` 1.2, :term:`TLS` 1.3, :term:`RSA` certificates, :term:`ECDSA`
certificates, :term:`ECDHE` key exchange, client certificates, :term:`AES-GCM`,
Chacha20-Poly1305 ciphers, etc.
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
   writing-tests
   advanced-decision-graph
   modifying-messages
   connection-state
   statistical-analysis
   timing-analysis
   ci-integration
   testing-extensions
   testimonials
   glossary
   modules


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`glossary`
* :ref:`search`
