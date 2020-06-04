=============================
Projects using tlsfuzzer
=============================

Besides the internal use of tlsfuzzer in Red Hat few projects adopted it
in upstream testing.

GnuTLS
======

You can find the most complete integration of tlsfuzzer in the GnuTLS project.
The configuration files for it reside in the main source repository,
in `tests/suite/tls-fuzzer
<https://gitlab.com/gnutls/gnutls/-/tree/master/tests/suite/tls-fuzzer>`_
directory.

To see it in action compile GnuTLS as usual and go to the ``tests/suite``
directory. There execute
``make check TESTS=tls-fuzzer/tls-fuzzer-nocert-tls13.sh``.

NSS
===

The other project with few test scripts automated is the NSS library.
You can find the test scripts in the `nss/tests/tlsfuzzer
<https://dxr.mozilla.org/mozilla-central/source/security/nss/tests/tlsfuzzer>`_
directory.
