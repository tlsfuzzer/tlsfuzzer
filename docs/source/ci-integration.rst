=================
Integrating in CI
=================

While you can write one-off test cases using tlsfuzzer to test a specific
issue, tlsfuzzer caters to :term:`CI` environments.

Preparation
===========

Configuration of the server has significant impact on its behaviour.
For example, you can't test :term:`ECDSA` cipher suites without an
:term:`ECDSA` certificate available for the server.

To verify all features of a server implementation you need to enable all
of them in the server.
In case the features conflict with each-other, you need to test
them separately by running the relevant tests with every configuration.

As a full-featured implementation has a lot of independent parameters,
you can find yourself in a situation where you don't have enough computer
resources to test all combinations of parameters.
In such case you may want to apply `combinatorial testing
<https://www.nist.gov/programs-projects/automated-combinatorial-testing-software-acts>`_,
or `pairwise testing <https://en.wikipedia.org/wiki/All-pairs_testing>`_,
to keep the required amount of server configurations manageable.

Configuration variables
-----------------------

You should take into consideration the following aspects of server
configuration:

..
    please do not renumber the following list, there are external references
    to it

1. How many and what types of certificates the server has set up

   * especially relevant for differences between ``rsaEncryption`` and
     ``rsassa-pss`` in Subject Public Key Info
2. Test with :term:`SNI` enabled and disabled
3. Testing the default host vs :term:`SNI` host of a :term:`SNI`\ -enabled
   server
4. Test with different security levels enabled in the library

   * for OpenSSL: cipherstring with ``@SECLEVEL=3`` vs ``@SECLEVEL=0``
   * for GnuTLS: priority string with ``NORMAL`` vs ``SECURE256:%PROFILE_HIGH``
5. No client certificates, requesting client certificates, or requiring client
   certificates
6. Test with :term:`ALPN` (or :term:`NPN`) enabled and disabled
7. Session tickets enabled or not

   * For example in OpenSSL it influences the *kind* of tickets issued by
     OpenSSL in :term:`TLS` 1.3
8. Test with support for 0-RTT enabled and disabled

   * for example, even with 0-RTT disabled, the server still must process
     0-RTT ClientHello but ignore the early data
9. Enabled protocol versions (e.g. with :term:`TLS` 1.2 implemented but only
   :term:`TLS` 1.1 enabled, the server must not abort connection starting
   with a :term:`TLS` 1.1 ClientHello with ``TLS_FALLBACK_SCSV``
10. Changes to configuration before session establishment and resumption
    (e.g. resuming a session with a now disabled cipher; or
    processing 0-RTT data with its cipher disabled)
11. Integrated with different applications—callbacks can change important
    parts of implementation behaviour
12. Large client or server certificates
13. The private key residing in an :term:`HSM` or a smart card

    * different features supported in the smart card—things like RSA-PSS
      or SHA-384
14. Testing with specific extension or feature of the protocol disabled,
    enabled, or required
15. Server running under valgrind, compiled with ubsan, asan, etc.
16. Force-enabled features deprecated in later protocol versions
    (e.g. PKCS#1 v1.5 SHA-1 signatures enabled through configuration
    should not enable them in :term:`TLS` 1.3)
17. Server running on different hardware (different assembly implementations
    in use, AES-NI support, SSE3, etc.)
18. Interactions between implementation versions and session resumptions—
    test what happens when a client resumes a session from old library with
    new server (and vice versa, to simulate server downgrade)


Running tests
=============

Since the included tests expect strict adherence to :term:`RFC`\ s, you can
expect that executing them for the first time will find a lot of issues.
As such, you should start with running them one by one, manually, inspecting
test results and checking if they pass.

Many tests verify behaviour unrelated to main feature under
test, indicated by the name and the summary printed at the end of execution.
Such tests provide extra command line options to make them
more aligned with behaviour of the tested implementation.

.. warning::

    Some tests allow changing expected alert description for the negative
    tests. Before introducing any such modifcations you should have a good
    understanding of :term:`TLS` and oracle attacks—you need to verify that
    similarly malformed messages result in the exact same alerts.
    Please note that some features (e.g. padding in :term:`CBC` mode ciphers)
    have more than one script that tests them, so you need to adjust
    invocations of all relevant scripts.

If you find differences between script-expected behaviour and actually observed
behaviour of the system under test, inspect the source code to determine
the root cause of the issue.
Commonly the implementation detects the wrong behaviour of the
peer but returns a wrong alert.
While technically those are compliance issues and you should fix them
(see also the section :ref:`describing reasons for strict alert description
checking <checking-alerts>`), they don't cause interoperability or security
issues, so you can postpone fixing them.

While working on a test script, you should adjust its parameters so that it
matches the server configuration.
If a script expects different behaviour, you can either disable running
the failing test case by specifying its name as a parameter to ``-e`` option or
mark it as an "expected failure" by specifying its name as a parameter to
``-x`` option.
In the latter case, you can also specify a substring to match the printed
error against with the ``-X`` option.
Using ``-x`` ensures that resolving the bug causes the test suite to "notice"
the new behaviour.
Pairing it with ``-X`` option ensures that the *way* the test fails doesn't
change.

Scripts by default require less than 10 seconds to execute against a local
server (using a mid-range CPU from 2020).
You can use the ``-n`` option to control how many tests to execute in a
script.
To execute all tests in a script, specify ``-n 0``.

Automation scripts
==================

Tlsfuzzer ships with a few scripts to make using it in :term:`CI` easier:
``verify-scripts-json.py``, ``scripts_retention.py``, and
``verify-multiple-jsons.py``.

The ``scripts_retention.py`` one starts servers based on passed configuration
file.
To ensure reliable execution, it verifies that the server can accept
connections before running the test cases.
The script uses ``server_hostname`` and ``server_port`` to verify readiness
of the server to accept connections.

.. tip::
    The ``server_command`` can specify the server to run or a command necessary
    to reconfigure the server. In latter case, it needs to run for as long
    as ``scripts_retention.py`` executes test scripts for—
    ``scripts_retention.py`` aborts testing when this command exits.

A test case marked with ``"exp_pass": false`` needs to fail, otherwise
the script counts it as a failure.

You can find example configuration files in ``tests`` directory:
`tlslite-ng.json
<https://github.com/tomato42/tlsfuzzer/blob/master/tests/tlslite-ng.json>`_
and
`tlslite-ng-random-subset.json
<https://github.com/tomato42/tlsfuzzer/blob/master/tests/tlslite-ng-random-subset.json>`_.
The latter one is part of the :term:`CI` for tlsfuzzer.

The ``verify-multiple-jsons.py`` and ``verify-scripts-json.py`` check if
specified json files reference all tests in the ``scripts`` directory.
You should use them when migrating to new version of tlsfuzzer to verify that
you don't skip any newly added scripts.
