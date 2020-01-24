==========
Quickstart
==========

After installing the dependencies and checking out the git repository it's
possible to execute test cases by pointing them at :term:`TLS` servers.

Starting an OpenSSL server
==========================

To have a server to test against you can use OpenSSL. Example below shows
how to setup a configuration with a self-signed certificate.
You can execute the scripts against any network-accessible server,
if you have one already running, you can skip this part.

Generate certificates
---------------------

Most test cases require a server configured with a certificate
(the ones that require more complex :term:`PKIX` infrastructure print it
when executed).

To create a simple self-signed certificate and key, execute the following
OpenSSL command:

.. code-block:: bash

    openssl req -x509 -newkey rsa -keyout /tmp/localhost.key \
    -out /tmp/localhost.crt -subj /CN=localhost -nodes -batch \
    -days 3650

Start the server
----------------

Once you have a key and a certificate, you can use them to configure a test
server with support for minimal subset of HTTP:

.. code-block:: bash

    openssl s_server -key /tmp/localhost.key -cert /tmp/localhost.crt -www


Executing a test case
=====================

With a :term:`TLS` server available, you can start executing test cases against
it.

To verify that a server supports :term:`TLS` 1.2 or earlier, you can
use the ``test-conversation.py`` script.

To execute the script against a server running on ``localhost`` on port 4433,
as it's set-up in the preceding OpenSSL example, execute the following
command in the checkout of tlsfuzzer repository:

.. code-block:: bash

    PYTHONPATH=. python scripts/test-conversation.py

This command should provide the following output if everything went fine:

.. code-block:: none

    sanity ...
    OK

    sanity ...
    OK

    Basic conversation script; check basic communication with typical
    cipher, TLS 1.2 or earlier and RSA key exchange (or (EC)DHE if
    -d option is used)

    version: 4

    Test end
    successful: 2
    failed: 0

All the test scripts support at least ``--help`` option. For this script it
will provide the following information:

.. code-block:: none

    Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]
     -h hostname    name of the host to run the test against
                    localhost by default
     -p port        port number to use for connection, 4433 by default
     probe-name     if present, will run only the probes with given
                    names and not all of them, e.g "sanity"
     -e probe-name  exclude the probe from the list of the ones run
                    may be specified multiple times
     -n num         only run `num` random tests instead of a full set
                    ("sanity" tests are always executed)
     -d             negotiate (EC)DHE instead of RSA key exchange
     --help         this message

Almost all scripts support this set of command line options.

Executing a test case to verify :term:`TLS` 1.3 support works similar:

.. code-block:: bash

    PYTHONPATH=. python scripts/test-tls13-conversation.py

This produces similar output:

.. code-block:: none

    sanity ...
    OK

    sanity ...
    OK

    Basic communication test with TLS 1.3 server
    Check if communication with typical group and cipher works with
    the TLS 1.3 server.

    version: 2

    Test end
    successful: 2
    failed: 0

Similarly to the :term:`TLS` 1.2 script, this one supports a set of options:

.. code-block:: none

    Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]
     -h hostname    name of the host to run the test against
                    localhost by default
     -p port        port number to use for connection, 4433 by default
     probe-name     if present, will run only the probes with given
                    names and not all of them, e.g "sanity"
     -e probe-name  exclude the probe from the list of the ones run
                    may be specified multiple times
     -n num         only run `num` random tests instead of a full set
                    ("sanity" tests are always executed)
     --help         this message

As cryptographic parameter negotiation happens differently in :term:`TLS` 1.3
than it does in :term:`TLS` 1.2, the :term:`TLS` 1.3 scripts generally don't
support the ``-d`` option.

.. note::
  When a particular test case in the script observes an expected behaviour
  it prints an "OK" status, if all test cases in a test script do that, the
  script passes. Expected behaviour doesn't mean a successful
  connection. Negative test cases *expect* a failed :term:`TLS` handshake or
  a particular kind of connection abortion.
