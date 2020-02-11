==========
Quickstart
==========

Installing dependencies
=======================

To execute tlsfuzzer test scripts you need a python environment.
This framework supports all versions of python since 2.6 except
3.0, 3.1, and 3.2.
Check the `Travis CI <https://travis-ci.org/tomato42/tlsfuzzer>`_
to see explicitly tested environments.

Python supports installing modules system-wide, to the user directory, or to
a virtual environment.
With ``tlsfuzzer`` dependencies you can use either option, though some work
better than others.

.. note::

    Execute all example commands in the root directory of tlsfuzzer repository
    checkout.

.. hint::

    If you plan to develop, not just use tlsfuzzer, use the instructions in the
    :ref:`installation` chapter.
    If you want to try several scripts before installing full
    development environment, for swift clean up, use the virtual environment
    installation method.

System wide installation
------------------------

Installation of modules system-wide allows for easy execution of scripts later.
This does "pollute" the
system and conflicts with python modules managed by the OS
package manager though. It also requires administrative privileges on the
system. You should use this approach if you plan to
keep using tlsfuzzer for a long time.

To install all dependencies execute as root:

.. code:: bash

    pip install -r requirements.txt

.. warning::
    Different versions of python keep their modules separate, as such,
    installing packages with ``pip`` from Python 2.7 doesn't make them
    available for Python 3.7 and vice versa.

User directory installation
---------------------------

If you don't have administrative privileges on the system, you can install
python modules to your local home directory. This doesn't make them usable
for other users of the system. Unlike the virtual environment approach,
it does make running with wrong python environment less probable.

To install all dependencies to user directory execute:

.. code:: bash

    pip install --user -r requirements.txt


For Python 3.7 this places the modules to the
``~/.local/lib/python3.7/site-packages/`` directory.
For Python 2.7 this places the modules to the
``~/.local/lib/python2.7/site-packages/`` directory.

Virtual environment installation
--------------------------------

You can find detailed description of Python virtual environments in the
`official documentation <https://docs.python.org/3/tutorial/venv.html>`_.
Deleting a virtual environment doesn't influence anything outside of it,
making it safe to do after you don't need it.

To create a virtual environment in a new directory, for example
``~/tlsfuzzer-env``, execute:

.. code:: bash

    python -m venv ~/tlsfuzzer-env

To install all dependencies in that virtual environment execute:

.. code:: bash

    ~/tlsfuzzer-env/bin/pip install -r requirements.txt


.. note::

    When you use virtual environments you must specify the ``python``
    executable from the virtual environment, not the system-wide one.
    Use ``~/tlsfuzzer-env/bin/python`` instead of ``python`` to execute
    the test scripts in following examples. You can also "activate" an
    environment to make ``python`` and ``pip`` point to commands
    from the virtual environment, this modifies only the current session
    though. To do that execute ``source ~/tlsfuzzer-env/bin/activate``.

Starting an OpenSSL server
==========================

To have a server to test against you can use OpenSSL. Example below shows
how to setup a configuration with a self-signed certificate.
You can execute the scripts against any network-accessible server,
if you have one already running, you can skip this part.

Generate certificates
---------------------

Most test cases require a server configured with a certificate
(the ones that require more complex :term:`PKIX` setup print it
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
