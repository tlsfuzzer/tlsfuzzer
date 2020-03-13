====================
Simple test creation
====================

Network servers use connection timeouts to drop stalled or unused connections.
For some that happens in a minute or two, for others in seconds.
Thus, robust test cases require automation.
tlsfuzzer achieves it through a runner that executes decision graphs.

The test scripts included in ``scripts/`` directory build the decision graph
necessary for testing different scenarios. After building a graph, the runner
executes it and provides a test result (by raising an exception in case of
errors).
The example below builds a single graph and executes it.

Building decision graph
=======================

To exchange :term:`TLS` messages the script needs to establish a :term:`TCP`
connection.
:py:class:`~tlsfuzzer.messages.Connect` takes the server's hostname and a port
number to do that:

.. code:: python

    from tlsfuzzer.messages import Connect
    root_node = Connect("localhost", 4433)
    node = root_node

ClientHello
-----------

Next step requires sending the first message of the :term:`TLS` handshake:
the ClientHello.
This node requires at least two parameters: the list of cipher suites and
a dictionary of extensions.

:py:class:`~tlslite.constants.CipherSuite` class lists cipher suites supported
by the project or
defined by :term:`IETF`.
To establish a connection with ones that use :term:`ECDHE` key exchange and
most commonly used :term:`AES` ciphers, define the following list:

.. code:: python

    from tlslite.constants import CipherSuite
    ciphers = [
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    ]

Connections that use :term:`ECDHE` key exchange need to advertise to the server
the elliptic curves supported by the client.
Those advertisements travel inside extensions.

:py:class:`~tlsfuzzer.messages.ClientHelloGenerator` requires passing the
extensions as a
:py:class:`dict` or similar object:

.. code:: python

    extensions = {}

:py:class:`~tlslite.constants.GroupName` class lists the groups defined for
:term:`TLS`.
To use the two most common ones write:

.. code:: python

    from tlslite.constants import GroupName
    groups = [
        GroupName.secp256r1,
        GroupName.x25519
    ]

To send that list to the server, package it into a :term:`TLS` extension 
object.
That happens in :py:class:`~tlslite.extensions.SupportedGroupsExtension`:

.. code:: python

    from tlslite.extensions import SupportedGroupsExtension
    from tlslite.constants import ExtensionType
    groups_ext = SupportedGroupsExtension().create(groups)
    extensions[ExtensionType.supported_groups] = groups_ext

Since servers sign :term:`ECDHE` key exchange, clients need to advertise
the signature algorithms they support.
That happens in :py:class:`~tlslite.extensions.SignatureAlgorithmsExtension`
object.

To build a list of most common signature algorithms include:

.. code:: python

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

Then to convert it to an extension include:

.. code:: python

    from tlslite.extensions import SignatureAlgorithmsExtension
    sig_algs_ext = SignatureAlgorithmsExtension().create(sig_algs)
    extensions[ExtensionType.signature_algorithms] = sig_algs_ext

Clients need to advertise support for safe renegotiation, even if they
don't support renegotiation or intend to perform it.
To advertise it, send an empty ``renegotiation_info`` extension, like so:

.. code:: python

    from tlslite.extensions import RenegotiationInfoExtension
    renego_ext = RenegotiationInfoExtension().create(b'')
    extensions[ExtensionType.renegotiation_info] = renego_ext

After preparing all extensions, create the ClientHello object and attach it to
the decision graph:

.. code:: python

    from tlsfuzzer.messages import ClientHelloGenerator
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=extensions))

Server reply
------------

Nodes responsible for processing server response use values specified in
ClientHello as defaults, as such, they don't need any parameters:

.. code:: python

    from tlsfuzzer.expect import (
        ExpectServerHello, ExpectCertificate, ExpectServerKeyExchange,
        ExpectServerHelloDone
    )
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())

Client's key share and finish
-----------------------------

Since ServerKeyExchange message includes the group selected by the server,
the client can generate its own key share and send it back.

Again, as the client nodes look at exchanged messages in the connection, they
don't need any parameters:

.. code:: python

    from tlsfuzzer.messages import (
        ClientKeyExchangeGenerator,
        ChangeCipherSpecGenerator,
        FinishedGenerator
    )
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())

.. note::
    :py:class:`~tlsfuzzer.messages.ChangeCipherSpecGenerator` reconfigures the
    record layer to use encryption for sending the following messages.

Server's finish
---------------

Server accepts the handshake as successful by sending its own ChangeCipherSpec
and Finished, so the script needs to expect them:

.. code:: python

    from tlsfuzzer.expect import (
        ExpectChangeCipherSpec,
        ExpectFinished
    )
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())

.. note::
    :py:class:`~tlsfuzzer.expect.ExpectChangeCipherSpec()` reconfigures the
    record layer to use encryption for receiving the following messages.

Application data
----------------

What happens after the handshake depends on the application protocol that uses
:term:`TLS`.
To perform a single ``GET`` with HTTP 1.0, use the following:

.. code:: python

    from tlsfuzzer.messages import ApplicationDataGenerator
    from tlsfuzzer.expect import ExpectApplicationData
    request = b"GET / HTTP/1.0\r\n\r\n"
    node = node.add_child(ApplicationDataGenerator(request))
    node = node.add_child(ExpectApplicationData())

Closing the connection (alternatives in decision graphs)
--------------------------------------------------------

To handle slight differences between different ways that servers behave,
the framework allows specifying alternatives for the
expected messages.
Since some servers reply with ``close_notify`` Alert to client's
``close_notify`` while others close the connection instantly,
the script needs to reflect that.

.. tip::

    If you want to verify that the server *does* send an Alert before closing
    the connection, don't use the alternative mechanism. Rather specify
    the expected behaviour as connection close after Alert, without the use
    of ``next_sibling``.

To trigger connection close send the alert:

.. code:: python

    from tlsfuzzer.messages import AlertGenerator
    from tlslite.constants import AlertLevel, AlertDescription
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))

Nodes include alternative paths in the ``next_sibling`` field.
To specify that the script should expect connection close with or without
an Alert before connection close, use the following code:

.. code:: python

    from tlsfuzzer.expect import ExpectAlert, ExpectClose

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node.add_child(ExpectClose())

With no more nodes in the graph, the runner closes the connection
and ignores any data in buffers.
:py:class:`~.tlsfuzzer.expect.ExpectClose` instead verifies that server didn't
send any messages before closing the socket.

You can read more about alternatives in the :ref:`Decision graph` chapter.

Executing decision graphs
=========================

If you tried to execute this example script now, nothing would happen.
To actually connect to a server and exchange messages, the runner needs to
execute the decision graph.

As an argument the runner takes the root of the decision graph.
In case of unmet expectations (:term:`TCP` connection failure, misbehaviour
by the server, etc.) the runner raises an exception.

To prepare it execute:

.. code:: python

    from tlsfuzzer.runner import Runner
    runner = Runner(root_node)

To execute the decision graph:

.. code:: python

    runner.run()

Source code of the example
==========================

You can find this example with better formatting, help message, command line
option parsing, and support for :term:`RSA` key exchange in
`scripts/test-conversation.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-conversation.py>`_.
If you want to contribute test cases to this project you should use this
file as a template for :term:`TLS` 1.2 or earlier test cases.
For :term:`TLS` 1.3 test cases you should use
`scripts/test-tls13-conversation.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-tls13-conversation.py>`_.

With no clean-up this example looks like this:

.. literalinclude:: hello-world.py
    :language: python
