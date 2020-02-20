.. _Decision graph:

==============
Decision graph
==============

While this documentation calls the structure traversed by the runner a
"decision graph," as it can contain loops, it's more precisely described as a
directed graph. Older parts of this documentation and object names refer to
this structure as a "decision tree"—this name
reflects the most common use case in the bundled tests, not the most
complex supported one.

Node fields
===========

A decision graph node, a :py:class:`~tlsfuzzer.tree.TreeNode`, has two
pointers, to a ``child`` and to a ``next_sibling``.
On initialisation nodes set them to ``None``.

Child nodes
-----------

When a node matches received message and processes it without errors,
:py:class:`~tlsfuzzer.runner.Runner` continues execution by switching to the
child.

If ``child`` points to ``None``, runner closes open connections and ends
execution.

To create loops the ``child`` can point to itself or nodes that point to it,
either directly or transitively.
You need to use this mechanism to allow receiving arbitrary number of messages.

Sibling nodes
--------------

The runner uses nodes pointed to by ``next_sibling`` when received message
doesn't match the current node. When sending messages, runner looks
into ``next_sibling`` when connection got closed.

You can use this mechanism to either break out of loops or to define
alternatives in execution.

Advanced decision graph structures
==================================

As mentioned before, the decision graph allows for non-linear relationship
between nodes.

Loops
-----

Test case runner in tlsfuzzer can accept arbitrary number of messages if
the node points to itself as its child.

For example, to accept zero or more NewSessionTicket messages in
:term:`TLS` 1.3 connection, the script needs to include the following code:

.. code:: python

    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

Servers that send the NewSessionTicket after Finished and before
any other messages, require the preceding code after
:py:class:`~tlsfuzzer.expect.ExpectFinished`.
That handles OpenSSL-using servers and others that behave similarly.

.. note::
    :term:`TLS` standard does allow sending NewSessionTicket messages at
    arbitrary times after Finished.

Write the following code to make the runner finish the loop once an
ApplicationData message is received:

.. code:: python

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling

.. tip::
    If you want to accept arbitrary number of NewSessionTicket messages, but
    no fewer than a specified amount, add more
    :py:class:`~tlsfuzzer.expect.ExpectNewSessionTicket` nodes before the
    loop to ensure that server sends them.

You can find a working example of this code in
`test-tls13-conversation.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-tls13-conversation.py>`_.

Alternatives
------------

Servers configured with client certificate based authentication send
CertificateRequest message.
For a script to interoperate with such servers it needs to expect that message.
If a client receives it, it needs to reply with a Certificate message,
even if it doesn't have a certificate (it sends an empty message then).
Since a node doesn't have a limit on the number of parent nodes, script
can specify a branch to handle such connections.

Start with specifying the exceptional path, save reference to the fork point:

.. code:: python

    node = node.add_child(ExpectCertificateRequest())
    fork = node
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator())

Then specify the usual path, for servers that don't ask for client
certificates:

.. code:: python

    fork.next_sibling = ExpectServerHelloDone()

In both handshake scenarios the client sends ClientKeyExchange message,
this joins the paths:

.. code:: python

    join = ClientKeyExchangeGenerator()
    # join regular path:
    fork.next_sibling.add_child(join)
    # join CR path:
    node = node.add_child(join)

After that, handshake continues as usual with ChangeCipherSpec, Finished, etc.

.. note::
    When specifying alternative messages, you must take care not to allow
    message exchanges forbidden by the standards.
    Place all the messages that depend on the branch in the branch to ensure
    that (but check if using a command line switch to build different graphs
    doesn't lead to simpler test scripts).

You can find a working example of this code in
`test-fuzzed-plaintext.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-fuzzed-plaintext.py>`_.

Error handling
--------------

If you want to allow the server to abort connection while *sending* data,
use the sibling mechanism too.

To allow the server to close the connection while writing to it,
specify the :py:class:`~tlsfuzzer.expect.ExpectClose` as sibling of the node:

.. code:: python

    node = node.add_child(CertificateVerifyGenerator(private_key))
    node.next_sibling = ExpectClose()
    node = node.add_child(ChangeCipherSpecGenerator())
    node.next_sibling = ExpectClose()
    node = node.add_child(FinishedGenerator())
    node.next_sibling = ExpectClose()

Use :py:class:`~tlsfuzzer.expect.ExpectAlert` the same way.

.. note::
    Runner supports only :py:class:`~tlsfuzzer.expect.ExpectAlert` and
    :py:class:`~tlsfuzzer.expect.ExpectClose` as siblings of generator nodes.
    Since connection close triggers this path, you can read only already
    buffered messages.

You can find a working example of this code in
`test-certificate-verify-malformed-sig.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-certificate-verify-malformed-sig.py>`_.
