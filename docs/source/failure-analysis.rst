================
Failure analysis
================

As the scripts in ``tlsfuzzer`` expect very specific behaviour from the server
not all failures and errors reported by the script necessarily mean that the
server is buggy.

Note that those are just some of the tips, and this article is far from
complete.
To understand the failures and analyse them you will likely need to have
a deep understanding of the TLS protocol.
Remember to first understand what is happening and why it's happening
before dismissing test failure as "irrelevant" or a "false positive".
Also, when investigating, don't be afraid to edit the test scripts:
they're intentionally written with little code reuse to make that process
easy and contained.

Execution summary
=================

All scripts print the following summary after execution:

.. code::

    Test end
    ====================
    version: 8
    ====================
    TOTAL: 2
    SKIP: 0
    PASS: 2
    XFAIL: 0
    FAIL: 0
    XPASS: 0
    ====================

The ``version`` field is self-explanatory, it's the version number of the
script.
Every time the script is modified in a way that its execution *may*
change, that version number is incremented.

The ``TOTAL`` is the number of conversations executed by the script.
While typically "conversations" is equivalent to "connections", in case the
script is testing session resumption, the actual number of connections
can be larger.

The ``SKIP`` is the number of conversations that were excluded from execution
through the use of the ``-e`` command line option.

The ``PASS`` is the number of conversations in which the server behaved
in expected manner (either the connection was successful when we expected
success or the server correctly detected a malformed message when we
sent one).

The ``XFAIL`` is the number of conversations that *eXpectedly FAILed*.
That is, the number of conversations that were specified with the ``-x`` option
and subsequently failed (without the specific error message, or
with the exact error message specified with the ``-X`` option).

The ``FAIL`` is the number of conversations in which the server behaved
in unexpected manner (refused the connection when we expected a
successful handshake, didn't error out when we sent malformed messaged, etc.).

The ``XPASS`` is the number of conversations that *unXepectedly PASSed*.
That is, the conversations that were specified with the ``-x`` option but
didn't fail.

Those names are taken from the ``pytest`` project and have the same
meaning there.

The overall script will return a non-zero exit code if either the ``FAIL``
or the ``XPASS`` count is more than zero.

Failure in sanity
=================

For the overall test to be valid in the first place, we need to establish
a baseline: verify that we can connect to the server and that we can
perform a basic handshake, exchange some data, and perform an orderly
connection shutdow.

This is done by the ``sanity`` conversations inside the scripts.

For example, if the script is testing that the server is rejecting
malformed ClientHello messages, we first need to verify that it will
accept a non-malformed message first: that happens in the the ``sanity``
case.
If that one doesn't pass, we may not be testing the ClientHello parser at
all, as the server may be rejecting the connection because of the advertised
ciphersuite by the client, not anything else.

Now, since we want to detect wrong behaviour from the server,
the scripts are fairly strict with the expected behaviour in the ``sanity``
case.
In particular, the *number* of ApplicationData packets expected as the
reply to the HTTP GET request is exactly one.
This is to detect situations in which the server sends each line of
reply in single ApplicationData record (very bad),
or a situation in which an HTTP server sends headers and body of the
response in separate records (bad, as that leaks the exact size of both,
which can have privacy consequences).

That of course means that you generally can't execute the scripts against
servers that reply with a large web page that doesn't fit into a single
TLS ApplicationData record (at least, not without modifying the scripts).
It's also like that, as some servers prefer to fragment the response
to smaller records, ones that fit into MTU (to improve latency), while
others will happily send records of maximum size and as few of them as
possible.
What is the expected behaviour for a particular server is not something
we should specify for each and every test script, so they expect
one and only one record as the response (though there are scripts that
test large responses specifically, like the ``test-record-size-limit.py``).
