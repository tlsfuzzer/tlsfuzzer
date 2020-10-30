====================
Message manipulation
====================

Tlsfuzzer provides facilities to modify messages and records before sending,
use them to create malformed messages.
You can apply the modifiers on generator nodes, the ones that send messages
to the peer.

Custom message generation
=========================

Tlsfuzzer provides support for sending arbitrary messages over established
connections.
It provides two nodes to achieve it: one to send messages unencrypted and
one to send them using the current connection status.

Creating unencrypted messages
-----------------------------

To send a record with a specific payload and type, irrespective of
active encryption or negotiated fragmentation, use
:py:class:`~tlsfuzzer.messages.PlaintextMessageGenerator`.
It accepts two parameters to specify data sent to the other
peer (``content_type`` and ``data``) as well as one
used for debugging: ``description``, printed when sending of the message
failed.

.. note::
    As it skips all the usual message processing steps, it also doesn't
    update handshake hashes so values calculated for Finished and connection
    secrets in :term:`TLS` 1.3 won't match expected ones.

For example, to send an empty ClientHello message, write:

.. code:: python

    node = node.add_child(PlaintextMessageGenerator(
        ContentType.handshake,
        bytearray(b'\x01\x00\x00\x00')))

You can find a usage example in:
`test-aesccm.py <https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-aesccm.py>`_.

.. tip::
    If you want to send an otherwise valid message, only as plaintext, not
    encrypted, see the :ref:`clearing-encryption-settings` section.

To write directly to the socket, without record layer encapsulation,
use the :py:class:`~tlsfuzzer.messages.RawSocketWriteGenerator`.
It accepts two parameters, one to specify the data to write and another,
optional, used for debugging, the ``description``.

Creating arbitrary messages
---------------------------

To send messages with a specific payload and type, while using encryption
and record layer fragmentation, use
:py:class:`~tlsfuzzer.messages.RawMessageGenerator`.

It accepts two parameters that specify data sent to the other side
(``content_type`` and ``data``) and one that stores message to print if
processing of the message fails: ``description``.

For example, to send an empty Finished message, write:

.. code:: python

    node = node.add_child(RawMessageGenerator(
        ContentType.handshake,
        bytearray(b'\x14\x00\x00\x00')

You can find a usage example in:
`test-invalid-content-type.py <https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-invalid-content-type.py>`_.


Modifying messages
==================

Tlsfuzzer supports applying two operations to sent messages: modifying
length and modifying contents of specific bytes.

Modifying length
----------------

Handshake messages include an internal header that identifies the message
type and message length.
Two methods can change their payload while modifying the header to match.

The :py:func:`~tlsfuzzer.messages.pad_handshake` function adds data at the
end of payload. The ``size`` param specifies how many bytes and
the ``pad_byte`` parameter specifies the value of the added bytes.

In the other calling convention, it accepts literal bytes to add to the payload
by using the ``pad`` keyword argument.

For example, to add 10 bytes of value 0 at the end of ClientHello, write:

.. code:: python

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    exts = {ExtensionType.renegotiation_info: None}
    msg_gen = ClientHelloGenerator(cipihers, extensions=exts)
    node = node.add_child(pad_handshake(msg_gen, 10))

You can find a usage example in:
`test-truncating-of-client-hello.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-truncating-of-client-hello.py>`_.

If you want to remove bytes from the end of a message, you can either
specify a negative ``size`` or use the
:py:func:`~tlsfuzzer.messages.truncate_handshake` function.

.. note::

    The sender can format ClientHello in two ways: with and without extensions.
    A ClientHello with an empty list of extensions differs from one without
    extensions by two zero bytes (they encode the length of the extensions).
    Thus adding 2 zero bytes to an extensions-less ClientHello or removing
    enough bytes from a ClientHello with extensions to turn it into one
    without extensions can cause the
    :py:func:`~tlsfuzzer.messages.pad_handshake` to create a well-formed
    message, despite modifying it.

Modifying content
-----------------

The :py:func:`~tlsfuzzer.messages.fuzz_message` supports changing arbitrary
parts of sent messages.

Both optional parameters of the function, ``substitutions`` and ``xors`` expect
a dictionary as value.
The keys of the dictionary specify the bytes to change.
To specify the bytes counting from the end of the message use negative numbers.

For example, to change the type of a ClientHello message to that of ServerHello
use the following code:

.. code:: python

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    exts = {ExtensionType.renegotiation_info: None}
    msg_gen = ClientHelloGenerator(cipihers, extensions=exts)
    node = node.add_child(fuzz_message(msg_gen,
                                       {0: HandshakeType.server_hello}))

You can find a usage example in:
`test-invalid-client-hello.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-invalid-client-hello.py>`_.

Modifying records
=================

The :term:`TLS` protocol specifies four types of encrypted records:
ones that use stream encryption, ones that use block encryption in
:term:`MAC` then encrypt mode, ones that use block encryption in encrypt then
:term:`MAC` mode, and ones that use :term:`AEAD` ciphers.
Each of them behaves differently on the record layer level, thus modifying the
intermediate ciphertext requires the use of different functions.

Fuzzing the MAC
---------------

To change the authentication tag you need to use different functions depending
on which cipher suite and extensions have been negotiated.

For ciphers that use :term:`HMAC` you can change the authentication tag using
the :py:func:`~tlsfuzzer.messages.fuzz_mac` function.

.. note::

    :py:func:`~tlsfuzzer.messages.fuzz_mac` works with stream ciphers and
    block ciphers in :term:`CBC` mode only. It doesn't work for SSLv2
    connections though.

You use :py:func:`~tlsfuzzer.messages.fuzz_mac` the same way as you use
:py:func:`~tlsfuzzer.messages.fuzz_message`: pass the message to change as the
first argument and use the other two to specify the bytes to either xor or
substitute.

Use the following code to invert the first and last bit of the :term`HMAC` in
a record with a Finished message:

.. code:: python

    msg_gen = FinishedGenerator()
    xors = {0: 0x80, -1: 0x01}
    node = node.add_child(fuzz_mac(msg_gen, xors=xors))

You can find a usage example in:
`test-fuzzed-MAC.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-fuzzed-MAC.py>`_.

Since both :term:`AEAD` cipher suites and :term:`CBC` cipher suites in "encrypt
then :term:`MAC`\ " mode don't encrypt the authentication tag, you can use the
:py:func:`~tlsfuzzer.messages.fuzz_encrypted_message` function to change it.
As it allows modification of any part of encrypted message, not just the tag,
you need to know the size of the authentication tag to change the first byte
of it though.

.. hint::

    :term:`AES-CCM8` uses tags 8 bytes long.
    :term:`AES-GCM`, Chacha20-Poly1305, :term:`AES-CCM` and MD5-HMAC use tags
    16 bytes long.
    SHA1-HMAC uses tags 20 bytes long.
    SHA256-HMAC uses tags 32 bytes long.
    SHA384-HMAC uses tags 48 bytes long

Use the following code to invert the first and last bit of authentication tag
in a record with a Finished message in an :term:`AES-GCM` connection:

.. code:: python

    msg_gen = FinishedGenerator()
    xors = {-17: 0x80, -1: 0x01}
    node = node.add_child(fuzz_encrypted_message(msg_gen, xors=xors))

You can find a usage example in:
`test-chacha20.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-chacha20.py>`_.

Tlsfuzzer can go as far as changing the whole plaintext
right before encryption, this can change the :term:`HMAC` for :term:`CBC`
mode ciphers working in "encrypt then :term:`MAC`\ " mode.
Use the :py:func:`~tlsfuzzer.messages.replace_plaintext` function for that.

.. hint::

    The length of the replacement plaintext must be a multiple of cipher's
    block size: 8 bytes for 3DES and 16 bytes for other ciphers.

For example, to create a record with a plaintext with all bytes of the
:term:`IV` set to 1 (assuming :term:`AES` cipher), all bytes of the payload
set to 2, all bytes of the authentication tag set to 3 (assuming
SHA1-\ :term:`HMAC`),
and a zero-length padding, use the following code:

.. code:: python

    iv_bytes = bytearray([1]*16)
    payload_bytes = bytearray([2]*11)
    mac_bytes = bytearray([3]*20)
    pad_bytes = bytearray(b'\x00')
    new_plaintext = iv_bytes + payload_bytes + mac_bytes + pad_bytes
    assert len(new_plaintext) % 16 == 0
    msg_gen = FinishedGenerator()
    node = node.add_child(replace_plaintext(msg_gen, new_plaintext))

You can find a usage example in:
`test-fuzzed-plaintext.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-fuzzed-plaintext.py>`_.

While you can use the :py:func:`~tlsfuzzer.messages.fuzz_plaintext` function
to change the :term:`MAC`, you need to know the length of padding to know
where :term:`MAC` begins and ends in the plaintext.

Fuzzing the padding
-------------------

The :term:`CBC` mode ciphers require input with length that's a multiple
of the cipher block size. Since stream ciphers and :term:`AEAD` ciphers
dont't require that, :term:`TLS` 1.2 and earlier doesn't define padding for
them.

As a single byte encodes the length of the padding, 255 bytes is the max length
(256 bytes including the byte encoding length).

:term:`TLS` 1.3 defines padding differently, it combines it with
content type specification for record payload, thus the max record
length (2\ :sup:`14` or 16384 bytes) defines max padding.

The :py:func:`~tlsfuzzer.messages.fuzz_padding` function can change the
padding used by :term:`CBC` cipher suites.

For example, to negate the last byte of padding of a record with Finished
message (while ensuring non-zero length padding), use the following code:

.. code:: python

    msg_gen = FinishedGenerator()
    node = node.add_child(fuzz_padding(msg_gen, min_length=1,
                                       xors={-2: 0xff}))

You can find a usage example in:
`test-fuzzed-padding.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-fuzzed-padding.py>`_.

While you can use the :py:func:`~tlsfuzzer.messages.fuzz_plaintext` function
to change the padding, it doesn't support specifying the min length
for the padding.

TLS 1.3 padding length
----------------------

tlsfuzzer supports changing the padding in sent records through a callback
mechanism.
The :py:class:`~tlsfuzzer.messages.SetPaddingCallback` node sets the
callback for calculating the padding size.
It includes two factory methods and one ready to use callback.

For example, to make all records send max supported padding in the connection,
use the following code:

.. code:: python

    node = node.add_child(
        SetPaddingCallback(SetPaddingCallback.fill_padding_cb))

You can find a usage example in:
`test-tls13-record-layer-limits.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-tls13-record-layer-limits.py>`_.

Sending too big records
-----------------------

The :term:`TLS` protocol specifies the max length of payload at 2\ :sup:`14`
bytes.
To send records with larger payload use
:py:class:`~tlsfuzzer.messages.SetMaxRecordSize` to increase that limit.

.. note::

    This increases the max length of *payload*. With active encryption,
    records include :term:`IV`, :term:`MAC` and padding or :term:`AEAD` tag,
    making them at least 16 bytes larger.

.. warning::

    The :term:`TLS` protocol specifies the length in record header as two
    bytes, as such, records larger than 2\ :sup:`16`\ - 1 or 65535 bytes
    have no physical representation and tlsfuzzer doesn't support sending them.
    :term:`IV`, padding and authentication tag increase the size of record
    compared to the payload by at least 16 bytes and at most by 276 bytes.

With this limit unmodified, the record layer fragments a 16385 byte message
into two records.

For example, to send an ApplicationData record 1 byte larger than the
:term:`TLS` specified limit, use the following code:

.. code:: python

    node = node.add_child(SetMaxRecordSize(2**16-1))  # "unlimited"
    node = node.add_child(ApplicationDataGenerator(bytearray(b'A' * 16385)))

You can find a usage example in:
`test-record-size-limit.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-record-size-limit.py>`_.


Message fragmentation
=====================

Tlsfuzzer provides methods to control fragmentation and sending of the
messages.

Splitting messages
------------------

To send one higher level message in more than one record, you can use
:py:func:`~tlsfuzzer.messages.split_message`,
:py:class:`~tlsfuzzer.messages.PopMessageFromList`, and
:py:class:`~tlsfuzzer.messages.FlushMessageList`.

The :py:func:`~tlsfuzzer.messages.split_message` requires a :py:func:`list`
object to pass the created fragments to the other two nodes.
It sends the first fragment at that point.
:py:class:`~tlsfuzzer.messages.PopMessageFromList` takes one fragment from
the list and sends it.
:py:class:`~tlsfuzzer.messages.FlushMessageList` takes all remaining fragments
from the list and sends them in one record.
If a message has a post-send action, they execute it after sending the last
fragment.

For example, to send a ClientHello in two records, the first of 2 bytes length,
use the following code:

.. code:: python

    ciphres = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    msg_gen = ClientHelloGenerator(ciphers)
    fragment_list = []
    node = node.add_child(split_message(msg_gen, fragment_list, 2))
    node = node.add_child(FlushMessageList(fragment_list))

You can find a usage example in:
`test-large-hello.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-large-hello.py>`_.
