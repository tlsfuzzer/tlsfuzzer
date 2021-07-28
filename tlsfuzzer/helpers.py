# Author: Hubert Kario, (c) Red Hat 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Helper functions for test scripts."""

import time
from functools import partial
from tlslite.constants import HashAlgorithm, SignatureAlgorithm, \
        SignatureScheme, ClientCertificateType, ExtensionType

from tlslite.extensions import KeyShareEntry, PreSharedKeyExtension, \
        PskIdentity, ClientKeyShareExtension
from tlslite.handshakehelpers import HandshakeHelpers
from .handshake_helpers import kex_for_group


__all__ = ['sig_algs_to_ids', 'key_share_gen', 'psk_ext_gen',
           'psk_ext_updater', 'psk_session_ext_gen', 'flexible_getattr',
           'key_share_ext_gen', 'uniqueness_check', 'RSA_SIG_ALL',
           'ECDSA_SIG_ALL', 'RSA_PKCS1_ALL', 'RSA_PSS_PSS_ALL',
           'RSA_PSS_RSAE_ALL', 'ECDSA_SIG_TLS1_3_ALL', 'EDDSA_SIG_ALL',
           'SIG_ALL', 'AutoEmptyExtension', 'client_cert_types_to_ids']


RSA_SIG_ALL = [(getattr(HashAlgorithm, x), SignatureAlgorithm.rsa) for x in
               ['sha512', 'sha384', 'sha256', 'sha224', 'sha1', 'md5']] + [
                   SignatureScheme.rsa_pss_rsae_sha256,
                   SignatureScheme.rsa_pss_rsae_sha384,
                   SignatureScheme.rsa_pss_rsae_sha512,
                   SignatureScheme.rsa_pss_pss_sha256,
                   SignatureScheme.rsa_pss_pss_sha384,
                   SignatureScheme.rsa_pss_pss_sha512]
"""List of all RSA signature algorithms supported by tlsfuzzer,
as used in ``signature_algorithms`` or ``signature_algorithms_cert``
extensions.
"""


ECDSA_SIG_ALL = [(getattr(HashAlgorithm, x), SignatureAlgorithm.ecdsa) for x in
                 ["sha512", "sha384", "sha256", "sha224", "sha1"]]
"""List of all ECDSA signature algorithms supported by tlsfuzzer,
as used in ``signature_algorithms`` or ``signature_algorithms_cert``
extensions.
"""


RSA_PKCS1_ALL = [(getattr(HashAlgorithm, x), SignatureAlgorithm.rsa) for x in
                 ('sha512', 'sha384', 'sha256', 'sha224', 'sha1', 'md5')]
"""List of all signature algorithms that use PKCS#1 v1.5 padding."""


RSA_PSS_PSS_ALL = [SignatureScheme.rsa_pss_pss_sha512,
                   SignatureScheme.rsa_pss_pss_sha384,
                   SignatureScheme.rsa_pss_pss_sha256]
"""List of all signature algorithms that use RSA-PSS padding and have been
made with RSA-PSS key."""


RSA_PSS_RSAE_ALL = [SignatureScheme.rsa_pss_rsae_sha512,
                    SignatureScheme.rsa_pss_rsae_sha384,
                    SignatureScheme.rsa_pss_rsae_sha256]
"""List of all signature algorithms that use RSA-PSS padding and have been
made with rsaEncryption (PKCS#1) key."""


ECDSA_SIG_TLS1_3_ALL = [SignatureScheme.ecdsa_secp521r1_sha512,
                        SignatureScheme.ecdsa_secp384r1_sha384,
                        SignatureScheme.ecdsa_secp256r1_sha256]
"""
List of all ECDSA signature algorithms that can be used in TLS 1.3.

Subset of :py:const:`ECDSA_SIG_ALL`.
"""

EDDSA_SIG_ALL = [SignatureScheme.ed448,
                 SignatureScheme.ed25519]
"""
List of all EdDSA signature algorithms that can be used in TLS 1.2 and later.
"""


SIG_ALL = RSA_PSS_PSS_ALL + RSA_PSS_RSAE_ALL + RSA_PKCS1_ALL + ECDSA_SIG_ALL +\
    EDDSA_SIG_ALL
"""List of all signature algorithms supported by tlsfuzzer,
as used in ``signature_algorithms`` or ``signature_algorithms_cert`` extension.

For now includes only RSA, ECDSA and EdDSA algorithms, will include DSA
algorithms later on.

Sorted in order of strongest to weakest hash.
"""


def _hash_name_to_id(h_alg):
    """Try to convert hash algorithm name to HashAlgorithm TLS ID.

    accepts also a string with a single number in it
    """
    try:
        return int(h_alg)
    except ValueError:
        return getattr(HashAlgorithm, h_alg)


def _sign_alg_name_to_id(s_alg):
    """Try to convert signature algorithm name to SignatureAlgorithm TLS ID.

    accepts also a string with a single number in it
    """
    try:
        return int(s_alg)
    except ValueError:
        return getattr(SignatureAlgorithm, s_alg)


def sig_algs_to_ids(names):
    """Convert a string with signature algorithm names to list of IDs.

    :type names: str
    :param names: whitespace separated list of names of hash algorithm
        names. Names can be specified as the legacy (TLS1.2) hash algorithm
        and hash type pairs (e.g. ``sha256+rsa``), as a pair of numbers (e.g
        ``4+1``) or as the new TLS 1.3 signature scheme (e.g.
        ``rsa_pkcs1_sha256``).
        Full parameter string then can look like: ``sha256+rsa 5+rsa
        rsa_pss_pss_sha256``.
    :raises AttributeError: when the specified identifier is not defined in
        HashAlgorithm, SignatureAlgorithm or SignatureScheme
    :return: list of tuples
    """
    ids = []

    for name in names.split():
        if '+' in name:
            h_alg, s_alg = name.split('+')

            hash_id = _hash_name_to_id(h_alg)
            sign_id = _sign_alg_name_to_id(s_alg)

            ids.append((hash_id, sign_id))
        else:
            ids.append(getattr(SignatureScheme, name))

    return ids


def _ext_name_to_id(name):
    """
    Convert a string with a name of extension to numerical ID.

    Handles both numerical IDs and names.

    :raises AttributeError: when the specified identifier is not defined
        in ExtensionType
    """
    try:
        return int(name)
    except ValueError:
        return getattr(ExtensionType, name)


def ext_names_to_ids(names):
    """
    Convert a string with names of extensions to list of IDs.

    :type names: str
    :param names: whitespace separated list of names of extension types.
        Names can be specified either as full names (``server_name``) or
        as numerical IDs (``0``).

    :raises AttributeError: when the specified identifier is not defined
        in ExtensionType
    :rtype: list of int
    """
    ids = []
    for name in names.split():
        ids.append(_ext_name_to_id(name))

    return ids


def client_cert_types_to_ids(names):
    """
    Convert a string with client certificate method names to list of IDs.

    :type names: str
    :param names: whitespace separated list of names of client certificate
        types (used in CertificateRequest message in TLS 1.2 and earlier).
        Identifiers can be names (e.g. ``rsa_sign``), or integers (e.g. ``1``
        instead of ``rsa_sign``).
    :raises AttributeError: when the specified identifier is not defined in
        :py:class:`ClientCertificateType`
    :rtype: list of int
    """
    ids = []
    for name in names.split():
        try:
            ids.append(int(name))
        except ValueError:
            ids.append(getattr(ClientCertificateType, name))

    return ids


def key_share_ext_gen(groups):
    """
    Generator of key_share extension.

    Generator that can be used to delay the generation of key shares for
    TLS 1.3 ClientHello.

    :type groups: list
    :param groups: TLS numerical IDs from GroupName identifying groups
       that should be present in the extension or ready to use KeyShareEntries.
    :rtype: callable
    """
    def _key_share_ext_gen(state, groups=groups):
        del state
        gen_groups = []
        for g_id in groups:
            if isinstance(g_id, KeyShareEntry):
                gen_groups.append(g_id)
                continue
            gen_groups.append(key_share_gen(g_id))
        return ClientKeyShareExtension().create(gen_groups)
    return _key_share_ext_gen


def key_share_gen(group, version=(3, 4)):
    """
    Create a random key share for a group of a given id.

    :type group: int
    :param group: TLS numerical ID from GroupName identifying the group
    :type version: tuple
    :param version: TLS protocol version as a tuple, as encoded on the
        wire
    :rtype: `tlslite.extensions.KeyShareEntry`
    """
    kex = kex_for_group(group, version)
    private = kex.get_random_private_key()
    share = kex.calc_public_value(private)
    return KeyShareEntry().create(group, share, private)


def _get_psk_config_hash(psk_settings):
    sett_len = len(psk_settings)

    if sett_len == 2:
        psk_hash = "sha256"
    elif sett_len == 3:
        psk_hash = psk_settings[2]
    else:
        raise ValueError("Invalid number of options in PSK config")

    if psk_hash not in ("sha256", "sha384"):
        raise ValueError("Supported hashes are 'sha256' and 'sha384' only")

    return psk_hash


def psk_ext_gen(psk_settings):
    """
    Create a PreSharedKeyExtension from given settings.

    Takes a list of 2 or 3-element tuples, where the first element is an
    identity name, the second is the shared secret and the third is the name
    of the associated hash (``sha256` or ``sha384``, with ``sha256`` being the
    default). The names and shared secrets need to be bytes-like objects.

    :type psk_settings: list
    :param psk_settings: list of tuples
    :return: extension
    """
    identities = []
    binders = []

    for config in psk_settings:
        if not config[0]:
            raise ValueError("identity can't be an empty string")

        identities.append(PskIdentity().create(config[0], 0))

        psk_hash = _get_psk_config_hash(config)

        binders.append(bytearray(32 if psk_hash == 'sha256' else 48))

    return PreSharedKeyExtension().create(identities, binders)


def _psk_session_ext_gen(state, psk_settings):
    ident = []
    binder = []
    if psk_settings:
        ext = psk_ext_gen(psk_settings)
        ident = list(ext.identities)
        binder = list(ext.binders)

    if not state.session_tickets:
        raise ValueError("No New Session Ticket messages in session")
    nst = state.session_tickets[-1]

    # nst.time is fractional but ticket time should be in ms, not s as the
    # NewSessionTicket.time is
    ticket_time = int(time.time() * 1000 - nst.time * 1000 +
                      nst.ticket_age_add) % 2**32
    ticket_iden = PskIdentity().create(nst.ticket, ticket_time)
    binder_len = state.prf_size

    ident.insert(0, ticket_iden)
    binder.insert(0, bytearray(binder_len))

    return PreSharedKeyExtension().create(ident, binder)


def psk_session_ext_gen(psk_settings=None):
    """
    Generator that uses last New Session Ticket to create PSK extension.

    Can optionally take a list of tuples that define static PSKs that will
    be added after the NST PSK.
    See :py:func:`psk_ext_gen` for description of their
    format.

    :type psk_settings: list
    :param psk_settings: list of tuples
    :return: extension generator
    """
    return partial(_psk_session_ext_gen, psk_settings=psk_settings)


def _psk_ext_updater(state, client_hello, psk_settings):
    h_hash = state.handshake_hashes
    nst = None
    if state.session_tickets:
        nst = state.session_tickets[-1]
    HandshakeHelpers.update_binders(
        client_hello,
        h_hash,
        psk_settings,
        [nst] if nst else None,
        state.key['resumption master secret'] if nst else None)


def psk_ext_updater(psk_settings=tuple()):
    """
    Uses the provided settings to update the PSK binders in CH PSK extension.

    Generator that can be used to generate the callback for the
    ClientHelloGenerator.modifiers setting.

    See :py:func:`psk_ext_gen` for a specification of ``psk_settings``.

    This updater requires that the PSK extension be the last one in
    ClientHello.

    Please note that if the ClientHello is subsequently modified (either by
    modifiers placed after this one or generic message fuzzers) after this
    updater was run, the binders it has created will likely become invalid.
    This is because the binders sign (using an HMAC) the whole ClientHello
    message, including the handshake protocol header (the one byte handshake
    type and the 3-byte length), but excluding other binders.
    """
    return partial(_psk_ext_updater, psk_settings=psk_settings)


def flexible_getattr(val, val_type):
    """Convert a string of number, name, or None to object.

    If the :py:attr:`val` is a number, return a number, when it's a string
    like ``none`` return ``None`` object.
    When it's a string representing one of the fields in provided type, return
    that value.
    """
    if val in ("None", "none", "NONE"):
        return None
    try:
        return int(val)
    except ValueError:
        return getattr(val_type, val)


def _is_hashable(val):
    """Check if val is hashable."""
    try:
        hash(val)
    except TypeError:
        return False
    return True


def uniqueness_check(values, count):
    """
    Check if values in the lists in the dictionary are unique.

    Also check if all the arrays have the length of :py:attr:`count`.

    :param values: dictionary of lists to check
    :type count: int
    :param count: expected length of lists
    :return: list of errors found
    """
    ret = []
    for name, array in values.items():
        if len(array) != count:
            ret.append("Unexpected number of values in '{0}'. Expected: {1}, "
                       "got: {2}.".format(name, count, len(array)))
        # FFDHE key shares in TLS 1.2 are stored as ints and they are not
        # convertible to "bytes" directly, so we need to treat them specially
        if array and _is_hashable(array[0]):
            if len(set(array)) != len(array):
                ret.append("Duplicated entries in '{0}'.".format(name))
        else:
            if len(set(bytes(i) for i in array)) != len(array):
                ret.append("Duplicated entries in '{0}'.".format(name))
    return ret


class AutoEmptyExtension(object):
    """
    Identifier used to tell ClientHelloGenerator to create empty extension.
    """

    def __new__(cls):
        """Return a singleton object."""
        if not hasattr(cls, 'instance') or not cls.instance:
            cls.instance = object.__new__(cls)
        return cls.instance


def protocol_name_to_tuple(name):
    """
    Translate human readable protocol name ("TLSv1.0") to a tuple representing
    on the wire protocol version ((3, 1)).

    :raises ValueError: the string was not recognised as a protocol name
    """
    names = {"sslv2": (0, 2),
             "ssl2": (0, 2),
             "sslv3": (3, 0),
             "ssl3": (3, 0),
             "tlsv1.0": (3, 1),
             "tls1.0": (3, 1),
             "tlsv1.1": (3, 2),
             "tls1.1": (3, 2),
             "tlsv1.2": (3, 3),
             "tls1.2": (3, 3),
             "tlsv1.3": (3, 4),
             "tls1.3": (3, 4)}
    val = names.get(name.lower())
    if val:
        return val
    raise ValueError("Unrecognised protocol name: {0}".format(name))


def expected_ext_parser(names):
    """
    Convert a string with names of extensions and messages to a dict.

    extension are separated by whitespace, the messages are separated by
    colons ":". Extension can be specified by name ("status_request") or by
    number ("5"). If the name is invalid, the function will raise
    AttributeError. The supported message names are: CH, SH, EE, CT, CR, NST
    and HRR.
    """
    ret = {'CH': [],
           'SH': [],
           'EE': [],
           'CT': [],
           'CR': [],
           'NST': [],
           'HRR': []}

    for ext_spec in names.split():
        params = ext_spec.split(':')
        if len(params) < 2:
            raise ValueError("Invalid message specification for extension: "
                             "{0}".format(ext_spec))
        ext_id = _ext_name_to_id(params[0])
        for msg_id in params[1:]:
            if msg_id not in ret:
                raise ValueError("Error while parsing data for extension {0}: "
                                 "the '{1}' message name is unknown.".format(
                                     params[0], msg_id))
            ret[msg_id].append(ext_id)

    return ret


def dict_update_non_present(d, keys, value=None):
    """
    Update the dict d using keys, setting them to value, if the key is missing.

    Will update the dictionary only if the given key is not already present
    in dictionary, will raise ValueError when it is.

    if keys are None, returns unmodified d.
    If d is None, allocates and returns a new dictionary otherwise returns the
    modified dictionary d.
    """
    if keys is None:
        return d
    if d is None:
        d = {}
    for k in keys:
        if k in d:
            raise ValueError("Key '{0}' already present in dictionary"
                             .format(k))
        d[k] = value
    return d
