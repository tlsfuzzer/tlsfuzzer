# Author: Hubert Kario, (c) Red Hat 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Helper functions for test scripts."""

from tlslite.constants import HashAlgorithm, SignatureAlgorithm, \
        SignatureScheme, GroupName

from tlslite.keyexchange import ECDHKeyExchange, FFDHKeyExchange
from tlslite.extensions import KeyShareEntry

__all__ = ['sig_algs_to_ids', 'key_share_gen']


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

    :param str names: whitespace separated list of names of hash algorithm
        names. Names can be specified as the legacy (TLS1.2) hash algorithm
        and hash type pairs (e.g. sha256+rsa), as a pair of numbers (e.g 4+1)
        or as the new TLS 1.3 signature scheme (e.g. rsa_pkcs1_sha256).
        Full string then could look like "sha256+rsa 5+rsa rsa_pss_pss_sha256"
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


def key_share_gen(group, version=(3, 4)):
    """
    Create a random key share for a group of a given id.

    :param int group: TLS numerical ID from GroupName identifying the group
    :param tuple version: TLS protocol version as a tuple, as encoded on the
        wire
    :return: KeyShareEntry
    """
    if group in GroupName.allFF:
        kex = FFDHKeyExchange(group, version)
    else:
        kex = ECDHKeyExchange(group, version)

    private = kex.get_random_private_key()
    share = kex.calc_public_value(private)
    return KeyShareEntry().create(group, share, private)
