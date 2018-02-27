# Author: Hubert Kario, (c) Red Hat 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Helper functions for test scripts."""

from tlslite.constants import HashAlgorithm, SignatureAlgorithm, \
        SignatureScheme


__all__ = ['sig_algs_to_ids']


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
