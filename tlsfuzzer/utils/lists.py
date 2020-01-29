# Author: Hubert Kario, (c) 2017
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Utility functions for lists."""

import re


def natural_sort_keys(key, _nsre=re.compile('([0-9]+)')):
    """
    Split the key into a sortable list for the :py:func:`sorted` builtin.

    Natural sort sorts words using dictionary order and numbers using
    numerical order, so ``ab20`` will be placed before ``ab100``.

    Used with :py:func:`sorted` like this:

    .. code-block:: python

      a = dict()
      b = sorted(a, key=natural_sort_keys)

    :param key: key used for sorting

    :rtype: list
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(_nsre, key)]
