# Author: Daiki Ueno, (c) 2020
# Released under GNU GPL v2.0, see LICENSE file for details

"""Compatibility wrapper of OrderedDict."""

import sys

# Use dict() as OrderedDict in Python 3.8+, as it suffices our use of
# ordered dictionaries. The relevant changes are:
# - "Dict keeps insertion order in Python 3.7+":
#   https://mail.python.org/pipermail/python-dev/2017-December/151283.html
# - "reversible dict":
#   https://bugs.python.org/issue33462
if sys.version_info >= (3, 8):
    OrderedDict = dict
else:
    from . import _ordered_dict
    OrderedDict = _ordered_dict.OrderedDict
