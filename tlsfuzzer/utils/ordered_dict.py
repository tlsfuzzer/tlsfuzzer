# Author: Daiki Ueno, (c) 2020
# Released under GNU GPL v2.0, see LICENSE file for details

"""Compatibility wrapper of OrderedDict."""

import sys

# Dict keeps insertion order in Python 3.7+:
# https://mail.python.org/pipermail/python-dev/2017-December/151283.html
if sys.version_info >= (3, 7):
    OrderedDict = dict
else:
    from . import _ordered_dict
    OrderedDict = _ordered_dict.OrderedDict
