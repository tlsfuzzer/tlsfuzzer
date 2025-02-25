#!/usr/bin/env python

# Author: Hubert Kario
# Released under Gnu GPL v2.0, see LICENSE file for details

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name="tlsfuzzer",
      version="0.0.1",
      author="Hubert Kario",
      author_email="hkario@redhat.com",
      url="https://github.com/tlsfuzzer/tlsfuzzer",
      description="TLS test suite and fuzzer.",
      license="GPLv2",
      install_requires=["ecdsa >= 0.15", "tlslite-ng >= 0.8.2"],
      packages=["tlsfuzzer", "tlsfuzzer.utils"])
