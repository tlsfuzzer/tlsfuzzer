#!/usr/bin/env python

# Author: Hubert Kario
# Released under Gnu GPL v2.0, see LICENSE file for details

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name="tlsfuzzer",
      author="Hubert Kario",
      author_email="hkario@redhat.com",
      url="https://github.com/tlsfuzzer/tlsfuzzer",
      description="TLS test suite and fuzzer.",
      license="GPLv2",
      install_requires=["ecdsa >= 0.15", "tlslite-ng >= 0.8.2"],
      extras_require={
          "analysis": [
              # Additionally to `tlsfuzzer.analysis`, this also satisfies the
              # following apps:
              # test_bleichenbacher_timing_marvin
              # test_lucky13
              # test_tls13_minerva
              # test_bleichenbacher_timing_pregenerate
              "matplotlib",
              "numpy",
              "pandas",
              "scipy",
          ],
          "execution": [
              "zstd",  # test_tls13_client_certificate_compression
          ],
          "extraction": [
              # Additionally to `tlsfuzzer.analysis`, this partially satisfies
              # the following apps:
              # test_bleichenbacher_timing_marvin
              # test_lucky13
              # test_tls13_minerva
              # test_bleichenbacher_timing_pregenerate
              "dpkt",
              "numpy",
              "pandas",
          ],
      },
      packages=["tlsfuzzer", "tlsfuzzer.utils"])
