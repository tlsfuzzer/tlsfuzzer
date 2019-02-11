# Vision for tlsfuzzer project

As the Github project's description and tags state, the main idea behind
tlsfuzzer is to be _the_ test suite and fuzzer for the TLS protocol.

That means being able to test not only if the implementation has or does not
have well known vulnerabilities, but also if it does implement the different
versions of TLS and TLS extensions correctly.
Both in isolation, and in interaction with other extensions or settings.

Because of
[combinatorial explosion](https://en.wikipedia.org/wiki/Combinatorial_explosion#Computing)
the process of testing needs to be automated to a large degree.
But at the same time, to verify that specific features are supported at all,
we need to be able to create scripts that explicitly verify support
for features.

In the mid-term we will focus on test scripts that test just few configuration
options at a time.
In future, using something like
[combinatorial coverage](https://csrc.nist.gov/Projects/Automated-Combinatorial-Testing-for-Software/Combinatorial-Coverage)
to ensure fastest discovery of most severe issue is the likely approach.

## Limitations

Wanting to be the definite test suite for TLS places few limitation on us:

* the system needs to be portable
  * needs to be runnable on different operating systems
  * needs to be runnable on different architectures (x86_64, aarch64, ppc64,
    …)
  * needs to run also on very old systems (RHEL 5 with Python 2.6 from EPEL is
    currently the oldest explicitly targeted)
  * needs not to be limited by system FIPS mode
    (implementations like OpenSSL, when running in FIPS mode disable certain
    hashes, ciphers and protocols, this must not be the case for tlsfuzzer)
* system needs to be able to run against arbitrary servers and with arbitrary
  clients
  * (for clients or servers that can not be runnable or reconfigurable using
    command line, it will require more cooperation from System Under Test)

## Medium term

Currently, the main focus is on testing servers, this will likely remain
until the system has feature partity with OpenSSL, GnuTLS and
[NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) (not to be
confused with the unix
[nss](https://en.wikipedia.org/wiki/Name_Service_Switch)).

While we are mostly focusing on newly added features, it is because they are
not "battle hardened".
In general we want 100% feature partity, irrespective if that last 1% is
a SEED cipher, or if it is ECDSA certificate support.

## Use in future

Currently the testing is performed using test scripts.
That requires either manually selecting them and running them, or using the
quite primitive `scripts_retention.py` script.

The ultimate vision for the tlsfuzzer is to have two basic modes of operation.

In first mode, the script will ask for information how to run the system under
test, how to reconfigure it to specific options and how to provide it with
specific certificates.
It will then proceed to run it with different settings, and report which
features of TLS protocol could have not been tested, asking if that lack in
coverage is ok, or how to reconfigure the server further.
This process will create a configuration file that will be then usable in
automated systems.

In second mode, tlsfuzzer will digest the file and verify if the invariants
are still met (like extensions or ciphers that are supposed to be unsupported
are unsupported, etc.).
Once this verification is ready, it will begin test proper, first verifying
basics of TLS RFC compliance, and then going into more and more obscure
configurations and error conditions, randomly selecting the modifications.
That second mode could be configured to perform either a set number of tests
or run for a specified amount of time.
Or be completely unbounded and report errors/failures as it is running.

Detection of errors server behaviour in this testing could be performed either
by using a reference implementation that is very flexible wrt. supported
features, or by implementing the full logic and understanding of TLS within
tlsfuzzer.

## Non targets

As the name suggests, the project is supposed to test TLS.
That means that values provided externally to TLS, like certificates, keys,
OCSP responses or CT binders are outside the scope of this project.

This is because the handling of them happens on a level above TLS, and
as long as the TLS specifications themselves don't specify specific behaviour,
are outside the scope of the TLS protocol.

So unless a specific feature of X.509 is necessary to support feature
in TLS (e.g. ECDSA ciphersuites require support for ECDSA certificates),
support for that feature will not be provided.
When support is provided, it will not be comprehensively tested by tlsfuzzer.
