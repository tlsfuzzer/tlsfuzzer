[![Build Status](https://github.com/tlsfuzzer/tlsfuzzer/workflows/GitHub%20CI/badge.svg?branch=master)](https://github.com/tlsfuzzer/tlsfuzzer/actions?query=workflow%3A%22GitHub+CI%22+branch%3Amaster)
[![Read the Docs](https://img.shields.io/readthedocs/tlsfuzzer)](https://tlsfuzzer.readthedocs.io/en/latest/)
[![Coverage Status](https://coveralls.io/repos/tlsfuzzer/tlsfuzzer/badge.svg?branch=master)](https://coveralls.io/r/tlsfuzzer/tlsfuzzer?branch=master)
[![Code Climate](https://codeclimate.com/github/tlsfuzzer/tlsfuzzer/badges/gpa.svg)](https://codeclimate.com/github/tlsfuzzer/tlsfuzzer)
[![Code Quality: Python](https://img.shields.io/lgtm/grade/python/g/tlsfuzzer/tlsfuzzer.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tlsfuzzer/tlsfuzzer/context:python)
[![Total Alerts](https://img.shields.io/lgtm/alerts/g/tlsfuzzer/tlsfuzzer.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/tlsfuzzer/tlsfuzzer/alerts)

# tlsfuzzer
tlsfuzzer is a test suite for SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, and
TLS 1.3 implementations. It's in early stages of development, so there are
no API stability guarantees. While it uses fuzzing techniques for testing
(randomisation of passed in inputs), the scripts are generally written in a
way that verifies correct error handling: unlike typical fuzzers it doesn't
check only that the system under test didn't crash, it checks that it
returned correct error messages.

You can find ready-to-use scripts testing for many vulnerabilities (
[ROBOT](https://robotattack.org/),
[DROWN](https://drownattack.com/), etc.)
and general standards conformity
([RFC 5246](https://tools.ietf.org/html/rfc5246),
[RFC 7627](https://tools.ietf.org/html/rfc7627),
[RFC 7905](https://tools.ietf.org/html/rfc7905), etc.) in the `scripts/`
directory.

## Dependencies

You'll need:

 * Python 2.6 or later or Python 3.3 or later
 * [tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng)
   0.8.0-alpha40 or later (note that `tlslite` will *not* work and
   they conflict with each other)
 * [ecdsa](https://github.com/warner/python-ecdsa)
   python module (dependency of tlslite-ng, should get installed
   automatically with it), use at least version 0.15 for optimal performance

Optionally, to make cryptographic calculations significantly faster, you may
want to install the following libraries (see tlslite-ng and python-ecdsa
README files for details):

 * m2crypto
 * gmpy

To get `pip` (if your python installation doesn't already have it) download
[get-pip.py](https://bootstrap.pypa.io/get-pip.py) and run
(or see [USAGE.md](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/USAGE.md)
for alternative configuration that does not require installation of packages):

```
python get-pip.py
```

Then install tlslite-ng:

```
pip install --pre tlslite-ng
```

(Use `--upgrade --pre` if you did install it before)

Download the tlsfuzzer:

```
git clone https://github.com/tlsfuzzer/tlsfuzzer.git
```

## Usage

After all dependencies are installed, make sure:

 * you're in the directory of the project (after git clone just `cd tlsfuzzer`)
 * the server you want to test is running on the same computer (localhost)
 * the server is listening on port 4433
 * and the server will answer with data to HTTP queries (answer with valid
   HTTP responses is optional)

Then you can run one of the tests in
[`scripts`](https://github.com/tlsfuzzer/tlsfuzzer/tree/master/scripts)
directory, like so:

```
PYTHONPATH=. python scripts/test-invalid-compression-methods.py
```

If test has additional requirements, it will output them to console. No errors
printed means that all expecations were met (so for tests with bad data the
server rejected our messages).

All scripts also accept `--help` to print the help message (specification of
all the options given script supports), `-h` to specify the hostname or
IP address of the server-to-be-tested and `-p` to specify the port of the
service to be tested.

See [USAGE.md](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/USAGE.md) for
more info and how to interpret errors and failures reported by scripts.

You can find mode detailed documentation for the project at
[tlsfuzzer.readthedocs.io](https://tlsfuzzer.readthedocs.io).

Using tlsfuzzer to test for timing side-channel attacks (Lucky13, padding
oracle attacks and timing-based Bleichenbacher oracle) is described in
the [TIMING.md](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/TIMING.md)
document.

## Server under test configuration

In general, the server under test requires just a RSA certificate, you
can create it using the following OpenSSL command:

```
openssl req -x509 -newkey rsa -keyout localhost.key -out localhost.crt -subj \
/CN=localhost -nodes -batch
```

**Note**: tlsfuzzer verifies only TLS level behaviour, it does not perform
any checks on the certificate (like hostname validation, CA signatures or
key usage). It does however verify if the signatures made on TLS message
by the server (like in Server Key Exchange or Certificiate Verify message)
match the certificate sent by the server.

More detailed instructions, including how to build the different frameworks
from source, are available in the
[Server setup](https://github.com/tlsfuzzer/tlsfuzzer/wiki/Server-setup) wiki
page.

Example server configurations:

### OpenSSL

To test OpenSSL, it's sufficient to pass an extra `-www` option to a
typical `s_server` command line:

```
openssl s_server -key localhost.key -cert localhost.crt -www
```

### GnuTLS

To test GnuTLS server, you need to tell it to behave as an HTTP server
and additionally, to not ask for client certificates:

```
gnutls-serv --http -p 4433 --x509keyfile localhost.key --x509certfile \
localhost.crt --disable-client-cert
```

### NSS

To test the Mozilla NSS library server, you first need to create a database
with server certificate:

```
mkdir nssdb
certutil -N -d sql:nssdb --empty-password
openssl pkcs12 -export -passout pass: -out localhost.p12 -inkey localhost.key \
-in localhost.crt -name localhost
pk12util -i localhost.p12 -d sql:nssdb -W ''
```

Finally, start the server with support for TLSv1.0 and later protocols, DHE
ciphers and with the above certificate:

```
selfserv -d sql:./nssdb -p 4433 -V tls1.0: -H 1 -n localhost
```

### Advanced configuration
More advanced and complex configurations as well as description how to compile
the above servers from source is available on the wiki page
[Server setup](https://github.com/tlsfuzzer/tlsfuzzer/wiki/Server-setup).

## Contributing

See the
[CONTRIBUTING.md](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/CONTRIBUTING.md)
document for description how to set up your development environment, sanity
check the changes and requirements the changes need to follow.

You may also want to read the
[VISION.md](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/VISION.md)
to learn more about the planned scope of the project.

Contributors are expected to follow the project's
[CODE OF CONDUCT](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/CODE_OF_CONDUCT.md)
when interacting with other members of the community.
