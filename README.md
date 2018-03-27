[![Build Status](https://travis-ci.org/tomato42/tlsfuzzer.svg?branch=master)](https://travis-ci.org/tomato42/tlsfuzzer)
[![Coverage Status](https://coveralls.io/repos/tomato42/tlsfuzzer/badge.svg?branch=master)](https://coveralls.io/r/tomato42/tlsfuzzer?branch=master)
[![Code Health](https://landscape.io/github/tomato42/tlsfuzzer/master/landscape.svg?style=flat)](https://landscape.io/github/tomato42/tlsfuzzer/master)
[![Code Climate](https://codeclimate.com/github/tomato42/tlsfuzzer/badges/gpa.svg)](https://codeclimate.com/github/tomato42/tlsfuzzer)

# tlsfuzzer
Fuzzer and test suite for TLS (SSLv2, SSLv3, v1.0, v1.1, v1.2, v1.3) implementations.
Early alpha version - thus no API stability guarantees.

## Dependencies

You'll need:

 * Python 2.6 or later or Python 3.2 or later
 * tlslite-ng 0.7.0-alpha3 or later (note that `tlslite` will *not* work and
   they conflict with eachother)
 * ecdsa python module (dependency of tlslite-ng, should get installed
   automatically with it)

Optionally, to make some calculations faster, you may want to install the
following libraries (see tlslite-ng README for details):

 * m2crypto
 * pycrypto
 * gmp

To get `pip` (if your python installation doesn't already have it) download
[get-pip.py](https://bootstrap.pypa.io/get-pip.py) and run:

```
python get-pip.py
```

Then install tlslite-ng:

```
pip install --pre tlslite-ng
```

(Use `--upgrade` if you did install it before)

Download the tlsfuzzer:

```
git clone https://github.com/tomato42/tlsfuzzer.git
```

## Usage

After all dependencies are installed, make sure:

 * you're in the directory of the project (after git clone just `cd tlsfuzzer`)
 * the server you want to test is running on the same computer (localhost)
 * the server is listening on port 4433
 * and the server will answer with data to HTTP queries (answer with valid
   HTTP responses is optional)

Then you can just run one of the tests in `scripts` directory, as such:

```
PYTHONPATH=. python scripts/test-invalid-compression-methods.py
```

If test has additional requirements, it will output them to console. No errors
printed means that all expecations were met (so for tests with bad data the
server rejected our messages).

See [USAGE.md](https://github.com/tomato42/tlsfuzzer/blob/master/USAGE.md) for
more info and how to interpret errors.

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
by the server (like in Server Key Exchange message) match the certificate
sent by the server.


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
