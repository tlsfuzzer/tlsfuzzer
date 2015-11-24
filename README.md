[![Build Status](https://travis-ci.org/tomato42/tlsfuzzer.svg?branch=master)](https://travis-ci.org/tomato42/tlsfuzzer)
[![Coverage Status](https://coveralls.io/repos/tomato42/tlsfuzzer/badge.svg?branch=master)](https://coveralls.io/r/tomato42/tlsfuzzer?branch=master)
[![Code Health](https://landscape.io/github/tomato42/tlsfuzzer/master/landscape.svg?style=flat)](https://landscape.io/github/tomato42/tlsfuzzer/master)
[![Code Climate](https://codeclimate.com/github/tomato42/tlsfuzzer/badges/gpa.svg)](https://codeclimate.com/github/tomato42/tlsfuzzer)
[![Code Issues](https://www.quantifiedcode.com/api/v1/project/58f8ffe4125b4d72a9d9337aa3ba96eb/badge.svg)](https://www.quantifiedcode.com/app/project/58f8ffe4125b4d72a9d9337aa3ba96eb)

# tlsfuzzer
Fuzzer and test suite for TLS (v1.0, v1.1, v1.2) implementations. Early alpha
version.

## Dependencies
You'll need:
 * Python 2.6 or later or Python 3.2 or later
 * tlslite-ng (note that `tlslite` will *not* work and they conflict with
   eachother)

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
pip install tlslite-ng
```

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
