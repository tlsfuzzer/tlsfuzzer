# How to contribute

## Preparation for contributing

* You need a [GitHub account](https://github.com/signup/free)
* Submit an [issue ticket](https://github.com/tlsfuzzer/tlsfuzzer/issues) for
  your issue if there is none yet
  * Describe the issue and include steps to reproduce if it's a bug, mention
    the earliest version that you know is affected and the version you're using.
  * Describe the enhancement and your general ideas on how to implement it
    if you want to add new feature or extend existing one. This is not
    necessary if the change is small.
* If you are able and want to fix the issue, fork the repository on GitHub and
  see [Developing changes](#developing-changes) section

## Ways to contribute

* Look for issues in the
  [projects](https://github.com/tlsfuzzer/tlsfuzzer/projects) page.
  [TLS 1.3 coverage](https://github.com/tlsfuzzer/tlsfuzzer/projects/1) is the
  highest priority project now.
* Look for
  [open issues](https://github.com/tlsfuzzer/tlsfuzzer/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22),
  ones that have
  [maintenance](https://github.com/tlsfuzzer/tlsfuzzer/issues?q=is%3Aissue+is%3Aopen+label%3Amaintenance)
  label and/or
  [good first issue](https://github.com/tlsfuzzer/tlsfuzzer/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
  are good choices
* Report ideas for
  [new test scripts](https://github.com/tlsfuzzer/tlsfuzzer/issues/new?template=New_test_script.md)
  to verify TLS implementations with
* Run static code analyses on tlsfuzzer, report issues they found
  * Integrate them into CI or development scripts
  * [yala](https://github.com/cemsbr/yala) may be a good place to start
* Extend documentation (including this file!) or wiki
  * document how to set up and run tlsfuzzer on Windows or OSX

## Developing changes

### TL;DR

1. [Fork it](https://github.com/tlsfuzzer/tlsfuzzer/fork)
1. Clone it
  * `git clone git@github.com:<your-github-nick>/tlsfuzzer.git`
  * `cd tlsfuzzer`
1. Install dependencies (as root)
  * `pip2 install coverage ecdsa Sphinx sphinx-rtd-theme unittest2 mock`
  * `pip3 install coverage ecdsa`
  * `pip2 install -r build-requirements.txt`
  * `pip3 install -r build-requirements.txt`
1. Download tlslite-ng
  * `git clone https://github.com/tlsfuzzer/tlslite-ng.git .tlslite-ng`
  * `ln -s .tlslite-ng/tlslite tlslite`
1. Verify installation
  * `make test`
1. Create your feature branch (`git checkout -b my-new-feature`)
1. Write changes, follow Python standard guidelines, include test cases
1. Run tests (`make test`)
1. Commit your changes (`git commit -am 'Add some feature'`)
1. Push to the branch upstream (`git push origin my-new-feature`)
1. Create new
   [Pull Request](https://github.com/tlsfuzzer/tlsfuzzer/pull/new/master)

### Technical requirements

To be able to work on the code you will need few pieces of software installed.
The most important is the `python` interpreter. Some development dependencies
have additional restrictions on the versions used, so I recommend using Python
2.7 and Python 3.4 as the lowest versions (see
[`.travis.yml`](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/.travis.yml)
if you want to setup development environment on different versions).
[Git client](https://git-scm.com/), [make](https://www.gnu.org/software/make/)
(though likely other `make` implementions will work too, scripts for
Windows are [planned](https://github.com/tlsfuzzer/tlsfuzzer/issues/22)),
text editor and ability to install local python packages (ability to run
`pip`).

The list goes as follows:

* python (2.7 and 3.4)
* git
* GNU make
* pip
* sphinx
* tlslite-ng

The python module dependencies are as follows:

* unittest (unittest2 on Python 2; should be part of Python 3 install)
* mock (should be part of Python 3 distribution of unittest)
* ecdsa
* pylint
* diff_cover
* coverage
* hypothesis
* enum34 (for Python2, in case of new hypothesis package)

On Fedora they can be installed using:

```
dnf install python2-ecdsa python3-ecdsa pylint python3-pylint \
    python2-diff-cover python3-diff-cover python2-coverage python3-coverage \
    python2-hypothesis python3-hypothesis python3-libs python2-unittest2 \
    python2-mock
```

On RHEL 7 you will need to enable [EPEL](https://fedoraproject.org/wiki/EPEL),
and install [pip](https://pip.pypa.io/en/stable/installing/) for Python3,
after which you can install the dependencies using:

```
yum install python-ecdsa python34-ecdsa pylint \
    python-coverage python34-coverage python2-hypothesis \
    python34-libs python-unittest2 python-mock python-pip
pip2 install diff-cover
pip3 install hypothesis diff-cover pylint
```

Optional module dependencies:

* tackpy
* m2crypto
* pycrypto
* gmpy

On Fedora they can be installed using:

```
pip install tackpy
dnf install m2crypto python3-m2crypto python2-crypto python3-crypto \
    python2-gmpy2 python3-gmpy2
```

#### Virtual environment

While the above descriptions ask for installing the packages system-wide, it's
possible to install python packages without root permissions, that does
require use of package like
[`virtualenv`](https://virtualenv.pypa.io/en/stable/) or the
[`venv`](https://docs.python.org/3/tutorial/venv.html) from Python 3.

### Make changes

* Fork the tlsfuzzer project
* Clone to your local machine your fork: `git clone git@github.com:.../tlsfuzer.git`
* Download tlslite-ng:
  * `git clone https://github.com/tlsfuzzer/tlslite-ng.git .tlslite-ng`
  * `ln -s .tlslite-ng/tlslite tlslite`
* Verify that test cases are runnable: `make test`
* In your cloned repository, create a topic branch for your upcoming patch
  (e.g. 'implement-aria' or 'bugfix-osx-crash')
  * usually this is based on the master branch
  * to create branch based on master:
    `git checkout master; git branch <example-name>` then
    checkout the branch `git checkout <example-name>`. For your own convenience
    avoid working directly on the `master` branch.
* Make sure you stick to the coding style that is used in surrounding code
  * you can use `pylint --msg-template="{path}:{line}: [{msg_id}({symbol}),
    {obj}] {msg}" tlslite > pylint_report.txt; diff-quality --violations=pylint
    pylint_report.txt` to see if your changes (and only your changes) do not
    violate the general guidelines (alternatively you can just run
    `make test` as described
    below).
* Make commits of logical units and describe them properly in commits
  * When creating a comment, keep the first line short and separate it from
    the rest by whiteline
  * See also [OpenStack guide](https://wiki.openstack.org/wiki/GitCommitMessages)
    for general good ideas about git commit messages
* Check for unnecessary whitespace with `git diff --check` before committing
* Generally newly submitted code should have test coverage so that it can
  be clearly shown that it works correctly.
  * inspect results of running `coverage` reported by `make test`
  * pull requests with code refactoring of code that does not have test
    coverage should have test coverage of the code added first (as separate
    commit or separate PR)
* Assure that test suite continues to pass by running all tests using
  `make test` (see also [tlsfuzzer testing](#tlsfuzzer-testing))
  * Pull requests that fail the last check of the `test` target,
    the test coverage check, may still be accepted, but making pull request
    that passes it is the best way to make the review quick.

### Submit changes

* Push your changes to a topic branch in your fork of the repository.
  `git push origin <example-name>`
* Open a pull request to the original repository and choose the right original
  branch you want to patch (that usually will be tlsfuzzer/master).
* If you posted issues previously, make sure you reference them in the opening
  commit of the pull request (e.g. 'fixes #12'). But _please do not close the
  issue yourself_. GitHub will do that automatically once the issue is merged.
  * in general, fill up the questionnaire that github automatically adds to
  pull request
* Wait for automatic checks to pass. CI checks are mandatory, pull
  requests which
  fail it will not be merged. Coveralls and LGTM failures are not blocking
  but may require explanation. Going to codeclimate
  (see README.md for links) and checking the branch and pull request is also
  a good idea.
  * if you are not sure if the pull request will pass the checks it is OK to
    submit
    a test pull request, marking it as '[WIP]' in title, and removing it once
    the automated checks pass
* Once you receive feedback from reviewers or from the automated systems,
  modify your local patches (that usually means that you need to prepare
  "fixup" patches and/or interactively
  [rebase](https://help.github.com/articles/about-git-rebase/)) and push
  updated branch to github (that usually will require to perform a
  [force push](http://movingfast.io/articles/git-force-pushing/))
  * sometimes it will require
    [squashing](http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html)
    the changes together
* Wait again for automated checks, once they're finished, @mention the previous
  reviewer or @tomato42 if there were none.

### Future work

When working on new features, or after few days, the upstream `master` branch
might have moved forward.

To update your copy of it, first add a "remote" that points to upstream repo:

```
git remote add tlsfuzzer https://github.com/tlsfuzzer/tlsfuzzer.git
```

Get changes from it:

```
git fetch tlsfuzzer
```

Update your local `master` branch:

```
git checkout master
git pull tlsfuzzer master
```

Upload the new `master` branch to your fork:

```
git push origin master
```

This workflow allows for easy updates and rebases of the feature branches.

In case you already added changes to your local `master` branch, it is possible
to undo those changes (search for `git reset`), or pull and rebase at the same
time (instead of just `git pull`):

```
git pull tlsfuzzer master --rebase
```

### Additional Resources

* [General GitHub documentation](http://help.github.com/)
* [GitHub pull request documentation](http://help.github.com/send-pull-requests/)

## tlsfuzzer testing

(not to be confused with testing _with_ (or _using_) tlsfuzzer, for that see
[USAGE.md](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/USAGE.md)
document)

The testing of tlsfuzzer happens in three main steps:

1. unittest
1. regression tests
1. static analysis

### unittest

Unittests live in the `tests` directory, for every module there is one
test module and for every class there is one test class.
Test coverage for class `Foo` from module `tlsfuzzer.bar` will thus live in
`tests/test_tlsfuzzer_bar.py` module/file in the `TestFoo` class.

For very complex classes, or to limit code duplication, classes may have
multiple test classes, but all will have that same prefix.

Unit tests are run after _every_ commit by the CI system.
This is done to simplify eventual
[bisection](https://git-scm.com/docs/git-bisect) when looking for root cause
of some issue.

### Regression tests

To make sure that the test scripts living in the `scripts` directory
continue to be runnable and working as expected (mainly as a sanity check,
not through verification), they are being run against the tlslite-ng server.

The specification of those tests lives in `tests/tlslite-ng-random-subset.json`
and `tests/tlslite-ng.json` files.
As the full test suite runs for almost half an hour, in CI we run only a
subset of all of the specific tests in the scripts.
In other words, we do run all scripts, but we don't run every test from every
script.

### Static analysis

To verify code quality, in CI we're using `pylint` to verify that the
code follows Python standards for code formatting and antipatterns
(`diff-quality` is used to apply those checks only on new code).
Additionally we use CodeClimate and lgtm CI services to provide similar checks.

Finally, to verify that the added code actually is covered by unit tests, we
use coveralls.io to check code coverage.

## Change requirements

When contributing patches please follow the following guidelines:

* Code follows the [PEP 8](https://www.python.org/dev/peps/pep-0008/) and
  the [PEP 257](https://www.python.org/dev/peps/pep-0257/) style guides
* Code should not use platform specific extensions – should be runnable on
  Linux, Windows and OSX (CI does not verify it, yet:
  [#22](https://github.com/tlsfuzzer/tlsfuzzer/issues/22),
  [#21](https://github.com/tlsfuzzer/tlsfuzzer/issues/21))
* When adding new functionality unit tests need to be provided with those
  changes, see
  [unit test checklist](https://github.com/tlsfuzzer/tlsfuzzer/wiki/Unit-test-checklist)
  for unit test requirements
  * You can check if unittests actually cover the added code by looking at the
    coveralls.io report for a given PR
* When creating new test scripts, use
  [`test-conversation.py`](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-conversation.py)
  and
  [`test-tls13-conversation.py`](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-tls13-conversation.py)
  as templates
* When creating new test scripts, consult
  [Test script checklist](https://github.com/tlsfuzzer/tlsfuzzer/wiki/Test-script-checklist)
* New test scripts need to be added to `tests/tlslite-ng.json` and
  `tests/tlslite-ng-random-subset.json` files (note: they are sorted
  alphabetically)
* When working on existing TLS 1.3 issues, consult the annotated
  [TLS 1.3 draft](https://github.com/tomato42/tls13-spec/blob/notes/draft-ietf-tls-tls13.md)
  for the context
