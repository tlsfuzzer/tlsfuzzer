.. _installation:

============
Installation
============

The project is set up so that installation of it or dependencies is not
necessary.

Installing the dependencies will make handling all dependencies easier though.

(More complete instructions are in
`CONTRIBUTING.md <https://github.com/tomato42/tlsfuzzer/blob/master/CONTRIBUTING.md>`_
and
`USAGE.md <https://github.com/tomato42/tlsfuzzer/blob/master/USAGE.md>`_
files.)

``pip``
=======

Because the tlsfuzzer is developed in lock-step with tlslite-ng, only the
newest releases of the latter are expected to work. That means either
alpha or beta versions of tlslite-ng.

To install the latest version tested use ``pip``:

::

    pip install -r requirements.txt


Using source directly
=====================

If the dependencies of tlslite-ng are already installed, the only part of
tlslite-ng necessary for tlsfuzzer to work, is the ``tlslite`` module.
As such, it's possible to just link the ``tlslite`` directory in a
checkout of tlslite-ng project inside the checkout of tlsfuzzer.

If both tlsfuzzer and tlslite-ng have been cloned to the same directory,
it's enough to execute the following command inside the tlsfuzzer directory:

::

    ln -s ../tlslite-ng/tlslite tlslite


Virtual environments
====================

If you would like to install tlslite-ng or its dependencies, but not affect
the general system, or even your personal python packages, it's possible
to use virtual environments.
