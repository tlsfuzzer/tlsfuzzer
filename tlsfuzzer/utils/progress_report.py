# Author: Hubert Kario, (c) 2023
# Released under Gnu GPL v2.0, see LICENSE file for details
from __future__ import print_function
import time
import math
from threading import Event

"""Rporting progress of a task and reporting estimated completion time."""


def _format_seconds(sec):
    """Format number of seconds into a more readable string."""
    elems = []
    msec, sec = math.modf(sec)
    sec = int(sec)
    days, rem = divmod(sec, 60*60*24)
    if days:
        elems.append("{0:2}d".format(days))
    hours, rem = divmod(rem, 60*60)
    if hours or elems:
        elems.append("{0:2}h".format(hours))
    minutes, sec = divmod(rem, 60)
    if minutes or elems:
        elems.append("{0:2}m".format(minutes))
    elems.append("{0:5.2f}s".format(sec+msec))
    return " ".join(elems)


def _prefix_handler(count, suffix, divisor):
    """Format the number with a given suffix and divisor"""
    ret = count
    lvl = 0
    lvls = {0: '',
            1: 'k' + suffix,
            2: 'M' + suffix,
            3: 'G' + suffix,
            4: 'T' + suffix,
            5: 'E' + suffix}
    while ret > 2 * divisor and lvl <= max(lvls):
        ret /= divisor
        lvl += 1

    return "{0:.2f}{1}".format(ret, lvls[lvl])


def _si_prefix(count):
    """Format the number with a SI prefix"""
    return _prefix_handler(count, '', 1000.0)


def _binary_prefix(count):
    """Format the number with a binary prefix"""
    return _prefix_handler(count, 'i', 1024.0)


def _wait(status, delay, event_type=type(Event())):
    if isinstance(status[2], event_type):
        status[2].wait(delay)
    else:
        time.sleep(delay)


def _sanitize_args(status, prefix, delay, end):
    """Check if params are sane and set defaults."""
    if len(status) != 3:
        raise ValueError("status is not a 3 element array")
    if delay is None:
        delay = 2
    if end is None:
        end = '\r'
    if prefix == 'decimal':
        prefix_format = _si_prefix
    else:
        assert prefix == 'binary'
        prefix_format = _binary_prefix

    return delay, end, prefix_format


def _done(status, event_type=type(Event())):
    if isinstance(status[2], event_type):
        if status[2].is_set():
            return True
    elif not status[2]:
        return True
    return False


def progress_report(status, unit='', prefix='decimal', delay=None, end=None):
    """
    Periodically report progress of a task in ``status``, a thread runner.

    :param list status: must be a list with three elements, first two
    specify a fraction of completed work (i.e.
    ``0 <= status[0]/status[1] <= 1``),
    third specifies if the reporting process should continue running.
    It can either be a ``bool`` or a :py:class:`threading.Event` instance.
    A ``False`` bool value there will cause the thread to finish.
    An ``Event`` object with flag set will cause the thread to finish
    (using Event is recommended when the ``delay`` is long as that allows a
    quick and clean shutdown of the process).

    :param str unit: is the first name of the unit of the two elements in
    ``status`` (like ``B`` for bytes or `` conn`` for connections).

    :param str prefix: controls the exponent for the SI prefix, use ``decimal``
    for 1000 and ``binary`` for 1024

    :param float delay: sets how often to print the status line, in seconds

    :param str end: line terminator to use when printing the status line,
    use ``\r`` to overwrite the line when printing (default), or ``\n`` to
    print a whole new line every time.
    """
    delay, end, prefix_format = _sanitize_args(status, prefix, delay, end)
    # technically that should be time.monotonic(), but it's not supported
    # on python2.7
    start_exec = time.time()
    prev_loop = start_exec
    event_type = type(Event())
    while True:
        old_exec = status[0]
        _wait(status, delay)
        now = time.time()
        elapsed = now-start_exec
        loop_time = now-prev_loop
        prev_loop = now
        elapsed_str = _format_seconds(elapsed)
        done = status[0]*100.0/status[1]
        try:
            remaining = (100-done)*elapsed/done
        except ZeroDivisionError:
            # if none done assume that each work unit will take as
            # much as current runtime
            remaining = status[1]*elapsed
        remaining_str = _format_seconds(remaining)
        eta = time.strftime("%H:%M:%S %d-%m-%Y",
                            time.localtime(now+remaining))
        print("Done: {0:6.2f}%, elapsed: {1}, speed: {2}{6}/s, "
              "avg speed: {3}{6}/s, remaining: {4}, ETA: {5}{7}"
              .format(
                  done, elapsed_str,
                  prefix_format((status[0] - old_exec)/loop_time),
                  prefix_format(status[0]/elapsed),
                  remaining_str,
                  eta,
                  unit,
                  " " * 4), end=end)

        if _done(status):
            break
