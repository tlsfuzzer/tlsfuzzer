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


def _si_prefix(count):
    """Format the number with a SI prefix"""
    ret = count
    lvl = 0
    lvls = {0: '', 1: 'k', 2: 'M', 3: 'G', 4: 'T', 5: 'E'}
    while ret > 2000:
        ret /= 1000.0
        lvl += 1

    return "{0:.2f}{1}".format(ret, lvls[lvl])


def _binary_prefix(count):
    """Format the number with a binary prefix"""
    ret = count
    lvl = 0
    lvls = {0: '', 1: 'ki', 2: 'Mi', 3: 'Gi', 4: 'Ti', 5: 'Ei'}
    while ret > 2000:
        ret /= 1024.0
        lvl += 1

    return "{0:.2f}{1}".format(ret, lvls[lvl])


def progress_report(status, unit='', prefix='decimal', delay=2.0):
    """
    Periodically report progress of a task in `status`, a thread runner.

    status must be an array with three elements, first two specify a
    fraction of completed work (i.e. 0 <= status[0]/status[1] <= 1),
    third specifies if the reporting process should continue running.
    It can either be a bool or a threading.Event instance.
    A False bool value there will cause the thread to finish.
    An Event object with flag set will cause the thread to finish
    (using Event is recommended when the `delay` is long as that allows a
    quick and clean shutdown of the process).

    `unit` is the first two elements in `status` (like 'B' for bytes or
    ' conn' for connections).

    `prefix` controls the exponent for the SI prefix, `decimal` for
    1000 and `binary` for 1024

    `delay` sets how often to print the status line, in seconds
    """
    if len(status) != 3:
        raise ValueError("status is not a 3 element array")
    # technically that should be time.monotonic(), but it's not supported
    # on python2.7
    start_exec = time.time()
    prev_loop = start_exec
    if prefix == 'decimal':
        prefix_format = _si_prefix
    else:
        assert prefix == 'binary'
        prefix_format = _binary_prefix
    event_type = type(Event())
    while True:
        old_exec = status[0]
        if isinstance(status[2], event_type):
            status[2].wait(delay)
        else:
            time.sleep(delay)
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
                  " " * 4), end="\r")

        if isinstance(status[2], event_type):
            if status[2].is_set():
                break
        elif not status[2]:
            break
