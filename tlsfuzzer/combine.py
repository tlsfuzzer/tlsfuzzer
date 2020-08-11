# Author: Hubert Kario, (c) Red Hat 2020
# Released under the Gnu GPL v2.0, see LICENSE file for details

"""Utility for combining multiple timing.csv files into one."""

from __future__ import print_function

import sys
import getopt
import csv
from os.path import join


def help_msg():
    """Print help message."""
    print("""Usage: ./combine.py -o out-dir in0 [in1 [in2 [...]]]
-o out-dir          Output directory (required)
                    Any timing.csv file there will be overwritten
--help              This help message
in0, in1, ...       Input files to combine

This is a helper tool to either convert from the old timing.csv file
(one that placed all observations of a single probe in a single line)
or to combine multiple runs of the same set of probes to allow analysis
with stronger statistical significance.
""")


def get_format(file_name):
    """
    Guess the file format of the provided csv file.

    Returns either "row-based", when all values for a given class are in a
    single line, or "column-based", when all values for a given class are
    in a single column.
    """
    with open(file_name, "r") as f:
        line = f.readline()

        if line and line[0] == '"':
            # handle quoted probe names
            pos = line.find('"', 1)
            if pos < 0:
                raise ValueError("Malformed csv file")
            first = line[1:pos]
            vals = [first] + line[pos+2:].split(',')
        else:
            vals = line.split(',')

        if not vals or not vals[0]:
            raise ValueError("Empty file: {0}".format(file_name))
        if len(vals) == 1:
            return "column-based"
        try:
            float(vals[1])
            return "row-based"
        except ValueError:
            return "column-based"


def read_row_based_csv(file_name):
    with open(file_name, 'r') as f:
        in_file = csv.reader(f)
        for i in (list(i) for i in zip(*in_file)):
            yield i


def read_column_based_csv(file_name):
    with open(file_name, 'r') as f:
        in_file = csv.reader(f)
        for i in in_file:
            yield i


def combine(output, inputs):
    """Combine timing.csv files into a single one."""
    columns = None

    with open(join(output, "timing.csv"), "w") as out:
        out_csv = csv.writer(out)
        for file_name in inputs:
            fmt = get_format(file_name)
            if fmt == "row-based":
                values = read_row_based_csv(file_name)
            else:
                assert fmt == "column-based"
                values = read_column_based_csv(file_name)

            values_header = next(values)

            if columns is None:
                columns = values_header
                out_csv.writerow(columns)

            if columns != values_header:
                raise ValueError(
                    "Column names in {0} don't match column "
                    "names from first input file".format(file_name))

            out_csv.writerows(values)


def main():
    output = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "o:", ["help"])

    for opt, arg in opts:
        if opt == "-o":
            output = arg
        else:
            assert opt == "--help"
            help_msg()
            sys.exit(0)

    inputs = args
    if not inputs:
        raise ValueError("No input files provided")
    if not output:
        raise ValueError("No output directory provided")

    combine(output, inputs)


if __name__ == "__main__":
    main()
