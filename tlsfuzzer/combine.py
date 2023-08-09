# Author: Hubert Kario, (c) Red Hat 2020
# Released under the Gnu GPL v2.0, see LICENSE file for details

"""Utility for combining multiple timing.csv files into one."""

from __future__ import print_function

import sys
import getopt
import csv
from os.path import join, splitext


def help_msg():
    """Print help message."""
    print("""Usage: ./combine.py -o out-dir in0 [in1 [in2 [...]]]
-o out-dir          Output directory (required)
                    Any timing.csv file there will be overwritten
--measurements      Specifies that the files are measurements
                    Any measurements.csv file there will be overwritten
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
    """Combine timing.csv or measurements.csv files into a single one."""
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


def combine_measurements(output, inputs):
    filename = "measurements"

    with open(join(output, filename + '.csv'), "w") as out_fp:
        lines_so_far = 0
        total_samples = 0
        for file_name in inputs:
            with open(file_name, 'r') as in_fp:
                in_csv = csv.reader(in_fp)
                for row in in_csv:
                    try:
                        line_num = int(row[0]) + lines_so_far

                        out_fp.write(
                            "{0},{1},{2}\n".format(line_num, row[1], row[2])
                        )
                        total_samples += 1
                    except IndexError:
                        raise ValueError("File does not have correct format")

                lines_so_far = line_num + 1

    count_file = filename + ".count"

    with open(join(output, count_file), "w") as out_fp:
        out_fp.write(
            'Compined {0:,} samples in {1:,} lines in file {2}.\n'
            .format(
                total_samples, lines_so_far - 1,
                join(output, filename + ".csv")
            )
        )


def main():
    output = None
    measurements = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "o:", ["help", "measurements"])

    for opt, arg in opts:
        if opt == "-o":
            output = arg
        elif opt == "--measurements":
            measurements = True
        else:
            assert opt == "--help"
            help_msg()
            sys.exit(0)

    inputs = args
    if not inputs:
        raise ValueError("No input files provided")
    if not output:
        raise ValueError("No output directory provided")

    if measurements:
        combine_measurements(output, inputs)
    else:
        combine(output, inputs)


if __name__ == "__main__":
    main()
