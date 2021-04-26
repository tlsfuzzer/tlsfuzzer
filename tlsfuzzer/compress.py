# Author: Hubert Kario, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Combining extracted times to the order they were collected in."""

from __future__ import print_function

import getopt
import sys
import csv

from tlsfuzzer.utils.log import Log

def help_msg():
    """Print help message."""
    print("Usage: compress -l logfile -o output -i input")
    print(" -l logfile     Filename of the timing log (required)")
    print(" -o output      File to save the timing list (required)")
    print(" -i input       Read the timings from this file")
    print(" --help         Display this message")
    print("")
    print("Copies the times from input to output file based on order in")
    print("logfile. In other words, recreates the --raw-times file useful for")
    print("extract.py")


def main():
    logfile = None
    output_path = None
    input_path = None

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "l:o:i:", ["help"])
    for opt, arg in opts:
        if opt == "-l":
            logfile = arg
        elif opt == "-o":
            output_path = arg
        elif opt == "-i":
            input_path = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)

    if args:
        print("Unexpected arguments: {0}".format(args))
        sys.exit(1)

    if not all((logfile, output_path, input_path)):
        print("All parameters must be specified: -l, -i, -o")
        print()
        help_msg()
        sys.exit(1)

    log = Log(logfile)
    log.read_log()

    class_generator = log.iterate_log()
    class_names = log.get_classes()
    tuple_len = len(class_names)

    with open(input_path, 'r') as input_file:
        in_csv = iter(csv.reader(input_file))
        header = next(in_csv)
        if sorted(header) != sorted(class_names):
            print("Error: Names in log file don't match names in input file")
            print("log file: {0}".format(sorted(class_names)))
            print("input file: {0}".format(sorted(header)))
            sys.exit(1)

        if header != class_names:
            header_order = [header.index(i) for i in class_names]
            order_fixer = lambda x: [x[i] for i in header_order]
        else:
            order_fixer = lambda x: x

        assert class_names == order_fixer(header)

        with open(output_path, 'w') as output_file:
            output_file.write("raw times\n")
            for order in zip(*((class_generator, ) * tuple_len)):
                values = next(in_csv)
                values = order_fixer(values)
                output_file.write("\n".join(values[i] for i in order) + "\n")

if __name__ == '__main__':
    main()
