# Author: Hubert Kario, (c) 2022
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Convert the log file to a list, so that raw_times_detail can be analysed."""

from __future__ import print_function

import getopt
import sys
import itertools
from tlsfuzzer.utils.log import Log
import pandas as pd


def help_msg():
    print("Usage log_to_list -l logfile -i legend -o output")


def main():
    """Process the parameters."""

    logfile = None
    output = None
    legend = None

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "l:i:o:", ["help"])
    for opt, arg in opts:
        if opt == "-l":
            logfile = arg
        elif opt == "-o":
            output = arg
        elif opt == "-i":
            legend = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        else:
            print("Unrecognised options: {0} {1}".format(opt, arg))
            sys.exit(1)

    if args:
        print("Unrecognised options: {0}".format(args))
        sys.exit(1)

    if not legend or not logfile or not output:
        print("Must provide logfile (-l), legend file (-i) and output file (-o)")
        sys.exit(1)

    log = Log(logfile)
    log.read_log()

    legend_f = pd.read_csv(legend)

    legend_map = dict()

    for index, row in legend_f.iterrows():
        legend_map[row['Name']] = row['ID']

    class_names = log.get_classes()

    with open(output, "w") as o_file:
        o_file.write("ID,tuple\n")
        for tuple_index, class_index in zip(
                itertools.chain.from_iterable(
                    itertools.repeat(i, len(class_names))
                    for i in itertools.count(0)),
                log.iterate_log()):
            class_name = class_names[class_index]
            o_file.write("{0},{1}\n".format(
                legend_map[class_name],
                str(tuple_index)))


if __name__ == "__main__":
    main()
