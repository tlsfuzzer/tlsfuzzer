#!/usr/bin/python
import os
import getopt
import sys
from tlsfuzzer.utils.log import Log

def help_msg():
    print("""
Usage: shuffled_keys_generator.py [OPTIONS] KEY_FILE1 KEY_FILE2 ...

Options:
  -n <int>    Number of repetitions (default: 100000)
  -l <str>    Log file path (default: log.csv)
  -o <str>    Output file path (default: keys.pem)
  -d          Dry run: validate files and show sequence without writing
  -h          Show this help message
    """)

def main():
    # --- Default Values ---
    repetitions = 100000
    log_file = "log.csv"
    output_file = "keys.pem"
    dry_run = False

    # --- Parsing Arguments ---
    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hn:l:o:d",
            ["help", "repetitions=", "log-file=", "output=", "dry-run"]
        )
    except getopt.GetoptError:
        err = sys.exc_info()[1]
        print("Error: {0}".format(str(err)))
        help_msg()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help_msg()
            sys.exit(0)
        elif opt in ("-n", "--repetitions"):
            repetitions = int(arg)
        elif opt in ("-l", "--log-file"):
            log_file = arg
        elif opt in ("-o", "--output"):
            output_file = arg
        elif opt in ("-d", "--dry-run"):
            dry_run = True

    if not args:
        print("Error: No key files provided.")
        help_msg()
        sys.exit(1)

    # 1. Load and Validate file contents
    file_contents = {}
    log_class_names = []

    for file_path_str in args:
        # Python 2.6 alternative to pathlib: os.path
        basename = os.path.basename(file_path_str)

        if not os.path.exists(file_path_str):
            print("Error: Source file '{0}' not found.".format(file_path_str))
            sys.exit(1)

        if basename in file_contents:
            print("Error: Duplicate filename detected: '{0}'.".format(basename))
            sys.exit(1)

        # Explicitly reading in 'r' mode
        f = open(file_path_str, 'r')
        content = f.read()
        f.close()

        if "-----BEGIN" not in content:
            print("Warning: '{0}' does not appear to be a valid PEM file.".format(basename))

        file_contents[basename] = content
        log_class_names.append(basename)

    if dry_run:
        print("--- DRY RUN MODE ACTIVE ---")

    # 2. Setup tlsfuzzer Log and perform shuffles
    log = Log(log_file)
    log.start_log(log_class_names)

    # Python 2.6 doesn't support the {:,} thousands separator in format()
    # Using basic integer printing
    print("Generating {0} shuffled runs using {1} keys...".format(repetitions, len(args)))
    for _ in range(repetitions):
        log.shuffle_new_run()

    if not dry_run:
        log.write()

    # 3. Reconstruct the sequence
    log.read_log()
    test_classes = log.get_classes()

    if dry_run:
        print("\nPredicted sequence (first 10 runs):")
        # In Python 2, iterate_log() will return indices
        for i, index in enumerate(log.iterate_log()):
            if i >= 10: break
            print("  Run {0}: {1}".format(i + 1, test_classes[index]))
        print("\nDry run complete. No files were written.")
        return

    print("Writing concatenated keys to '{0}'...".format(output_file))
    try:
        out_file = open(output_file, "w")
        for index in log.iterate_log():
            out_file.write(file_contents[test_classes[index]])
        out_file.close()
    except IOError:
        err = sys.exc_info()[1]
        print("Error writing to output file: {0}".format(str(err)))
        sys.exit(1)

    print("Shuffle and generation complete.")

if __name__ == "__main__":
    main()
