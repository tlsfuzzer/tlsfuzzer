# Author: Dmitry Belyavskiy, (c) 2026
# Released under Gnu GPL v2.0, see LICENSE file for details
"""A helper script to prepare file with multiple keys concatenation."""
#!/usr/bin/python
import pathlib
import getopt
import sys
from tlsfuzzer.utils.log import Log

def help_msg():
    print("""
Usage: shuffled_keys_generator.py [OPTIONS]

Options:
  -n <int>    Number of repetitions (default: 100000)
  -c <int>    Number of keys (default: 10)
  -s <str>    Source prefix for files on disk (default: keyp521)
  -p <str>    Log prefix for internal mapping (default: key)
  -l <str>    Log file path (default: log.csv)
  -o <str>    Output file path (default: keys.pem)
  -h          Show this help message
    """)

def main():
    # --- Default Values ---
    repetitions = 100000
    count = 10
    src_prefix = "key"
    log_prefix = "key"
    log_file = "log.csv"
    output_file = "keys.pem"

    # --- Parsing Arguments ---
    try:
        # h does not have a colon because it takes no argument
        # All others have colons because they require values
        opts, args = getopt.getopt(
            sys.argv[1:],
            "hn:c:s:p:l:o:",
            ["help", "repetitions=", "count=", "src-prefix=", "log-prefix=", "log-file=", "output="]
        )
    except getopt.GetoptError as err:
        print(f"Error: {err}")
        help_msg()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help_msg()
            sys.exit(0)
        elif opt in ("-n", "--repetitions"):
            repetitions = int(arg)
        elif opt in ("-c", "--count"):
            count = int(arg)
        elif opt in ("-s", "--src-prefix"):
            src_prefix = arg
        elif opt in ("-p", "--log-prefix"):
            log_prefix = arg
        elif opt in ("-l", "--log-file"):
            log_file = arg
        elif opt in ("-o", "--output"):
            output_file = arg

    # 1. Load file contents into a dictionary
    file_contents = {}
    log_class_names = [f"{log_prefix}{i}.pem" for i in range(1, count + 1)]

    for i in range(1, count + 1):
        src_filename = f"{src_prefix}_{i}.pem"
        log_class_name = f"{log_prefix}{i}.pem"

        src_path = pathlib.Path(src_filename)
        if src_path.exists():
            file_contents[log_class_name] = src_path.read_text()
        else:
            print(f"Error: Required source file '{src_filename}' not found.")
            sys.exit(1)

    # 2. Setup tlsfuzzer Log and perform shuffles
    log = Log(log_file)
    log.start_log(log_class_names)

    print(f"Generating {repetitions:,} shuffled runs...")
    for _ in range(repetitions):
        log.shuffle_new_run()

    log.write()

    # 3. Reconstruct the sequence based on the log
    log.read_log()
    test_classes = log.get_classes()

    print(f"Writing concatenated keys to '{output_file}'...")
    try:
        with open(output_file, "w") as out_file:
            for index in log.iterate_log():
                class_name = test_classes[index]
                out_file.write(file_contents[class_name])
    except IOError as e:
        print(f"Error writing to output file: {e}")
        sys.exit(1)

    print("Shuffle and generation complete.")

if __name__ == "__main__":
    main()
