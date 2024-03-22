from __future__ import print_function
import getopt
import sys
from itertools import repeat
from threading import Thread, Event
from multiprocessing import Pool
from tlsfuzzer.utils.progress_report import progress_report
from tlslite.utils.keyfactory import generateRSAKey
from tlslite.utils.python_rsakey import Python_RSAKey
from ecdsa.der import encode_sequence, encode_integer, encode_oid, \
        encode_octet_string, topem

version = 1


def help_msg():
    print("Usage: {0} -o file.pem [-c int] [-s int]".format(sys.argv[0]))
    print("""
 -o file       File name to which to append newly generated keys
 -c int        Number of keys to generate (100000 by default)
 -s int        Bit size of the generated RSA keys (2048 by default)
 --workers int Number of worker processes to run in parallel (equal to numer
               of CPUs in the system by default)
 --verbose     Verbose output, progress reporting
 --help        Print this message
""")


def key_to_pkcs8(key):
    rsa_encryption = (1, 2, 840, 113549, 1, 1, 1)
    raw_key = encode_sequence(
        encode_integer(0),
        encode_integer(key.n),
        encode_integer(key.e),
        encode_integer(key.d),
        encode_integer(key.p),
        encode_integer(key.q),
        encode_integer(key.dP),
        encode_integer(key.dQ),
        encode_integer(key.qInv)
    )
    ret = encode_sequence(
        encode_integer(0),
        encode_sequence(
            encode_oid(*rsa_encryption),
            b"\x05\x00"  # NULL
        ),
        encode_octet_string(raw_key)
    )
    return ret


def pem_rsa_key(size):
    """Return a byte string that's a PEM encoding of RSA private key."""
    key = generateRSAKey(size, ["python"])

    pem_key = topem(key_to_pkcs8(key), "PRIVATE KEY")

    return pem_key


def main():
    count = 100000
    out_name = None
    size = 2048
    verbose = False
    workers = None
    endline = '\r'
    delay = 2.0

    argv = sys.argv[1:]

    opts, args = getopt.getopt(argv, "o:c:s:", ["verbose", "help", "workers=",
                                                "status-newline",
                                                "status-delay="])
    for opt, arg in opts:
        if opt == "-o":
            out_name = arg
        elif opt == "-c":
            count = int(arg)
        elif opt == "-s":
            size = int(arg)
        elif opt == "--verbose":
            verbose = True
        elif opt == "--workers":
            workers = int(arg)
        elif opt == "--status-newline":
            endline = '\n'
        elif opt == "--status-delay":
            delay = float(arg)
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        else:
            help_msg()
            raise ValueError("Unrecognised option: {0}".format(opt))

    if args:
        help_msg()
        raise ValueError("Trailing parameters: {0}".format(args))

    if not out_name:
        help_msg()
        raise ValueError("Output file name unspecified")


    if verbose:
        status = [0, count, Event()]
        kwargs = {"unit": " keygen"}
        kwargs['end'] = endline
        kwargs['delay'] = delay
        progress = Thread(target=progress_report, args=(status,),
                          kwargs=kwargs)
        progress.start()

    try:
        with open(out_name, "ab") as out_file:

            with Pool(workers) as pool:
                keys = pool.imap_unordered(pem_rsa_key, repeat(size, count),
                                           10)

                for pem_key in keys:
                    if verbose:
                        status[0] += 1

                    out_file.write(pem_key)
    finally:
        if verbose:
            status[2].set()
            progress.join()
            print()


if __name__ == "__main__":
    main()
