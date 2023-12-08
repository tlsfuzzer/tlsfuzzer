# Author: Hubert Kario, (c) 2021-2023
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Bleichenbacher attack test for Marvin workaround."""
from __future__ import print_function
import sys
import getopt
import os
from threading import Thread, Event

from tlslite.x509 import X509
from tlslite.utils.keyfactory import parsePEMKey
from tlsfuzzer.utils.progress_report import progress_report
from tlsfuzzer.utils.log import Log
from tlsfuzzer.utils.rsa import MarvinCiphertextGenerator


version = 5


def help_msg():
    """Print usage information."""
    print("Usage: <script-name> ...]")
    print(" -o dir         Specifies output directory for timing information")
    print("                /tmp by default")
    print(" --repeat rep   How many ciphertexts should be generated for each test")
    print("                100 by default")
    print(" --pms-len len  Generate ciphertexts that decrypt to specified")
    print("                number of bytes, 48 by default.")
    print(" --srv-key key  File with server private key.")
    print(" --srv-cert crt File with server certificate.")
    print(" --pms-tls-version ver Control the TLS version in the decrypted or")
    print("                synthethic plaintext. If left undefined the script")
    print("                will make sure not to generate message values that")
    print("                start with values appropriate for SSLv3, TLS 1.0,")
    print("                TLS 1.1, and TLS 1.2. If set, it should be a")
    print("                hex-encoded integer representing two bytes to be")
    print("                used as the version, e.g. \"0x0303\" for TLS 1.2")
    print("                Note: using this option will significantly increase")
    print("                the time to generate ciphertexts.")
    print(" --probe-reuse num How many times to reuse a probe before generating")
    print("                a new one. Low values will increase time to generate")
    print("                probes while large values risk false positives caused")
    print("                by ciphertext value. Set to 0 to never regenerate.")
    print("                Default 1")
    print(" --status-delay num How long to wait between status line updates.")
    print("                In seconds. Default: 2.0")
    print(" --status-newline Use newline for separating lines in the status messages")
    print(" --help         this message")


def main():
    """Generate test ciphertexts for Marvin workaround."""
    repetitions = 100
    outdir = "/tmp"
    pms_len = 48
    srv_key = None
    srv_cert = None
    pms_tls_version = None
    probe_reuse = 1
    status_delay = 2.0
    carriage_return = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv,
                               "o:",
                               ["help",
                                "repeat=",
                                "pms-len=",
                                "srv-key=",
                                "srv-cert=",
                                "pms-tls-version=",
                                "probe-reuse=",
                                "status-newline",
                                "status-delay="])
    for opt, arg in opts:
        if opt == '-o':
            outdir = arg
        elif opt == "--repeat":
            repetitions = int(arg)
        elif opt == "--pms-len":
            pms_len = int(arg)
        elif opt == "--srv-key":
            with open(arg, "rb") as f:
                text_key = f.read()
            if sys.version_info[0] >= 3:
                text_key = str(text_key, "utf-8")
            srv_key = parsePEMKey(text_key, private=True)
        elif opt == "--srv-cert":
            with open(arg, "rb") as f:
                text_cert = f.read()
            if sys.version_info[0] >= 3:
                text_cert = str(text_cert, "utf-8")
            srv_cert = X509()
            srv_cert.parse(text_cert)
        elif opt == "--pms-tls-version":
            int_ver = int(arg, 16)
            pms_tls_version = divmod(int_ver, 256)
        elif opt == "--probe-reuse":
            probe_reuse = int(arg)
        elif opt == "--status-newline":
            carriage_return = '\n'
        elif opt == "--status-delay":
            status_delay = float(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if not srv_cert or not srv_key:
        print("You must provide server private key and certificate")
        sys.exit(1)

    if args:
        print("Unexpected arguments: {0}".format(args))
        sys.exit(1)

    print("Test generating ciphertexts...")
    marvin_gen = MarvinCiphertextGenerator(
        srv_key, srv_cert.publicKey, pms_len, pms_tls_version)
    ciphertexts = marvin_gen.generate()
    print("Test passed.")

    with open(
        os.path.join(outdir, 'pms_values.bin'),
        "wb"
    ) as pms_file:
        print("Generating log...")

        status = [0, repetitions, Event()]
        kwargs = dict()
        kwargs['delay'] = status_delay
        kwargs['end'] = carriage_return
        progress = Thread(target=progress_report, args=(status,),
                          kwargs=kwargs)
        progress.start()

        try:
            # create a real order of tests to run
            log = Log(os.path.join(outdir, "log.csv"))

            log.start_log(ciphertexts.keys())
            for i in range(repetitions):
                status[0] = i+1
                log.shuffle_new_run()
        finally:
            status[2].set()
            progress.join()
            print()
        print("Log generated.")
        log.write()

        log.read_log()
        test_classes = log.get_classes()

        print("Generating ciphertexts...")

        status = [0, len(test_classes) * repetitions, Event()]
        kwargs = dict()
        kwargs['delay'] = status_delay
        kwargs['end'] = carriage_return
        progress = Thread(target=progress_report, args=(status,),
                          kwargs=kwargs)
        progress.start()

        exp_key_size = (len(srv_cert.publicKey) + 7) // 8

        # generate the PMS values
        try:
            for executed, index in enumerate(log.iterate_log()):
                if probe_reuse and \
                        executed % (len(test_classes) * probe_reuse) == 0:
                    ciphertexts = marvin_gen.generate()

                status[0] = executed + 1

                g_name = test_classes[index]

                res = ciphertexts[g_name]
                assert len(res) == exp_key_size, len(res)

                pms_file.write(res)
        finally:
            status[2].set()
            progress.join()
            print()

    print("Done")


if __name__ == "__main__":
    main()
