# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
from tlsfuzzer.scanner import Scanner
from tlsfuzzer.generators import Generator
from tlsfuzzer.fuzzers import Fuzzer
from tlsfuzzer.runner import Runner
import traceback

def main():

    fingerprint = Scanner().scan(ip="127.0.0.1", port=4433)

    generator = Generator(fingerprint)

    good = 0
    bad = 0

    for conversation in generator:
        fuzzer = Fuzzer(conversation, fingerprint)
        for fuzzed in fuzzer:
            runner = Runner(fuzzed)

            try:
                res = runner.run()
            except:
                print(traceback.format_exc())
                res = False

            if res:
                good+=1
            else:
                bad+=1

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
