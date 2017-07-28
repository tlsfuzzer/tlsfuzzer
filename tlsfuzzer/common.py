# Date: 28.7.2017
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Common functions"""

from __future__ import print_function
import traceback

import sys
import getopt
import os

from tlsfuzzer.runner import Runner


class Conversation(object):
    """
    Keeps basic informations for one conversation (subtest)

    @ivar name: conversation name
    @ivar root_node: first conversation node
    @ivar passed: specify if conversation passed run or not
    """

    def __init__(self, name):
        self.name = name
        self.root_node = None
        self.passed = None

    def print_result(self):
        """Present result of conversation run"""
        if os.name is 'posix':
            self.print_result_template('\033[92m', '\033[91m', '\033[0m')
        else:
            self.print_result_template()

    def print_result_template(self, code_ok='', code_fail='', code_end=''):
        """Printing template for conversation result"""
        if self.passed:
            print("[ {0}ok{1} ]\t{2}".format(code_ok, code_end, self.name))
        else:
            print("[{0}fail{1}]\t{2}".format(code_fail, code_end, self.name))


def print_statistic(conversations):
    """Print summary for all conversations (subtests)"""
    passed = 0
    not_passed = 0

    for conversation in conversations:
        if conversation.passed:
            passed += 1
        else:
            not_passed += 1

    print("\nSTATISTICS")
    print("successful:\t{0}".format(passed))
    print("failed:\t\t{0}".format(not_passed))


def print_traceback(conversations):
    """Print traceback summary for all failed conversations"""
    print("\nTRACEBACK SUMMARY")
    for conversation in conversations:
        if not conversation.passed:
            conversation.print_result()
            print(traceback.format_exc())


def help_msg():
    """Print help message"""
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" --help         this message")


def handle_user_input():
    """User input processing"""
    host = "localhost"
    port = 4433
    run_only = None
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)

    return host, port, run_only, run_exclude


def run_all(conversations):
    """Manage run of all prepared conversations and present results"""
    for conversation in conversations:
        runner = Runner(conversation.root_node)

        try:
            runner.run()
        except:
            conversation.passed = False
        else:
            conversation.passed = True
        finally:
            conversation.print_result()

    print_statistic(conversations)
    print_traceback(conversations)

    if not all(conversation.passed for conversation in conversations):
        sys.exit(1)
