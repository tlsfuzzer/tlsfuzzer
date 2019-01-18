from __future__ import print_function
from subprocess import Popen, call, PIPE
from threading import Thread, Lock
import os
import time
import logging
import sys
import socket
import threading
import json
import time
try:
    import queue
except ImportError:
    import Queue as queue

logging.basicConfig(level=logging.DEBUG)
#logging.basicConfig(level=logging.INFO)
#logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

out = queue.Queue()

pass_count = 0
fail_count = 0
pass_lock = threading.Lock()
fail_lock = threading.Lock()


def process_stdout(name, proc):
    for line in iter(proc.stdout.readline, b''):
        line = line.decode()
        line = line.rstrip()
        out.put("{0}:stdout:{1}".format(name, line))


def process_stderr(name, proc):
    for line in iter(proc.stderr.readline, b''):
        line = line.decode()
        line = line.rstrip()
        out.put("{0}:stderr:{1}".format(name, line))


def wait_till_open(host, port):
    t1 = time.time()
    while time.time() - t1 < 10:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((host, port))
        except socket.error as e:
            continue
        break
    else:
        raise ValueError("Can't connect to server")


def start_server(server_cmd, server_env=tuple(), server_host=None,
                 server_port=4433):
    if server_host is None:
        server_host = "localhost"
    my_env = os.environ.copy()
    my_env.update(server_env)
    ret = Popen(server_cmd, env=my_env,
                stdout=PIPE, stderr=PIPE, bufsize=1)
    thr_stdout = Thread(target=process_stdout, args=('server', ret))
    thr_stdout.daemon = True
    thr_stdout.start()
    thr_stderr = Thread(target=process_stderr, args=('server', ret))
    thr_stderr.daemon = True
    thr_stderr.start()
    try:
        wait_till_open(server_host, server_port)
    except ValueError:
        print_all_from_queue()
        raise
    return ret, thr_stdout, thr_stderr


def count_tc_passes(line):
    global pass_count
    global fail_count
    if line.find(':successful: ') >= 0:
        number = int(line.split(' ')[-1])
        with pass_lock:
            pass_count += number
    elif line.find(':failed: ') >= 0:
        number = int(line.split(' ')[-1])
        with fail_lock:
            fail_count += number


def print_all_from_queue():
    while True:
        try:
            line = out.get(False)
            count_tc_passes(line)
            print(line, file=sys.stderr)
        except queue.Empty:
            break


def flush_queue():
    while True:
        try:
            line = out.get(False)
            count_tc_passes(line)
        except queue.Empty:
            break


def run_clients(tests, srv, expected_size):
    good = 0
    bad = 0
    failed = []
    print_all_from_queue()
    for params in tests:
        script = params["name"]
        logger.info("{0}:started".format(script))
        start_time = time.time()
        proc_args = ['python', '-u',
                     'scripts/{0}'.format(script)]
        arguments = params.get("arguments", [])
        arguments = [expected_size if arg == "{expected_size}" else arg for
                     arg in arguments]
        proc_args.extend(arguments)
        my_env = os.environ.copy()
        my_env["PYTHONPATH"]="."
        proc = Popen(proc_args, env=my_env,
                     stdout=PIPE, stderr=PIPE, bufsize=1)
        thr_stdout = Thread(target=process_stdout, args=(script, proc))
        thr_stderr = Thread(target=process_stderr, args=(script, proc))
        thr_stdout.start()
        thr_stderr.start()
        thr_stdout.join()
        thr_stderr.join()
        proc.wait()
        ret = proc.returncode
        if srv.returncode is not None:
            logger.critical("Server process not active")
        end_time = time.time()
        if ret == 0 and params.get("exp_pass", True) or \
                ret != 0 and not params.get("exp_pass", True):
            good += 1
            logger.info("{0}:finished:{1:.2f}s".format(script,
                                                   end_time - start_time))
            flush_queue()
        else:
            bad += 1
            print_all_from_queue()
            logger.error("{0}:failure:{1:.2f}s:{2}".format(script,
                                                       end_time - start_time,
                                                       ret))
            failed.append(proc_args)

    return good, bad, failed


def run_with_json(config_file, srv_path, expected_size):
    with open(config_file) as f:
        config = json.load(f)

    good = 0
    bad = 0
    failed = []

    for srv_conf in config:
        command = srv_conf["server_command"]
        for number, value in enumerate(command):
            if value == "{command}":
                command[number] = srv_path
                break
        environment = srv_conf.get("environment", tuple())
        server_host = srv_conf.get("server_hostname", "localhost")
        server_port = srv_conf.get("server_port", 4433)

        srv, srv_out, srv_err = start_server(command, environment,
                                             server_host,
                                             server_port)
        logger.info("Server process started")

        try:
            n_good, n_bad, f_cmds = run_clients(srv_conf["tests"], srv,
                                                expected_size)
            good += n_good
            bad += n_bad
            failed.extend(f_cmds)

        finally:
            try:
                logging.debug("Killing server process")
                srv.send_signal(15)  # SIGTERM
                srv.wait()
                logging.debug("Server process killed: {0}".format(srv.returncode))
            except OSError:
                logging.debug("Can't kill server process")
        srv_err.join()
        srv_out.join()

    return good, bad, failed


def main():
    if len(sys.argv) != 4:
        print("provide path to config file, server executable and expected reply size")
        sys.exit(2)

    good, bad, failed = run_with_json(sys.argv[1], sys.argv[2], sys.argv[3])

    logging.shutdown()

    print("Ran {0} test cases".format(pass_count + fail_count))
    print("expected pass: {0}".format(pass_count))
    print("expected fail: {0}\n".format(fail_count))

    print("Ran {0} scripts".format(good + bad))
    print("good: {0}".format(good))
    print("bad: {0}".format(bad))
    if failed:
        print("Failed script configurations:")
        for i in failed:
            print(" {0!r}".format(i))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
