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
skip_count = 0
xfail_count = 0
fail_count = 0
xpass_count = 0
pass_lock = threading.Lock()
skip_lock = threading.Lock()
xfail_lock = threading.Lock()
fail_lock = threading.Lock()
xpass_lock = threading.Lock()


def process_stdout(name, proc):
    try:
        for line in iter(proc.stdout.readline, b''):
            line = line.decode()
            line = line.rstrip()
            out.put("{0}:stdout:{1}".format(name, line))
    except Exception as e:
        out.put("{0}:Exception:stdout:{1}".format(name, e))
        raise e


def process_stderr(name, proc):
    try:
        for line in iter(proc.stderr.readline, b''):
            line = line.decode()
            line = line.rstrip()
            out.put("{0}:stderr:{1}".format(name, line))
    except Exception as e:
        out.put("{0}:Exception:stderr:{1}".format(name, e))
        raise e


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


def count_tc_passes(line, exp_pass):
    global skip_count
    global pass_count
    global xfail_count
    global fail_count
    global xpass_count

    if line.find(':SKIP: ') >= 0:
        number = int(line.split(' ')[-1])
        with skip_lock:
            skip_count += number
    elif line.find(':PASS: ') >= 0:
        number = int(line.split(' ')[-1])
        with pass_lock:
            pass_count += number
    elif line.find(':XFAIL: ') >= 0:
        number = int(line.split(' ')[-1])
        with xfail_lock:
            xfail_count += number
    elif line.find(':FAIL: ') >= 0:
        number = int(line.split(' ')[-1])
        if exp_pass:
            with fail_lock:
                fail_count += number
        else:
            with xfail_lock:
                xfail_count += number
    elif line.find(':XPASS: ') >= 0:
        number = int(line.split(' ')[-1])
        if exp_pass:
            with xpass_lock:
                xpass_count += number
        else:
            with pass_lock:
                pass_count += number


def print_all_from_queue(exp_pass = True):
    while True:
        try:
            line = out.get(False)
            count_tc_passes(line, exp_pass)
            print(line, file=sys.stderr)
        except queue.Empty:
            break


def flush_queue(exp_pass = True):
    while True:
        try:
            line = out.get(False)
            count_tc_passes(line, exp_pass)
        except queue.Empty:
            break


def run_clients(tests, common_args, srv, expected_size, run_only=None):
    skipped = 0
    good = 0
    bad = 0
    failed = []
    print_all_from_queue()
    for params in tests:
        script = params["name"]

        if run_only is not None and script != run_only:
            # If the test name doesn't match, count it as skipped 
            logger.info("{0}:skipped".format(script))
            skipped += 1
            continue

        logger.info("{0}:started".format(script))
        start_time = time.time()
        proc_args = [sys.executable, '-u',
                     'scripts/{0}'.format(script)]
        arguments = params.get("arguments", [])
        arguments = [expected_size if arg == "{expected_size}" else arg for
                     arg in arguments]
        proc_args.extend(common_args + arguments)
        my_env = os.environ.copy()
        path = my_env.get("PYTHONPATH")
        my_env["PYTHONPATH"] = ".:{0}".format(path) if path else "."
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
        srv.poll()
        if srv.returncode is not None:
            logger.critical("Server process not active")
            print_all_from_queue(params.get("exp_pass", True))
        end_time = time.time()
        if ret == 0 and params.get("exp_pass", True) or \
                ret != 0 and not params.get("exp_pass", True):
            good += 1
            logger.info("{0}:finished:{1:.2f}s".format(script,
                                                   end_time - start_time))
            srv.poll()
            if srv.returncode is not None:
                print_all_from_queue(params.get("exp_pass", True))
            else:
                flush_queue(params.get("exp_pass", True))
        else:
            bad += 1
            print_all_from_queue(params.get("exp_pass", True))
            logger.error("{0}:failure:{1:.2f}s:{2}".format(script,
                                                       end_time - start_time,
                                                       ret))
            failed.append(proc_args)
        srv.poll()
        if srv.returncode is not None:
            break

    return good, bad, failed, skipped


def run_with_json(config_file, srv_path, expected_size, run_only=None):
    """
    Load a provided config_file, srv_path, expected_size and an optional
      run_only (which will instruct it what to run and skip the rest)
      and run each available test with the provided json configuration file
    """
    with open(config_file) as f:
        config = json.load(f)

    skipped = 0
    good = 0
    bad = 0
    failed = []

    for srv_conf in config:
        command = srv_conf["server_command"]
        for number, value in enumerate(command):
            if value == '{python}':
                command[number] = sys.executable
                break
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
        common_args = srv_conf.get("common_arguments", [])
        try:
            n_good, n_bad, f_cmds, n_skipped = run_clients(srv_conf["tests"], common_args, srv,
                                                expected_size, run_only)
            skipped += n_skipped
            good += n_good
            bad += n_bad
            failed.extend(f_cmds)

        finally:
            try:
                logging.debug("Killing server process")
                srv.send_signal(15)  # SIGTERM
                srv.wait()
                logging.info("Server process killed: {0}".format(srv.returncode))
            except OSError:
                logging.error("Can't kill server process, retcode: {0}"
                    .format(srv.returncode))
        srv_err.join()
        srv_out.join()

    return good, bad, failed, skipped

def main():
    if len(sys.argv) not in [4, 5]:
        print("Provide path to `config file`, `server executable` and expected `reply size`")
        print("You can provide an optional 4th arg that will limit the test to just one of the scripts")
        sys.exit(2)

    # This parameter allows us to pick one test - and only run it
    #  while skipping the rest of the tests, they will not be considered skipped
    run_only = None
    if len(sys.argv) == 5:
        run_only = sys.argv[4]

    good, bad, failed, skipped = run_with_json(sys.argv[1], sys.argv[2], sys.argv[3], run_only)

    logging.shutdown()
    print(20 * '=')
    print("Ran {0} test cases".format(pass_count + fail_count + skip_count + xfail_count + xpass_count))
    print("skip {0}".format(skip_count))
    print("pass: {0}".format(pass_count))
    print("xfail: {0}".format(xfail_count))
    print("fail: {0}".format(fail_count))
    print("xpass: {0}".format(xpass_count))
    print(20 * '=')

    print("Ran {0} scripts".format(good + bad))
    print("SKIP: {0}".format(skipped))
    print("PASS: {0}".format(good))
    print("FAIL: {0}".format(bad))
    print(20 * '=')

    if failed:
        print("Failed script configurations:")
        for i in failed:
            print(" {0!r}".format(i))

    # Report if something 'bad' happened, or that no 'good' occured
    if bad > 0 or good == 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
