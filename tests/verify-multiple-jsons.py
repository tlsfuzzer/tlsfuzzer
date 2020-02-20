#!/usr/bin/python

import os
from os import listdir, path
import json
from os.path import isfile, join, dirname, abspath
from sys import argv

parent_dir = dirname(dirname(abspath(__file__)))
scriptlist = [f for f in listdir(os.path.join(parent_dir,'scripts')) if isfile(join(os.path.join(parent_dir,'scripts'), f))]
jsonfiles = []
status = 0
for arg in argv[1:]:
    try:
        with open(arg) as f:
            jsonfiles.append(json.load(f))
    except IOError:
        print("Please check the input:'{0}', file doesn't appear to exist".format(arg))
        status =1
        continue
    except ValueError:
        print("Wrong file:'{0}' type: The input must be a json file".format(arg))
        status =1
        continue
    except IndexError:
        print("No input file was provided")
        status =1
        continue

missing = []
for f in scriptlist:
    if f not in str(jsonfiles):
        missing.append(f)
if not missing:
    print("\nAll scripts are in the json file")
else:
    print("\nThere are {0} scripts that are missing from {1}:".format(len(missing), arg))
    print("\n".join(missing))
    status = 1

missing = []
for test_script in scriptlist:
    script_path = os.path.join(parent_dir, 'scripts', test_script)
    with open(script_path, 'r') as f:
        script_content = f.read()
    if script_content.find('signature_algorithms') != -1:
        if script_content.find('signature_algorithms_cert') == -1:
            missing.append(test_script)
            status = 1

if not missing:
    print("All files that contain signature_algorithms,")
    print("also contain signature_algorithms_cert.")
else:
    print("There are {0} scripts that are missing signature_algorithms_cert:".format(len(missing)))
    print("\n".join(missing))

exit(status)
