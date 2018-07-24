#!/usr/bin/python

import os
from os import listdir, path
import json
from os.path import isfile, join, dirname, abspath
from sys import argv

parent_dir = dirname(dirname(abspath(__file__)))
scriptlist = [f for f in listdir(os.path.join(parent_dir,'scripts')) if isfile(join(os.path.join(parent_dir,'scripts'), f))]
status = 0
for arg in argv[1:]:
    missing = []
    try:
        jsonfile = json.load(open(arg))
    except IOError:
        print("Please check the input file name, it doesn't appear to exist")
        status =1
        continue
    except ValueError:
        print("Wrong file type: The input must be a json file")
        status =1
        continue
    except IndexError:
        print("No input file was provided")
        status =1
        continue
    for f in scriptlist:
        if f not in str(jsonfile):
            missing.append(f)
    if not missing:
        print(" All scripts are in the json file")
    else:
        print("There are {0} scripts that are missing from {1}:".format(len(missing), arg))
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
    print(" All files that contain signature_algorithms,")
    print(" also contain signature_algorithms_cert.")
else:
    print("There are {0} scripts that are missing signature_algorithms_cert:".format(len(missing)))
    print("\n".join(missing))

exit(status)
