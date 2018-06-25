#!/usr/bin/python

import os
from os import listdir, path
import json
from os.path import isfile, join, dirname, abspath
from sys import argv

dir = dirname(dirname(abspath(__file__)))
print(dir)
scriptlist = [f for f in listdir(os.path.join(dir,'scripts')) if isfile(join(os.path.join(dir,'scripts'), f))]
missing = []

try:
	jsonfile = json.load(open(argv[1]))
except IOError:
	print("Please check the input file name, it doesn't appear to exist")
	exit(1)
except ValueError:
	print("Wrong file type: The input must be a json file")
	exit(1)
except IndexError:
	print("No input file was provided")
	exit(1)

for f in scriptlist:
	if f not in str(jsonfile):
		missing.append(f)

if not missing:
	print(" All scripts are in the json file")
	exit(0)
else:
	print("There are " + str(len(missing)) + " scripts that are missing from the file:")
	print("\n".join(missing))
	exit(1)
