#!/usr/bin/env python

import sys
import argparse
import subprocess
import time
import os


parser = argparse.ArgumentParser(description='Run multiple clients for '
                                             'testing HW3 clients. '
                                             'Exits with status 0 if all '
                                             'child processes exit correctly.')
parser.add_argument('-g', '--games', type=int, default=1, 
                    help='Number of games to run.')
parser.add_argument('-s', '--secs', type=int, default=2,
                    help="Seconds to wait for all games to finish.")
parser.add_argument('-p', '--port', type=int, default=5555,
                    help='The port to connect to the server process on.')
parser.add_argument('--host', default="127.0.0.1",
                    help="The host of the server to connect to.")
parser.add_argument('--sleepy', action="store_true",
                    help="If passed, half of the clients will be run in "
                         "sleepy mode, namely they will stop talking for "
                         "5 seconds in the middle of the protocol.")
args = parser.parse_args()
cur_dir = os.path.dirname(__file__)
client_cmd = os.path.join(cur_dir, 'client')

client_one_args = [client_cmd, str(args.host), str(args.port)]
client_two_args = [client_cmd, str(args.host), str(args.port)]
if args.sleepy:
    client_two_args.append('h')

child_processes = []
for i in range(args.games):
    client_one = subprocess.Popen(client_one_args)
    client_two = subprocess.Popen(client_two_args)
    child_processes.append(client_one)
    child_processes.append(client_two)

secs_passed = 0.0
while secs_passed < args.secs:
    rsp_codes = [0 if c.poll() == 0 else 1 for c in child_processes]
    num_not_zero = sum(rsp_codes)
    if num_not_zero == 0:
        sys.exit(0)
    secs_passed += .5
    time.sleep(.5)

print "FAIL"
sys.exit(1)

