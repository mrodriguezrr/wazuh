#!/usr/bin/python3
# Copyright (C) 2015-2022, Wazuh Inc.
# Adapted for MikroTik active response.

import os
import sys
import json
import datetime
from pathlib import PureWindowsPath, PurePosixPath
from librouteros import connect

if os.name == 'nt':
    LOG_FILE = "C:\\Program Files (x86)\\ossec-agent\\active-response\\active-responses.log"
else:
    LOG_FILE = "/var/ossec/logs/active-responses.log"

MT_HOST   = os.environ.get("MT_HOST", "[MK_IP_address]")
MT_USER   = os.environ.get("MT_USER", "USER")
MT_PASS   = os.environ.get("MT_PASS", "PASSWD")
MT_PORT   = int(os.environ.get("MT_PORT", "8728"))
ADDR_LIST = os.environ.get("MT_ADDR_LIST", "blacklist")
TIMEOUT? MT_TIMEOUT = os.environ.get("MT_TIMEOUT", "1h")

ADD_COMMAND = 0
DELETE_COMMAND = 1
CONTINUE_COMMAND = 2
ABORT_COMMAND = 3

OS_SUCCESS = 0
OS_INVALID = -1

class message:
    def __init__(self):
        self.alert = ""
        self.command = 0

def write_debug_file(ar_name, msg):
    with open(LOG_FILE, mode="a") as log_file:
        ar_name_posix = str(PurePosixPath(PureWindowsPath(ar_name[ar_name.find("active-response"):])) )
        log_file.write(str(datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')) +
                       " " + ar_name_posix + ": " + msg + "\n")

def setup_and_check_message(argv):
    input_str = ""
    for line in sys.stdin:
        input_str = line
        break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Invalid JSON input")
        message.command = OS_INVALID
        return message

    message.alert = data
    cmd = data.get("command")

    if cmd == "add":
        message.command = ADD_COMMAND
    elif cmd == "delete":
        message.command = DELETE_COMMAND
    else:
        message.command = OS_INVALID
        write_debug_file(argv[0], "Invalid command: " + str(cmd))
    return message

def send_keys_and_check_message(argv, keys):
    keys_msg = json.dumps({"version":1,"origin":{"name":argv[0],"module":"active-response"},
                           "command":"check_keys","parameters":{"keys":keys}})

    write_debug_file(argv[0], keys_msg)
    print(keys_msg)
    sys.stdout.flush()

    input_str = ""
    while True:
        line = sys.stdin.readline()
        if line:
            input_str = line
            break

    write_debug_file(argv[0], input_str)

    try:
        data = json.loads(input_str)
    except ValueError:
        write_debug_file(argv[0], "Invalid response JSON")
        return OS_INVALID

    action = data.get("command")
    if action == "continue":
        return CONTINUE_COMMAND
    elif action == "abort":
        return ABORT_COMMAND
    else:
        write_debug_file(argv[0], "Invalid state command")
        return OS_INVALID

def mt_add_ip(api, ip):
    api.path("ip","firewall","address-list").add(
        list=ADDR_LIST, address=ip, timeout=MT_TIMEOUT, comment="Wazuh AR"
    )

def mt_remove_ip(api, ip):
    entries = api.path("ip","firewall","address-list").select(".id","address","list")
    for e in entries:
        if e.get("list") == ADDR_LIST and e.get("address").startswith(ip):
            api.path("ip","firewall","address-list").remove(e[".id"])

def main(argv):
    write_debug_file(argv[0], "Started")
    msg = setup_and_check_message(argv)

    if msg.command < 0:
        sys.exit(OS_INVALID)

    alert = msg.alert.get("parameters", {}).get("alert", {})
    ip = (alert.get("data", {}).get("srcip")
          or msg.alert.get("parameters", {}).get("srcip")
          or msg.alert.get("srcip"))

    if not ip:
        write_debug_file(argv[0], "No srcip found")
        sys.exit(OS_SUCCESS)

    keys = [ip]
    action = send_keys_and_check_message(argv, keys)

    if action != CONTINUE_COMMAND:
        if action == ABORT_COMMAND:
            write_debug_file(argv[0], "Aborted")
            sys.exit(OS_SUCCESS)
        else:
            write_debug_file(argv[0], "Invalid state command")
            sys.exit(OS_INVALID)

    try:
        api = connect(username=MT_USER, password=MT_PASS,
                      host=MT_HOST, port=MT_PORT, timeout=5, ssl=False)
        if msg.command == ADD_COMMAND:
            mt_add_ip(api, ip)
            write_debug_file(argv[0], f"Added {ip} to {ADDR_LIST}")
        elif msg.command == DELETE_COMMAND:
            mt_remove_ip(api, ip)
            write_debug_file(argv[0], f"Removed {ip} from {ADDR_LIST}")
    except Exception as e:
        write_debug_file(argv[0], f"MikroTik error: {e}")
        sys.exit(OS_INVALID)

    write_debug_file(argv[0], "Ended")
    sys.exit(OS_SUCCESS)

if __name__ == "__main__":
    main(sys.argv)
