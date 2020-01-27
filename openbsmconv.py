#!/usr/bin/env python3
#
# openbsmconv.py
# Converts OpenBSM log file which has a output by created 'praudit -ls /dev/auditpipe' to JSON format.
#
# Copyright 2020 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import argparse
import json
import os
import platform
import sys
import datetime
import struct
import pwd
import grp

# global variables
with_failure = False
with_failure_socket = False
debug_mode = False
file_debug = None
proc_stat = dict()


# setup arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Converts OpenBSM log file to JSON format.")
    parser.add_argument('-f', '--file', action='store', default=None,
                        help='Path to a bsm log file')
    parser.add_argument('-p', '--proclist', action='store', default=None,
                        help='Path to a process list file')
    parser.add_argument('-o', '--out', action='store', default=None,
                        help='Path to an output file')
    parser.add_argument('-c', '--console', action='store_true', default=False,
                        help='Output JSON data to stdout.')
    parser.add_argument('-rp', '--use-running-proclist', action='store_true', default=False,
                        help='Use current running process list instead of a existing process list file. And, the process list is saved to a file which places in the same directory of \'--file\' or to a file which specified \'--proclist\'.')
    parser.add_argument('--with-failure', action='store_true', default=False,
                        help='Output records which has a failure status too.')
    parser.add_argument('--with-failure-socket', action='store_true', default=False,
                        help='Output records which has a failure status too (related socket() syscall only).')
    parser.add_argument('--force', action='store_true', default=False,
                        help='Enable to overwrite an existing output file.')
    parser.add_argument('--debug', action='store_true', default=False, help='Enable debug mode.')
    args = parser.parse_args()

    return args


def check_arguments(args):
    global with_failure
    global with_failure_socket
    global debug_mode
    global file_debug

    if args.file:
        file_openbsm_log = os.path.abspath(args.file)
        if not os.path.exists(file_openbsm_log):
            sys.exit('Error: OpenBSM log file does not exist: {}'.format(file_openbsm_log))
        file_out = os.path.splitext(file_openbsm_log)[0] + '.json'
        file_proclist = os.path.splitext(file_openbsm_log)[0] + '.proclist'
        file_debug = os.path.splitext(file_openbsm_log)[0] + '.log'
    else:
        sys.exit('You must specify \'--file\' option')

    if args.out:
        file_out = os.path.abspath(args.out)

    if os.path.exists(file_out) and not (args.force or args.console):
        sys.exit('Error: output file already exists: {}'.format(file_out))

    if args.proclist and args.use_running_proclist:
        sys.exit('You can not specify both of \'--proclist\' and \'--use-running-proclist\'.')

    if args.proclist:
        file_proclist = os.path.abspath(args.proclist)

    if os.path.exists(file_proclist) and not args.use_running_proclist:
        load_proclist(file_proclist)
    elif args.use_running_proclist:
        if not get_proclist():
            sys.exit('Error: Cannot get a current process list.')

        if os.path.exists(file_proclist) and not args.force:
            sys.exit('Error: process list file already exists: {}'.format(file_proclist))
        else:
            save_proclist(file_proclist)
    else:
        sys.exit('Error: process list file does not exist: {}'.format(file_proclist))

    if args.with_failure:
        with_failure = True
        with_failure_socket = True
    elif args.with_failure_socket:
        with_failure_socket = True
    # with_failure = args.with_failure
    # with_failure_socket = args.with_failure_socket
    debug_mode = args.debug

    return file_openbsm_log, file_out


def dbg_print(msg):
    if msg and debug_mode:
        print('{}'.format(msg))
        if file_debug:
            open(file_debug, 'a').write('{}\n'.format(msg))
            return True

    return False


def get_proclist():
    # https://codeday.me/jp/qa/20190310/380909.html
    try:
        proc_stat[0] = dict()
        proc_stat[0]['procname'] = 'kernel_task'
        proc_stat[0]['ppid'] = 0

        process_list = [(int(pid), int(ppid), comm) for pid, ppid, comm in [x.strip().split(maxsplit=2) for x in os.popen('ps -Ao pid,ppid,comm')][1:]]
        for pid, ppid, procname in process_list:
            proc_stat[pid] = dict()
            proc_stat[pid]['procname'] = procname
            proc_stat[pid]['ppid'] = ppid

        proc_stat[1]['xpcproxy_child_pid'] = list()
        return True
    except KeyError:
        return False


def save_proclist(file_proclist):
    try:
        global proc_stat
        with open(file_proclist, 'wt') as fp:
            json.dump(proc_stat, fp, ensure_ascii=False, indent=4)
            return True
    except OSError as err:
        sys.exit(err)


def load_proclist(file_proclist):
    try:
        global proc_stat
        with open(file_proclist, 'rt') as fp:
            proclist = json.load(fp)
            for pid, stats in proclist.items():
                proc_stat[int(pid)] = dict()
                for key, val in stats.items():
                    proc_stat[int(pid)][key] = val
            proc_stat[1]['xpcproxy_child_pid'] = list()
            return True
    except (OSError, KeyError) as err:
        sys.exit(err)


def get_proc_info(pid, element):
    if pid == 1 and element == 'ppid':
        return 1

    if (pid in proc_stat) and (element in proc_stat[pid]):
        return proc_stat[pid][element]
    elif element == 'ppid':
        return 0
    else:
        return 'unknown'


def convert_user_to_id(username):
    # https://stackoverflow.com/questions/421618/python-script-to-list-users-and-groups
    try:
        return int(pwd.getpwnam(username)[2])
    except KeyError:
        sys.exit('Error: unknown username: {}'.format(username))


def convert_group_to_id(groupname):
    try:
        return int(grp.getgrnam(groupname)[2])
    except KeyError:
        sys.exit('Error: unknown groupname: {}'.format(groupname))


def get_event_name(record):
    try:
        header, x, version, event_name, payload = record.split(',', 4)
        if header == 'header':
            if version == '11':
                return event_name, payload
            else:
                sys.exit('Error: version is invalid: {}'.format(version))
        else:
            sys.exit('Error: header is invalid: {}'.format(header))
    except ValueError as err:
        sys.exit('Error: get_event_name(): {}\nrecord: {}'.format(err, record))


def get_signed_int(return_code):
    return struct.unpack('<i', struct.pack('<I', return_code))[0]


def get_record_timestamp(payload):
    modifier, time, msec, _payload = payload.split(',', 3)
    _time = int(datetime.datetime.strptime(time, '%a %b %d %H:%M:%S %Y').timestamp())
    _msec = int(msec.split()[1])
    return _time, _msec, _payload


def get_attributes_path(payload, attr_num):
    check_attr = 0
    payload_backup = ''
    _payload = payload
    _path, _payload = _payload.split(',', 1)
    path = _path
    while len(_payload) > 0:
        _tag, _payload = _payload.split(',', 1)
        if _tag == 'path':
            _path, _payload = get_attributes_path(_payload, attr_num)
            check_attr += 1
            if payload_backup:
                payload_backup += ',' + _tag + ',' + _path
            else:
                payload_backup = _tag + ',' + _path
        elif _tag in attr_num.keys():
            if payload_backup:
                payload_backup += ',' + _tag + ',' + ','.join(_payload.split(',', attr_num[_tag])[:attr_num[_tag]])
            else:
                payload_backup = _tag + ',' + ','.join(_payload.split(',', attr_num[_tag])[:attr_num[_tag]])
            _payload = _payload.split(',', attr_num[_tag])[attr_num[_tag]]
            check_attr += 1
        else:
            path += ',' + _tag

        if check_attr == 2:
            break
    return path, payload_backup + ',' + _payload


def get_attributes(tags, payload):
    tag_attr = dict()
    payload_orig = payload
    attr_num = {
        'argument': 3,
        'path': 1,
        'subject': 9,
        'return': 2,
        'attribute': 6,
        'process_ex': 9,
        'identity': 6,
        'trailer': 1,
        'arbitrary': 4,
        'exit': 2,
        'socket-unix': 2,
        'socket-inet': 3,
        'socket-inet6': 3,
        'text': 1,
    }

    while len(payload) > 0:
        attrib_list = list()
        tag, payload = payload.split(',', 1)
        if tag in tags and tag != 'exec arg':
            attrib_list = payload.split(',', attr_num[tag])[:attr_num[tag]]
            if tag not in tag_attr:
                tag_attr[tag] = list()

            if tag == 'path':
                path, payload = get_attributes_path(payload, attr_num)
                tag_attr[tag].append(path)
                continue
            elif tag == 'argument':
                tag_attr[tag].append(attrib_list)
            else:
                tag_attr[tag] = attrib_list

            payload = payload.split(',', attr_num[tag])[attr_num[tag]]
        elif tag == 'exec arg':
            tag_attr['exec arg'] = list()
            while True:
                _tag, payload = payload.split(',', 1)
                if _tag == 'path':
                    check = list()
                    path, __payload = get_attributes_path(payload, attr_num)
                    check.append(path)
                    for i in list(range(3)):
                        __tag, __payload = __payload.split(',', 1)
                        if __tag == 'path':
                            path, __payload = get_attributes_path(__payload, attr_num)
                            check.append(__tag)
                            check.append(path)
                        else:
                            check.append(__tag)

                    if (check[0].startswith('/') and check[1] == 'path' and check[2].startswith('/') and check[3] == 'attribute') or \
                            (check[0].startswith('/') and check[1] == 'arbitrary' and check[2] == 'hex' and check[3] == 'byte') or \
                            (check[0].startswith('/') and check[1] == 'subject'):
                        payload = _tag + ',' + payload
                        break
                else:
                    tag_attr['exec arg'].append(_tag)
        else:
            if tag not in attr_num:
                sys.exit('Error: Unknown tag: {} / {}'.format(tag, payload_orig))
            payload = payload.split(',', attr_num[tag])[attr_num[tag]]

    dbg_print('tag_attr : {}'.format(tag_attr))
    return tag_attr


def set_json_record(record_num, record_type, timestamp, msec, tag_attr):
    try:
        json_record = dict()
        pid = int(tag_attr['subject'][5])
        ppid = get_proc_info(pid, 'ppid')
        json_record['record_num'] = record_num
        json_record['record_type'] = record_type
        json_record['procname'] = get_proc_info(pid, 'procname')
        json_record['pprocname'] = get_proc_info(ppid, 'procname')
        json_record['timestamp'] = timestamp
        json_record['timestamp_ns'] = msec * 1000000
        json_record['pid'] = pid
        json_record['ppid'] = ppid
        json_record['uid'] = convert_user_to_id(tag_attr['subject'][3])
        json_record['gid'] = convert_group_to_id(tag_attr['subject'][4])
        json_record['egid'] = convert_user_to_id(tag_attr['subject'][1])
        json_record['euid'] = convert_group_to_id(tag_attr['subject'][2])
        return json_record
    except KeyError:
        return None


def convert_bsm_events(bsm_file):
    global proc_stat

    aue_file_write_events = [
        # 'AUE_OPEN_RC', 'AUE_OPEN_RTC',
        'AUE_OPEN_WC', 'AUE_OPEN_WTC',
        'AUE_OPEN_RWC', 'AUE_OPEN_WRTC',
        # 'AUE_OPENAT_RC', 'AUE_OPENAT_RTC',
        'AUE_OPENAT_WC', 'AUE_OPENAT_WTC',
        'AUE_OPENAT_RWC', 'AUE_OPENAT_WRTC',
        # 'AUE_OPEN_EXTENDED_RC', 'AUE_OPEN_EXTENDED_RTC',
        'AUE_OPEN_EXTENDED_WC', 'AUE_OPEN_EXTENDED_WTC',
        'AUE_OPEN_EXTENDED_RWC', 'AUE_OPEN_EXTENDED_WRTC',
        # 'AUE_OPENBYID_RC', 'AUE_OPENBYID_RTC',
        'AUE_OPENBYID_WC', 'AUE_OPENBYID_WTC',
        'AUE_OPENBYID_RWC', 'AUE_OPENBYID_WRTC',
        'AUE_LINK', 'AUE_LINKAT', 'AUE_SYMLINK',
    ]

    aue_file_rename_events = [
        'AUE_RENAME', 'AUE_RENAMEAT',
    ]

    aue_file_delete_events = [
        'AUE_UNLINK', 'AUE_UNLINKAT',
    ]

    aue_mkdir_events = [
        'AUE_MKDIR', 'AUE_MKDIRAT', 'AUE_MKDIR_EXTENDED',
    ]

    aue_rmdir_events = [
        'AUE_RMDIR',
    ]

    aue_fork_events = [
        'AUE_FORK', 'AUE_VFORK', 'AUE_FORK1', 'AUE_DARWIN_RFORK', 'AUE_RFORK', 'AUE_PDFORK',
    ]

    aue_execve_events = [
        'AUE_EXECVE', 'AUE_MAC_EXECVE', 'AUE_FEXECVE',
    ]

    aue_posix_spawn_events = [
        'AUE_POSIX_SPAWN',
    ]

    aue_exit_events = [
        'AUE_EXIT',
    ]

    aue_socket_events = [
        'AUE_SOCKET',
    ]

    aue_connect_events = [
        'AUE_CONNECT',
    ]

    aue_send_events = [
        # 'AUE_SEND',
        'AUE_SENDTO',
        'AUE_SENDMSG',
    ]

    aue_recv_events = [
        # 'AUE_RECV',
        'AUE_RECVFROM',
        'AUE_RECVMSG',
    ]

    aue_bind_events = [
        'AUE_BIND',
    ]

    aue_listen_events = [
        'AUE_LISTEN',
    ]

    aue_accept_events = [
        'AUE_ACCEPT',
    ]

    aue_close_events = [
        'AUE_CLOSE',
        'AUE_CLOSEFROM',
    ]

    record_num = 0
    json_record = list()
    with open(bsm_file) as fp:
        for record in fp:
            record = record.strip()
            event_name, payload = get_event_name(record)
            timestamp, msec, payload = get_record_timestamp(payload)
            if event_name in aue_file_write_events:
                tag_attr = get_attributes(['path', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) != -1 or with_failure:
                    json_record.append(set_json_record(record_num, 'file_write', timestamp, msec, tag_attr))
                    json_record[-1]['path'] = tag_attr['path'][0]
                    record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == -1 and with_failure:
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_file_rename_events:
                tag_attr = get_attributes(['path', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == 0 or with_failure:
                    json_record.append(set_json_record(record_num, 'file_rename', timestamp, msec, tag_attr))
                    record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == 0:
                    if len(tag_attr['path']) == 2:
                        json_record[-1]['oldpath'] = tag_attr['path'][0]
                        json_record[-1]['newpath'] = tag_attr['path'][1]
                    elif len(tag_attr['path']) == 3:
                        json_record[-1]['oldpath'] = tag_attr['path'][0]
                        json_record[-1]['newpath'] = tag_attr['path'][2]
                    elif len(tag_attr['path']) == 4:
                        json_record[-1]['oldpath'] = tag_attr['path'][1]
                        json_record[-1]['newpath'] = tag_attr['path'][3]
                    else:
                        sys.exit('Error: Unknown rename record: {}'.format(payload))
                elif with_failure:
                    json_record[-1]['oldpath'] = tag_attr['path'][0]
                    json_record[-1]['newpath'] = '-'
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_file_delete_events:
                tag_attr = get_attributes(['path', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == 0 or with_failure:
                    json_record.append(set_json_record(record_num, 'file_delete', timestamp, msec, tag_attr))
                    record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == 0:
                    json_record[-1]['path'] = tag_attr['path'][1]
                elif with_failure:
                    idx = len(tag_attr['path']) - 1
                    json_record[-1]['path'] = tag_attr['path'][idx]
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_mkdir_events:
                tag_attr = get_attributes(['path', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == 0 or with_failure:
                    json_record.append(set_json_record(record_num, 'folder_create', timestamp, msec, tag_attr))
                    json_record[-1]['path'] = tag_attr['path'][0]
                    record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == -1 and with_failure:
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_rmdir_events:
                tag_attr = get_attributes(['path', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == 0 or with_failure:
                    json_record.append(set_json_record(record_num, 'folder_delete', timestamp, msec, tag_attr))
                    json_record[-1]['path'] = tag_attr['path'][1]
                    record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == -1 and with_failure:
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_fork_events:
                tag_attr = get_attributes(['subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) != -1 or with_failure:
                    child_pid = int(tag_attr['return'][1])
                    pid = int(tag_attr['subject'][5])
                    if child_pid > 0:
                        proc_stat[child_pid] = dict()
                        proc_stat[child_pid]['ppid'] = pid  # This operation is correct!!
                        if 'procname' in proc_stat[pid]:
                            proc_stat[child_pid]['procname'] = proc_stat[pid]['procname']

            elif event_name in aue_execve_events:
                tag_attr = get_attributes(['exec arg', 'path', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) != -1 or with_failure:
                    pid = int(tag_attr['subject'][5])
                    if pid in proc_stat:
                        proc_stat[pid]['procname'] = tag_attr['path'][1]
                        json_record.append(set_json_record(record_num, 'procexec', timestamp, msec, tag_attr))
                        json_record[-1]['path'] = tag_attr['path'][1]
                        json_record[-1]['argc'] = len(tag_attr['exec arg'])
                        tag_attr['exec arg'][0] = tag_attr['path'][1]
                        json_record[-1]['argv'] = ' '.join(tag_attr['exec arg'])
                        record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == -1 and with_failure:
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_posix_spawn_events:
                tag_attr = get_attributes(['argument', 'exec arg', 'subject', 'return', 'identity'], payload)
                if get_signed_int(int(tag_attr['return'][1])) != 0 and not with_failure:
                    continue

                if 'argument' in tag_attr:
                    pid = int(tag_attr['subject'][5])
                    child_pid = int(tag_attr['argument'][0][1], 16)
                    if pid != 1:
                        proc_stat[child_pid] = dict()
                        proc_stat[child_pid]['procname'] = tag_attr['exec arg'][0]
                        proc_stat[child_pid]['ppid'] = pid
                    elif pid == 1 and tag_attr['exec arg'][0] == 'xpcproxy':
                        proc_stat[1]['xpcproxy_child_pid'].append(child_pid)
                        proc_stat[child_pid] = dict()
                        proc_stat[child_pid]['procname'] = tag_attr['exec arg'][0]
                        proc_stat[child_pid]['ppid'] = pid
                    json_record.append(set_json_record(record_num, 'procexec', timestamp, msec, tag_attr))
                    # modify PID and PPID that has been already set
                    json_record[-1]['pid'] = child_pid
                    json_record[-1]['ppid'] = pid
                    json_record[-1]['path'] = tag_attr['exec arg'][0]
                    json_record[-1]['argc'] = len(tag_attr['exec arg'])
                    json_record[-1]['argv'] = ' '.join(tag_attr['exec arg'])
                    record_num += 1
                elif 'exec arg' in tag_attr:
                    pid = int(tag_attr['subject'][5])
                    proc_stat[pid] = dict()
                    proc_stat[pid]['procname'] = tag_attr['exec arg'][0]
                    # if pid in proc_stat[1]['xpcproxy_child_pid']:
                    if pid in proc_stat[1]['xpcproxy_child_pid'] or tag_attr['identity'][1] == 'com.apple.xpc.proxy':
                        proc_stat[1]['xpcproxy_child_pid'].append(pid)
                        proc_stat[pid]['ppid'] = 1
                    else:
                        proc_stat[pid]['ppid'] = 0
                    json_record.append(set_json_record(record_num, 'procexec', timestamp, msec, tag_attr))
                    json_record[-1]['path'] = tag_attr['exec arg'][0]
                    json_record[-1]['argc'] = len(tag_attr['exec arg'])
                    json_record[-1]['argv'] = ' '.join(tag_attr['exec arg'])
                    record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) != 0 and with_failure:
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_exit_events:
                tag_attr = get_attributes(['subject'], payload)
                pid = int(tag_attr['subject'][5])
                if 'xpcproxy_child_pid' in proc_stat[1] and pid in proc_stat[1]['xpcproxy_child_pid']:
                    proc_stat[1]['xpcproxy_child_pid'].remove(pid)

            elif event_name in aue_socket_events:
                tag_attr = get_attributes(['argument', 'subject', 'return', 'identity'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == -1 and not with_failure_socket:
                    continue

                pid = int(tag_attr['subject'][5])
                socket_domain = int(tag_attr['argument'][0][1], 16)
                socket_type = int(tag_attr['argument'][1][1], 16)
                socket_protocol = int(tag_attr['argument'][2][1], 16)
                file_desc = int(tag_attr['return'][1])
                id = tag_attr['identity'][1]

                if pid not in proc_stat:
                    proc_stat[pid] = dict()
                if 'socket' not in proc_stat[pid]:
                    proc_stat[pid]['socket'] = dict()
                if file_desc not in proc_stat[pid]['socket']:
                    proc_stat[pid]['socket'][file_desc] = dict()
                if 'socket_stat' not in proc_stat[pid]['socket'][file_desc]:
                    proc_stat[pid]['socket'][file_desc]['socket_stat'] = 'socket'

                # Guess a protocol
                if socket_domain == 2 and socket_type == 1 and socket_protocol == 1:
                    proc_stat[pid]['socket'][file_desc]['protocol'] = 'icmp'
                elif socket_domain == 2 and socket_type == 1 and socket_protocol in (0, 17) or \
                        socket_domain == 26 and socket_type == 1 and socket_protocol in (0, 17):
                    proc_stat[pid]['socket'][file_desc]['protocol'] = 'udp'
                # Apple daemons => 2:2:0
                # Google Chrome => 2:2:6
                elif socket_domain == 2 and socket_type == 1 and socket_protocol in (0, 6) or \
                        socket_domain == 2 and socket_type == 2 and socket_protocol == 0 or \
                        socket_domain == 2 and socket_type == 2 and socket_protocol == 6 or \
                        socket_domain == 700 and socket_type == 1 and socket_protocol == 2:
                    proc_stat[pid]['socket'][file_desc]['protocol'] = 'tcp'
                # Ignore socket-unix
                elif socket_domain == 1:
                    pass
                # Ignore VMware Tools
                elif id == 'com.vmware.vmware-tools-daemon':
                    pass
                else:
                    protocol = '{}:{}:{}'.format(socket_domain, socket_type, socket_protocol)
                    proc_stat[pid]['socket'][file_desc]['protocol'] = protocol
                    dbg_print('Unknown protocol domain:type:protocol => {} / {}'.format(protocol, record))

                # use this infomation for debugging unknown protocol
                proc_stat[pid]['socket'][file_desc]['socket_param'] = '{}:{}:{}'.format(socket_domain, socket_type, socket_protocol)

            elif event_name in aue_connect_events:
                tag_attr = get_attributes(['argument', 'socket-inet', 'socket-inet6', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == -1 and not with_failure_socket:
                    continue

                if 'socket-inet' in tag_attr:
                    socket_inet = 'socket-inet'
                    version = 4
                elif 'socket-inet6' in tag_attr:
                    socket_inet = 'socket-inet6'
                    version = 6
                else:
                    continue

                pid = int(tag_attr['subject'][5])
                file_desc = int(tag_attr['argument'][0][1], 16)
                dstip = tag_attr[socket_inet][2]
                dstport = int(tag_attr[socket_inet][1])

                if file_desc not in proc_stat[pid]['socket']:
                    proc_stat[pid]['socket'][file_desc] = dict()
                    proc_stat[pid]['socket'][file_desc]['protocol'] = 'unknown'
                proc_stat[pid]['socket'][file_desc]['dstip'] = dstip
                proc_stat[pid]['socket'][file_desc]['dstport'] = dstport

                json_record.append(set_json_record(record_num, 'socket_connection', timestamp, msec, tag_attr))
                json_record[-1]['version'] = version
                json_record[-1]['direction'] = 'out'
                json_record[-1]['dstip'] = dstip
                json_record[-1]['dstport'] = dstport
                json_record[-1]['proto'] = proc_stat[pid]['socket'][file_desc]['protocol']
                if 'socket_param' in proc_stat[pid]['socket'][file_desc]:
                    json_record[-1]['socket_param'] = proc_stat[pid]['socket'][file_desc]['socket_param']
                record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == -1 and with_failure_socket:
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_send_events:
                tag_attr = get_attributes(['argument', 'socket-inet', 'socket-inet6', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == -1 and not with_failure_socket:
                    continue

                if 'socket-inet' in tag_attr:
                    socket_inet = 'socket-inet'
                    version = 4
                elif 'socket-inet6' in tag_attr:
                    socket_inet = 'socket-inet6'
                    version = 6
                else:
                    continue

                pid = int(tag_attr['subject'][5])
                file_desc = int(tag_attr['argument'][0][1], 16)
                dstip = tag_attr[socket_inet][2]
                dstport = int(tag_attr[socket_inet][1])

                if 'socket' not in proc_stat[pid]:
                    proc_stat[pid]['socket'] = dict()

                if file_desc not in proc_stat[pid]['socket']:
                    proc_stat[pid]['socket'][file_desc] = dict()
                    proc_stat[pid]['socket'][file_desc]['protocol'] = 'unknown'
                proc_stat[pid]['socket'][file_desc]['dstip'] = dstip
                proc_stat[pid]['socket'][file_desc]['dstport'] = dstport

                json_record.append(set_json_record(record_num, 'socket_connection', timestamp, msec, tag_attr))
                json_record[-1]['version'] = version
                json_record[-1]['direction'] = 'out'
                json_record[-1]['dstip'] = dstip
                json_record[-1]['dstport'] = dstport
                json_record[-1]['proto'] = proc_stat[pid]['socket'][file_desc]['protocol']
                if 'socket_param' in proc_stat[pid]['socket'][file_desc]:
                    json_record[-1]['socket_param'] = proc_stat[pid]['socket'][file_desc]['socket_param']
                record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == -1 and with_failure_socket:
                    json_record[-1]['reason'] = tag_attr['return'][0]
                    json_record[-1]['result'] = 'failure'

            elif event_name in aue_recv_events:
                tag_attr = get_attributes(['argument', 'socket-inet', 'socket-inet6', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == -1 and not with_failure_socket:
                    continue

                if 'socket-inet' in tag_attr:
                    socket_inet = 'socket-inet'
                    version = 4
                elif 'socket-inet6' in tag_attr:
                    socket_inet = 'socket-inet6'
                    version = 6
                else:
                    continue

                pid = int(tag_attr['subject'][5])
                file_desc = int(tag_attr['argument'][0][1], 16)
                srcip = tag_attr[socket_inet][2]
                srcport = int(tag_attr[socket_inet][1])

                if 'socket' not in proc_stat[pid]:
                    proc_stat[pid]['socket'] = dict()

                if file_desc not in proc_stat[pid]['socket']:
                    proc_stat[pid]['socket'][file_desc] = dict()
                    proc_stat[pid]['socket'][file_desc]['protocol'] = 'unknown'
                proc_stat[pid]['socket'][file_desc]['srcip'] = srcip
                proc_stat[pid]['socket'][file_desc]['srcport'] = srcport

                if 'socket_stat' in proc_stat[pid]['socket'][file_desc]:
                    if proc_stat[pid]['socket'][file_desc]['socket_stat'] == 'bind':
                        proc_stat[pid]['socket'][file_desc]['socket_stat'] = 'recv'
                        proc_stat[pid]['socket'][file_desc]['protocol'] = 'udp'

                json_record.append(set_json_record(record_num, 'socket_connection', timestamp, msec, tag_attr))
                json_record[-1]['version'] = version
                json_record[-1]['direction'] = 'in'
                json_record[-1]['srcip'] = srcip
                json_record[-1]['srcport'] = srcport
                json_record[-1]['proto'] = proc_stat[pid]['socket'][file_desc]['protocol']
                if 'socket_param' in proc_stat[pid]['socket'][file_desc]:
                    json_record[-1]['socket_param'] = proc_stat[pid]['socket'][file_desc]['socket_param']
                record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == -1 and with_failure_socket:
                    json_record[-1]['reason'] = tag_attr['return'][0]
                    json_record[-1]['result'] = 'failure'

            elif event_name in aue_bind_events:
                tag_attr = get_attributes(['argument', 'socket-inet', 'socket-inet6', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == -1 and not with_failure_socket:
                    continue

                if 'socket-inet' in tag_attr:
                    socket_inet = 'socket-inet'
                elif 'socket-inet6' in tag_attr:
                    socket_inet = 'socket-inet6'
                else:
                    continue

                pid = int(tag_attr['subject'][5])
                file_desc = int(tag_attr['argument'][0][1], 16)
                dstip = tag_attr[socket_inet][2]
                dstport = int(tag_attr[socket_inet][1])

                if 'socket_stat' in proc_stat[pid]['socket'][file_desc]:
                    if proc_stat[pid]['socket'][file_desc]['socket_stat'] == 'socket':
                        proc_stat[pid]['socket'][file_desc]['socket_stat'] = 'bind'

                proc_stat[pid]['socket'][file_desc]['dstip'] = dstip
                proc_stat[pid]['socket'][file_desc]['dstport'] = dstport

            elif event_name in aue_listen_events:
                tag_attr = get_attributes(['argument', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == -1 and not with_failure_socket:
                    continue

                pid = int(tag_attr['subject'][5])
                file_desc = int(tag_attr['argument'][0][1], 16)

                if 'socket_stat' in proc_stat[pid]['socket'][file_desc]:
                    if proc_stat[pid]['socket'][file_desc]['socket_stat'] == 'bind':
                        proc_stat[pid]['socket'][file_desc]['socket_stat'] = 'listen'

            elif event_name in aue_accept_events:
                tag_attr = get_attributes(['argument', 'socket-inet', 'socket-inet6', 'subject', 'return'], payload)
                if get_signed_int(int(tag_attr['return'][1])) == -1 and not with_failure_socket:
                    continue

                if 'socket-inet' in tag_attr:
                    socket_inet = 'socket-inet'
                elif 'socket-inet6' in tag_attr:
                    socket_inet = 'socket-inet6'
                else:
                    continue

                pid = int(tag_attr['subject'][5])
                file_desc_listen = int(tag_attr['argument'][0][1], 16)
                file_desc = get_signed_int(int(tag_attr['return'][1]))
                srcip = tag_attr[socket_inet][2]
                srcport = int(tag_attr[socket_inet][1])

                if 'socket_stat' in proc_stat[pid]['socket'][file_desc_listen]:
                    if proc_stat[pid]['socket'][file_desc_listen]['socket_stat'] == 'listen':
                        if file_desc not in proc_stat[pid]['socket']:
                            proc_stat[pid]['socket'][file_desc] = proc_stat[pid]['socket'][file_desc_listen]
                            proc_stat[pid]['socket'][file_desc]['socket_stat'] = 'accept'
                            proc_stat[pid]['socket'][file_desc]['protocol'] = 'tcp'

                json_record.append(set_json_record(record_num, 'socket_connection', timestamp, msec, tag_attr))
                json_record[-1]['version'] = version
                json_record[-1]['direction'] = 'in'
                json_record[-1]['srcip'] = srcip
                json_record[-1]['srcport'] = srcport
                json_record[-1]['proto'] = proc_stat[pid]['socket'][file_desc]['protocol']
                if 'socket_param' in proc_stat[pid]['socket'][file_desc]:
                    json_record[-1]['socket_param'] = proc_stat[pid]['socket'][file_desc]['socket_param']
                record_num += 1

                if get_signed_int(int(tag_attr['return'][1])) == -1 and with_failure_socket:
                    json_record[-1]['result'] = 'failure'
                    json_record[-1]['reason'] = tag_attr['return'][0]

            elif event_name in aue_close_events:
                pass

    return json_record


def main():
    args = parse_arguments()
    file_openbsm_log, file_out = check_arguments(args)

    bsm_events_json = convert_bsm_events(file_openbsm_log)

    if args.console:
        for bsm_event in bsm_events_json:
            print(json.dumps(bsm_event, ensure_ascii=False, indent=4))

    if args.out:
        try:
            with open(file_out, 'wt') as out_fp:
                for bsm_event in bsm_events_json:
                    json.dump(bsm_event, out_fp, ensure_ascii=False)
                    out_fp.write('\n')
        except OSError as err:
            sys.exit(err)

    return 0


if __name__ == "__main__":
    if platform.system() != 'Darwin':
        sys.exit('This script supports macOS only.')

    if sys.version_info[0:2] >= (3, 0):
        sys.exit(main())
    else:
        sys.exit('This script needs Python 3.x')
