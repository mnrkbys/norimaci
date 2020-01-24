#!/usr/bin/env python3
#
# norimaci.py
# Simple and light weight malware analysis sandbox for macOS.
# This script offers features similar to "Noriben.py".
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

import os
import sys
import argparse
import datetime
import json
import subprocess
import time
import codecs
import hashlib
import re
import traceback

try:
    import applescript
    has_applescript = True
except ImportError:
    has_applescript = False

has_internet = False

config = {
    'monitor_app': '/Applications/Monitor.app',
    'praudit': '/usr/sbin/praudit',
    'openbsm_data_conv': './openbsmconv.py',
    'monitor_data_conv': './monitorappconv.py',
    'debug': False,
    'haedless': False,
    'troubleshoot': False,
    'timeout_seconds': 0,
    'virustotal_api_key': '',
    'yara_folder': '',
    'hash_type': 'SHA256',
    'txt_extension': 'txt',
    'output_folder': '',
    'global_whitelist_append': '',
}

whitelist_process = [
    {'record_type': 'info'},
    {'record_type': 'procexec', 'path': r'/usr/libexec/xpcproxy', 'ppid': 1},  # for Monitor.app
    {'record_type': 'procexec', 'procname': r'/sbin/launchd', 'path': r'xpcproxy', 'ppid': 1},  # for OpenBSM
    {'record_type': 'procexec', 'path': r'(/System/Library/CoreServices/)?iconservicesagent?', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/System/Library/CoreServices/)?iconservicesagent?', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/System/Library/CoreServices/)?iconservicesagent?', 'ppid': 1},
    {'record_type': 'folder_create', 'procname': r'(/System/Library/CoreServices/)?iconservicesagent?', 'ppid': 1},
    {'record_type': 'folder_delete', 'procname': r'(/System/Library/CoreServices/)?iconservicesagent?', 'ppid': 1},
    {'record_type': 'procexec', 'path': r'(/System/Library/CoreServices/)?iconservicesd', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/System/Library/CoreServices/)?iconservicesd', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/System/Library/CoreServices/)?iconservicesd', 'ppid': 1},
    {'record_type': 'procexec', 'path': r'/usr/libexec/periodic-wrapper', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/usr/sbin/)?cfprefsd', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/usr/sbin/)?cfprefsd', 'ppid': 1},
    {'record_type': 'file_delete', 'procname': r'(/usr/sbin/)?cfprefsd', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/System/Library/Frameworks/OpenGL\.framework/Versions/A/Libraries/)?CVMServer', 'ppid': 1},
    {'record_type': 'file_delete', 'procname': r'(/System/Library/Frameworks/OpenGL\.framework/Versions/A/Libraries/)?CVMServer', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/System/Library/PrivateFrameworks/XprotectFramework\.framework/Versions/A/XPCServices/XprotectService\.xpc/Contents/MacOS/XprotectService/)?XprotectService', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/System/Library/PrivateFrameworks/XprotectFramework\.framework/Versions/A/XPCServices/XprotectService\.xpc/Contents/MacOS/XprotectService/)?XprotectService', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/usr/libexec/)?logd', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/usr/libexec/)?logd', 'ppid': 1},
    # 'Spotlight',
    {'record_type': 'file_write', 'procname': r'corespotlightd', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/System/Library/Frameworks/CoreServices\.framework/Frameworks/Metadata\.framework/Support/)?mds', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/System/Library/Frameworks/CoreServices\.framework/Frameworks/Metadata\.framework/Support/)?mds', 'ppid': 1},
    {'record_type': 'file_delete', 'procname': r'(/System/Library/Frameworks/CoreServices\.framework/Frameworks/Metadata\.framework/Support/)?mds', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/System/Library/Frameworks/CoreServices\.framework/Frameworks/Metadata\.framework/Versions/A/Support/)?mds_stores', 'ppid': 1},
    {'record_type': 'procexec', 'path': r'/System/Library/Frameworks/CoreServices\.framework/(Versions/A/)?Frameworks/Metadata\.framework/Versions/A/Support/mdworker', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'mdworker', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'mdworker', 'ppid': 1},
    {'record_type': 'procexec', 'path': r'/System/Library/Frameworks/CoreServices\.framework/(Versions/A/)?Frameworks/Metadata\.framework/Versions/A/Support/mdworker_shared', 'ppid': 1},
    {'record_type': 'dylib_load', 'procname': r'mdworker_shared', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'mdworker_shared', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'mdworker_shared', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/usr/libexec/)?lsd', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/usr/libexec/)?lsd', 'ppid': 1},
    {'record_type': 'procexec', 'procname': r'(/usr/libexec/)?trustd', 'ppid': 1},
    {'record_type': 'socket_connection', 'procname': r'(/usr/libexec/)?trustd', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/usr/libexec/)?trustd', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/usr/libexec/)?trustd', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'fud', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'fud', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'(/usr/libexec/)?nehelper', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'(/usr/libexec/)?nehelper', 'ppid': 1},
    {'record_type': 'folder_create', 'procname': r'(/usr/libexec/)?nehelper', 'ppid': 1},
    {'record_type': 'folder_delete', 'procname': r'(/usr/libexec/)?nehelper', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'pbs', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'pbs', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'mobileassetd', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'mobileassetd', 'ppid': 1},
    {'record_type': 'dylib_load', 'procname': r'com\.apple\.MediaL', 'path': r'/Library/Application Support/iLifeMediaBrowser/Plug-Ins/iLMB.+', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'/System/Library/CoreServices/sharedfilelistd', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'/System/Library/CoreServices/sharedfilelistd', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'/System/Library/Frameworks/MediaLibrary.framework/Versions/A/XPCServices/com.apple.MediaLibraryService.xpc/Contents/MacOS/com.apple.MediaLibraryService', 'ppid': 1},
    {'record_type': 'file_rename', 'procname': r'/System/Library/Frameworks/MediaLibrary.framework/Versions/A/XPCServices/com.apple.MediaLibraryService.xpc/Contents/MacOS/com.apple.MediaLibraryService', 'ppid': 1},
    {'record_type': 'file_delete', 'procname': r'/System/Library/Frameworks/MediaLibrary.framework/Versions/A/XPCServices/com.apple.MediaLibraryService.xpc/Contents/MacOS/com.apple.MediaLibraryService', 'ppid': 1},
    {'record_type': 'folder_create', 'procname': r'/System/Library/Frameworks/MediaLibrary.framework/Versions/A/XPCServices/com.apple.MediaLibraryService.xpc/Contents/MacOS/com.apple.MediaLibraryService', 'ppid': 1},
    {'record_type': 'procexec', 'path': r'/usr/libexec/AssetCache/AssetCache', 'ppid': 1},
    {'record_type': 'file_write', 'procname': r'/usr/libexec/AssetCache/AssetCache', 'ppid': 1},
    {'record_type': 'folder_create', 'procname': r'/usr/libexec/AssetCache/AssetCache', 'ppid': 1},
]

whitelist_file = [
    {'record_type': 'file_write', 'path': r'.+/\.DS_Store$'},
    {'record_type': 'file_write', 'path': r'/Users/.+/Library/Containers/com\.apple\.Safari/Data/Library/Caches/com\.apple\.Safari/WebKitCache/Version \d+/Records/.+'},
    {'record_type': 'file_rename', 'oldpath': r'/Users/.+/Library/Containers/com\.apple\.Safari/Data/Library/Caches/com\.apple\.Safari/WebKitCache/Version \d+/Records/.+'},
    {'record_type': 'file_rename', 'newpath': r'/Users/.+/Library/Containers/com\.apple\.Safari/Data/Library/Caches/com\.apple\.Safari/WebKitCache/Version \d+/Records/.+'},
    {'record_type': 'file_write', 'path': r'/private/var/folders/.+/.+/T(/.+)?/TemporaryItems/\(A Document Being Saved By .+\)/.+'},
    {'record_type': 'file_rename', 'oldpath': r'/private/var/folders/.+/.+/T(/.+)?/TemporaryItems/\(A Document Being Saved By .+\)/.+'},
    {'record_type': 'dylib_load', 'path': r'/private/var/db/CVMS/cvmsCodeSignObj.+'},
]

whitelist_hash = []

# initialize with empty list
auto_whitelist_pid = list()

__VERSION__ = '0.1.0'
virustotal_upload = True if config['virustotal_api_key'] else False
use_virustotal = True if config['virustotal_api_key'] and has_internet else False
file_debug = None
time_exec = 0
time_process = 0

# initialize with empty dict
# {pid: process full path}
process_full_path = dict()
# {path: True or False}
process_codesign_verify = dict()


def match_whitelist(whitelist, record):
    for whitelist_entry in whitelist:
        match_num = 0
        for element_type in whitelist_entry.keys():
            # These elements below has integer type value as their data
            if element_type in ['pid', 'ppid', 'uid', 'gid', 'euid', 'egid', 'is64', 'argc', 'version', 'srcport', 'dstport', 'dev']:
                if record[element_type] == whitelist_entry[element_type]:
                    match_num = match_num + 1
                else:
                    break
            else:
                try:
                    if element_type in record and re.match(whitelist_entry[element_type], record[element_type]):
                        match_num = match_num + 1
                    else:
                        break
                except Exception:
                    dbg_print('[!] Error found while processing filters.\r\nFilter:\t{}\r\nEvent:\t{}'.format(whitelist_entry[element_type], record))
                    dbg_print(traceback.format_exc())
                    return False

            if match_num == len(whitelist_entry.keys()):
                dbg_print("----- Filtered!! ----- {}".format(record))
                return True

    dbg_print("----- NOT Filtered!! ----- {}".format(record))
    return False


def match_auto_whitelist(auto_whitelist, record):
    if 'ppid' in record and record['ppid'] in auto_whitelist:
        dbg_print("----- Filtered!! (Auto) ----- {}".format(record))
        return True
    else:
        return False


def check_persistence_path(path):
    persistence_path_list = [
        r'(/System)?/Library/LaunchDaemons/.+\.plist$',
        r'(/System)?/Library/LaunchAgents/.+\.plist$',
        r'/Users/.+/Library/LaunchAgents/.+\.plist$',
        r'(/private)?/var/.+/Library/LaunchAgents/.+\.plist$',
        r'(/private)?/var/db/com\.apple\.xpc\.launchd/disabled\..+\.plist',
        r'(/private)?/var/at/tabs/.+',
        r'(/System)?/Library/ScriptingAdditions/.+\.osax$',
        r'(/System)?/Library/StartupItems/.+',
        r'(/private)?/etc/periodic\.conf$',
        r'(/private)?/etc/periodic/.+/.+',
        r'(/private)?/etc/.*\.local$',
        r'(/private)?/etc/rc\.common$',
        r'(/private)?/etc/emond\.d/.+',
        r'(/Users/.+|(/private)?/var)/Library/Preferences/com\.apple\.loginitems\.plist$',
        r'/Users/.+/Library/Application Support/com\.apple\.backgroundtaskmanagementagent/backgrounditems\.btm$',
    ]

    for persistence_path in persistence_path_list:
        if re.match(persistence_path, path):
            return True

    return False


def decode_json_obj(data):
    try:
        record, index = json.JSONDecoder().raw_decode(data)
        if config['debug']:
            print("{} : {}".format(record, index))
        return record, index
    except json.JSONDecodeError:
        raise


# load JSON data stream from a file
def load_json_file(file_path, whitelist, auto_whitelist):
    event_records = []
    read_data_size = 0

    try:
        fp = codecs.open(file_path, 'r', 'utf-8')
        json_file_size = os.path.getsize(file_path)
    except OSError as err:
        sys.exit('[!] Fatal: Error in load_json_file(): {}'.format(err))

    data = fp.read(4096)
    read_data_size = len(data)
    data = data.replace('\n', '')
    while True:
        if data or read_data_size < json_file_size:
            try:
                record, index = decode_json_obj(data)
                # if match_auto_whitelist(auto_whitelist, record) or match_whitelist(whitelist, record):
                if match_whitelist(whitelist, record):
                    data = data[index:]
                    if ('pid' in record and record['pid'] not in auto_whitelist) and \
                            ('procname' in record and record['procname'] != r'/usr/libexec/xpcproxy') and \
                            ('procname' in record and record['procname'] != r'/sbin/launchd'):
                        auto_whitelist.append(record['pid'])
                        dbg_print("Appended to auto_whitelist : {}".format(auto_whitelist))
                    continue
                else:
                    if record['record_type'] == 'procexec':
                        process_full_path[record['pid']] = record['path']
                    event_records.append(record)
                    data = data[index:]
            except json.JSONDecodeError:
                tmp = fp.read(4096)
                read_data_size += len(tmp)
                tmp = tmp.replace('\n', '')
                data += tmp
        else:
            fp.close()
            break

    return event_records


def get_proc_list():
    # https://codeday.me/jp/qa/20190310/380909.html
    try:
        proc_stat = dict()
        proc_stat[0] = dict()
        proc_stat[0]['procname'] = 'kernel_task'
        proc_stat[0]['ppid'] = 0

        process_list = [(int(pid), int(ppid), comm) for pid, ppid, comm in [x.strip().split(maxsplit=2) for x in os.popen('ps -Ao pid,ppid,comm')][1:]]
        for pid, ppid, procname in process_list:
            proc_stat[pid] = dict()
            proc_stat[pid]['procname'] = procname
            proc_stat[pid]['ppid'] = ppid
        return proc_stat
    except (OSError, KeyError) as err:
        sys.exit(err)


def save_proc_list(file_proc_list, proc_stat):
    try:
        with open(file_proc_list, 'wt') as fp:
            json.dump(proc_stat, fp, ensure_ascii=False, indent=4)
            return True
    except OSError as err:
        sys.exit(err)


def launch_openbsm(fp):
    global time_exec
    time_exec = time.time()

    try:
        return subprocess.Popen([config['praudit'], '-ls', '/dev/auditpipe'], stdout=fp)
    except (OSError, ValueError) as err:
        sys.exit('[!] Fatal: Error in launch_openbsm: {}'.format(err))


def terminate_openbsm(proc_openbsm, fp):
    global time_exec
    time_exec = time.time() - time_exec

    try:
        proc_openbsm.terminate()
        returncode = None
        # time.sleep(2)
        while returncode is None:
            time.sleep(0.1)
            returncode = proc_openbsm.poll()
        fp.close()
        # return proc_openbsm.returncode
        return returncode
    except Exception as err:
        sys.exit('[!] Fatal: Error in terminate_openbsm: {}'.format(err))


def launch_monitor_app():
    global time_exec
    time_exec = time.time()

    if not os.path.exists(config['monitor_app']):
        sys.exit('[!] Monitor.app does not exist: {}'.format(config['monitor_app']))

    scpt = applescript.AppleScript('''
        tell application "Monitor"
            activate
            delay 1
        end tell
        ''')
    scpt.run()
    toggle_monitoring()


def terminate_monitor_app():
    global time_exec
    time_exec = time.time() - time_exec

    scpt = applescript.AppleScript('''
        tell application "Monitor"
            -- activate
            delay 1
        end tell
        ''')
    scpt.run()
    toggle_monitoring()


def save_monitor_app_data(output_folder, filename):
    scpt1 = ('''
        tell application "System Events"
            tell process "Monitor"
                set frontmost to true
                -- activate
                delay 1
                key code 1 using {shift down, command down} -- Save As
        ''')
    scpt2 = ('''
                -- delay 0.5
                -- keystroke "/"
                delay 0.5
                keystroke "{}"
                delay 0.5
                key code 36 -- Enter
                delay 1
                keystroke "{}"
                delay 0.5
                key code 36 -- Enter
            end tell
        end tell
        '''.format(output_folder, filename))
    scpt = applescript.AppleScript(scpt1 + scpt2)
    scpt.run()


def quit_monitor_app():
    scpt = applescript.AppleScript('''
        tell application "Monitor"
            delay 1
            activate
            quit
        end tell
        ''')
    scpt.run()


def toggle_monitoring():
    scpt = applescript.AppleScript('''
        tell application "System Events"
            tell process "Monitor"
                tell window "Monitor"
                    click checkbox 4
                    -- checkbox 0 : Filters Process Events
                    -- checkbox 1 : Filters Process Events
                    -- checkbox 2 : Filters File Events
                    -- checkbox 3 : Filters Network Events
                    -- checkbox 4 : Monitor button
                    -- checkbox 5 : Scroll Enable/Disable
                    -- button 1 : Clear Log
                end tell
            end tell
        end tell
        ''')
    scpt.run()


def get_session_name():
    return datetime.datetime.now().strftime('%d_%b_%y__%H_%M_%f')


def get_script_dir():
    return os.path.dirname(os.path.abspath(sys.argv[0]))


def launch_data_converter(monitor, file_monitor, file_json, file_proclist=None):
    script_dir = get_script_dir()
    try:
        if monitor == 'openbsm':
            if file_proclist:
                converter_cmd = ('python3', os.path.join(script_dir, config['openbsm_data_conv']), '-p', file_proclist, '--with-failure-socket')
            else:
                converter_cmd = ('python3', os.path.join(script_dir, config['openbsm_data_conv']), '--with-failure-socket')
        elif monitor == 'monitorapp':
            converter_cmd = ('python3', os.path.join(script_dir, config['monitor_data_conv']))
        else:
            sys.exit('[!] Error: Unknown monitor type: {}'.format(monitor))

        try:
            subprocess.run([*converter_cmd, '-f', file_monitor, '-o', file_json, '--force'], check=True)
        except subprocess.CalledProcessError as err:
            sys.exit('[!] Fatal: Failed to run data converter: {}'.format(err))
    except OSError as err:
        sys.exit('[!] Fatal: Error in launch_data_converter: {}'.format(err))


def calc_file_hash(file):
    if config['hash_type'] == 'MD5':
        return hashlib.md5(codecs.open(file, 'rb').read()).hexdigest()
    elif config['hash_type'] == 'SHA1':
        return hashlib.sha1(codecs.open(file, 'rb').read()).hexdigest()
    elif config['hash_type'] == 'SHA256':
        return hashlib.sha256(codecs.open(file, 'rb').read()).hexdigest()


def virustotal_query_hash(hashval):
    pass


# verify code signature of external command file
def verify_codesign(cmd):
    try:
        if not subprocess.call(['/usr/bin/codesign', '--verify', cmd]):
            return True
        else:
            sys.exit('[!] Fatal: Failed to verify code signature: {}'.format(cmd))
    except OSError as err:
        sys.exit('[!] Fatal: Error in verify_codesign(): {}'.format(err))


def dbg_print(msg):
    if msg and config['debug']:
        print('{}'.format(msg))
        if file_debug:
            codecs.open(file_debug, 'a', 'utf-8').write('{}\n'.format(msg))
            return True

    return False


def parse_dns_reply(dns_reply):
    ip_addresses = list()
    query_host = dns_reply['dns']['dns_query']

    for dns_response in dns_reply['dns']['dns_replies']:
        host, ttl, dns_class, record_type, address = dns_response.split()
        if host == query_host:
            if record_type == 'CNAME':
                query_host = address
            elif record_type == 'A':
                ip_addresses.append(address)

    return '|'.join(ip_addresses)


def analyze_events(event_records, report, timeline):
    report_process = list()
    report_file = list()
    report_kext = list()
    report_dylib = list()
    # report_plist = list()
    report_persistence = list()
    report_network = list()
    report_dns = list()
    report_tty = list()
    report_error = list()
    remote_servers = list()

    time_parse_start = time.time()

    for event in event_records:
        outputtext = ''
        tl_text = ''
        date_stamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event['timestamp'])) + '.' + format(event['timestamp_ns'], '09d')

        if event['pid'] in process_full_path:
            procname = process_full_path[event['pid']]
        else:
            procname = event['procname']

        if event['record_type'] == 'procexec':
            if event['ppid'] in process_full_path:
                pprocname = process_full_path[event['ppid']]
            else:
                pprocname = event['pprocname']

            argv = event['argv'].replace('\x00', ' ').strip()
            outputtext = '[CreateProcess] {}:{} > "{}"\t[Child PID: {}]'.format(pprocname, event['ppid'], argv, event['pid'])
            tl_text = '{},Process,CreateProcess,{},{},{},{}'.format(date_stamp, pprocname, event['ppid'], argv, event['pid'])
            report_process.append(outputtext)
            timeline.append(tl_text)

        elif event['record_type'] == 'file_write':
            path = event['path']
            yara_hits = ''
            # if config['yara_folder'] and yara_rules:
            #     yara_hits = yara_filescan(path, yara_rules)

            if os.path.isdir(path):
                outputtext = '[CreateFolder] {}:{} > {}'.format(procname, event['pid'], path)
                tl_text = '{},File,CreateFolder,{},{},{}'.format(date_stamp, procname, event['pid'], path)
                report_file.append(outputtext)
                timeline.append(tl_text)
            else:
                try:
                    hashval = calc_file_hash(path)
                    if hashval in whitelist_hash:
                        dbg_print('[_] Skipping hash: {}'.format(hashval))
                        continue

                    av_hits = ''
                    if use_virustotal and has_internet:
                        av_hits = virustotal_query_hash(hashval)

                    outputtext = '[CreateFile] {}:{} > {}\t[{}: {}]{}{}'.format(procname, event['pid'], path, config['hash_type'], hashval, yara_hits, av_hits)
                    tl_text = '{},File,CreateFile,{},{},{},{},{},{},{}'.format(date_stamp, procname, event['pid'], path, config['hash_type'], hashval, yara_hits, av_hits)
                    report_file.append(outputtext)
                    timeline.append(tl_text)

                    if check_persistence_path(path):
                        outputtext = '[Persistence] {}:{} > {}\t[{}: {}]{}{}'.format(procname, event['pid'], path, config['hash_type'], hashval, yara_hits, av_hits)
                        tl_text = '{},File,Persistence,{},{},{},{},{},{},{}'.format(date_stamp, procname, event['pid'], path, config['hash_type'], hashval, yara_hits, av_hits)
                        report_persistence.append(outputtext)
                        timeline.append(tl_text)

                except (IndexError, IOError):
                    outputtext = '[CreateFile] {}:{} > {}\t[File no longer exists]'.format(procname, event['pid'], path)
                    tl_text = '{},File,CreateFile,{},{},{},N/A'.format(date_stamp, procname, event['pid'], path)
                    report_file.append(outputtext)
                    timeline.append(tl_text)

                    if check_persistence_path(path):
                        outputtext = '[Persistence] {}:{} > {}\t[File no longer exists]'.format(procname, event['pid'], path)
                        tl_text = '{},File,Persistence,{},{},{},N/A'.format(date_stamp, procname, event['pid'], path)
                        report_persistence.append(outputtext)
                        timeline.append(tl_text)

        elif event['record_type'] == 'file_rename':
            outputtext = '[RenameFile] {}:{} > {} => {}'.format(procname, event['pid'], event['oldpath'], event['newpath'])
            tl_text = '{},File,RenameFile,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['oldpath'], event['newpath'])
            report_file.append(outputtext)
            timeline.append(tl_text)

            if check_persistence_path(event['newpath']):
                outputtext = '[Persistence] {}:{} > {} => {}'.format(procname, event['pid'], event['oldpath'], event['newpath'])
                tl_text = '{},File,Persistence,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['oldpath'], event['newpath'])
                report_persistence.append(outputtext)
                timeline.append(tl_text)

        elif event['record_type'] == 'file_delete':
            path = event['path']
            outputtext = '[DeleteFile] {}:{} > {}'.format(procname, event['pid'], path)
            tl_text = '{},File,DeleteFile,{},{},{}'.format(date_stamp, procname, event['pid'], path)
            report_file.append(outputtext)
            timeline.append(tl_text)

        elif event['record_type'] == 'folder_create':
            path = event['path']
            outputtext = '[CreateFolder] {}:{} > {}'.format(procname, event['pid'], path)
            tl_text = '{},File,CreateFolder,{},{},{}'.format(date_stamp, procname, event['pid'], path)
            report_file.append(outputtext)
            timeline.append(tl_text)

        elif event['record_type'] == 'folder_delete':
            path = event['path']
            outputtext = '[DeleteFolder] {}:{} > {}'.format(procname, event['pid'], path)
            tl_text = '{},File,DeleteFolder,{},{},{}'.format(date_stamp, procname, event['pid'], path)
            report_file.append(outputtext)
            timeline.append(tl_text)

        elif event['record_type'] == 'kext_load':
            outputtext = '[LoadKext] {}:{} == {}'.format(procname, event['pid'], event['path'])
            tl_text = '{},File,LoadKext,{},{},{}'.format(date_stamp, procname, event['pid'], event['path'])
            report_kext.append(outputtext)
            timeline.append(tl_text)

        elif event['record_type'] == 'dylib_load':
            outputtext = '[LoadDylib] {}:{} == {}'.format(procname, event['pid'], event['path'])
            tl_text = '{},File,LoadDylib,{},{},{}'.format(date_stamp, procname, event['pid'], event['path'])
            report_dylib.append(outputtext)
            timeline.append(tl_text)

        elif event['record_type'] == 'socket_connection':
            if event['proto'] == 'tcp' and event['direction'] == 'out':
                outputtext = '[TCP] {}:{} > {}:{}'.format(procname, event['pid'], event['dstip'], event['dstport'])
                if outputtext not in report_network:
                    report_network.append(outputtext)
                tl_text = '{},Network,TCP Send,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['dstip'], event['dstport'])
                timeline.append(tl_text)

            elif event['proto'] == 'tcp' and event['direction'] == 'in':
                outputtext = '[TCP] {}:{} > {}:{}'.format(event['srcip'], event['srcport'], procname, event['pid'])
                if outputtext not in report_network:
                    report_network.append(outputtext)
                tl_text = '{},Network,TCP Receive,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['srcip'], event['srcport'])
                timeline.append(tl_text)

            elif event['proto'] == 'udp' and event['direction'] == 'out':
                outputtext = '[UDP] {}:{} > {}:{}'.format(procname, event['pid'], event['dstip'], event['dstport'])
                if outputtext not in report_network:
                    report_network.append(outputtext)
                tl_text = '{},Network,UDP Send,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['dstip'], event['dstport'])
                timeline.append(tl_text)

            elif event['proto'] == 'udp' and event['direction'] == 'in':
                outputtext = '[UDP] {}:{} > {}:{}'.format(event['srcip'], event['srcport'], procname, event['pid'])
                if outputtext not in report_network:
                    report_network.append(outputtext)
                tl_text = '{},Network,UDP Receive,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['srcip'], event['srcport'])
                timeline.append(tl_text)

            elif event['proto'] == 'icmp' and event['direction'] == 'out':
                outputtext = '[ICMP] {}:{} > {}:{}'.format(procname, event['pid'], event['dstip'], event['dstport'])
                if outputtext not in report_network:
                    report_network.append(outputtext)
                tl_text = '{},Network,ICMP Send,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['dstip'], event['dstport'])
                timeline.append(tl_text)

            elif event['proto'] == 'icmp' and event['direction'] == 'in':
                outputtext = '[ICMP] {}:{} > {}:{}'.format(event['srcip'], event['srcport'], procname, event['pid'])
                if outputtext not in report_network:
                    report_network.append(outputtext)
                tl_text = '{},Network,ICMP Receive,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['srcip'], event['srcport'])
                timeline.append(tl_text)

            elif event['proto'] == 'unknown' and event['direction'] == 'out':
                outputtext = '[TCP|UDP] {}:{} > {}:{}'.format(procname, event['pid'], event['dstip'], event['dstport'])
                if outputtext not in report_network:
                    report_network.append(outputtext)
                tl_text = '{},Network,TCP|UDP Send,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['dstip'], event['dstport'])
                timeline.append(tl_text)

            elif event['proto'] == 'unknown' and event['direction'] == 'in':
                outputtext = '[TCP|UDP] {}:{} > {}:{}'.format(event['srcip'], event['srcport'], procname, event['pid'])
                if outputtext not in report_network:
                    report_network.append(outputtext)
                tl_text = '{},Network,TCP|UDP Receive,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['srcip'], event['srcport'])
                timeline.append(tl_text)

            else:
                report_error.append('Unknown protocol type: {},{}'.format(event['proto'], event['direction']))

        elif event['record_type'] == 'dns_request':
            outputtext = '[DNS] {}:{} ? {}'.format(procname, event['pid'], event['dns']['dns_query'])
            if outputtext not in report_dns:
                report_dns.append(outputtext)

            tl_text = '{},Network,DNS Query,{},{},{}'.format(date_stamp, procname, event['pid'], event['dns']['dns_query'])
            timeline.append(tl_text)

        elif event['record_type'] == 'dns_reply':
            outputtext = '[DNS] {}:{} ? {} => {}'.format(procname, event['pid'], event['dns']['dns_query'], parse_dns_reply(event))
            if outputtext not in report_dns:
                report_dns.append(outputtext)

            tl_text = '{},Network,DNS Response,{},{},{},{}'.format(date_stamp, procname, event['pid'], event['dns']['dns_query'], parse_dns_reply(event))
            timeline.append(tl_text)

        elif event['record_type'] == 'tty':
            if event['operation'] == 'create':
                outputtext = '[CreateTTY] {}:{} > TTY:{}'.format(procname, event['pid'], event['dev'])
                tl_text = '{},TTY,Create,{},{},{}'.format(date_stamp, procname, event['pid'], event['dev'])

            elif event['operation'] == 'close':
                outputtext = '[CloseTTY] {}:{} > TTY:{}'.format(procname, event['pid'], event['dev'])
                tl_text = '{},TTY,Close,{},{},{}'.format(date_stamp, procname, event['pid'], event['dev'])

            else:
                report_error.append('Unknown TTY operation: {}'.format(event['operation']))

            report_tty.append(outputtext)
            timeline.append(tl_text)

        else:
            report_error.append("Unknown record: {}".format(event))

        if ('dstip' in event) and (event['dstip'] not in remote_servers):
            if event['dstip'] != '127.0.0.1' and event['dstip'] != '::1':
                remote_servers.append(event['dstip'])

        if ('srcip' in event) and (event['srcip'] not in remote_servers):
            if event['srcip'] != '127.0.0.1' and event['srcip'] != '::1':
                remote_servers.append(event['srcip'])

    time_parse_end = time.time()

    report.append('-=] Sandbox Analysis Report generated by Norimaci v{}'.format(__VERSION__))
    report.append('-=] Developed by Minoru Kobayashi: @unkn0wnbit')
    report.append('-=] The latest release can be found at https://github.com/mnrkbys/Norimaci')
    report.append('')

    if time_exec:
        report.append('-=] Execution time: %0.2f seconds' % time_exec)
    if time_process:
        report.append('-=] Processing time: %0.2f seconds' % time_process)

    time_analyze = time_parse_end - time_parse_start
    report.append('-=] Analysis time: %0.2f seconds' % time_analyze)
    report.append('')

    report.append('Processes Created:')
    report.append('==================')
    dbg_print('[*] Writing %d Process Events results to report' % (len(report_process)))
    for event in report_process:
        report.append(event)

    report.append('')
    report.append('File Activity:')
    report.append('==================')
    dbg_print('[*] Writing %d Filesystem Events results to report' % (len(report_file)))
    for event in report_file:
        report.append(event)

    report.append('')
    report.append('dylib Files:')
    report.append('==================')
    dbg_print('[*] Writing %d dylib Files results to report' % (len(report_dylib)))
    for dylib_file in sorted(report_dylib):
        report.append(dylib_file)

    report.append('')
    report.append('kext Files:')
    report.append('==================')
    dbg_print('[*] Writing %d kext Files results to report' % (len(report_kext)))
    for kext_file in sorted(report_kext):
        report.append(kext_file)

    # report_plist
    # report.append('')
    # report.append('plist Files:')
    # report.append('==================')
    # dbg_print('[*] Writing %d plist Files results to report' % (len(report_plist)))
    # for plist_file in sorted(report_plist):
    #     report.append(plist_file)

    report.append('')
    report.append('Network Traffic:')
    report.append('==================')
    dbg_print('[*] Writing %d Network Events results to report' % (len(report_network)))
    for event in report_network:
        report.append(event)

    report.append('')
    report.append('DNS Queries:')
    report.append('==================')
    dbg_print('[*] Writing %d DNS Queries results to report' % (len(report_dns)))
    for dns_query in sorted(report_dns):
        report.append(dns_query)

    report.append('')
    report.append('Unique Hosts:')
    report.append('==================')
    dbg_print('[*] Writing %d Remote Servers results to report' % (len(remote_servers)))
    for server in sorted(remote_servers):
        report.append(server)

    report.append('')
    report.append('Persistence:')
    report.append('==================')
    dbg_print('[*] Writing %d Persistence results to report' % (len(report_persistence)))
    for persistence in sorted(report_persistence):
        report.append(persistence)

    report.append('')
    report.append('TTY:')
    report.append('==================')
    dbg_print('[*] Writing %d TTY results to report' % (len(report_tty)))
    for tty in sorted(report_tty):
        report.append(tty)

    if report_error:
        report.append('\r\n\r\n\r\n\r\n\r\n\r\nERRORS DETECTED')
        report.append('The following items could not be parsed correctly:')
        dbg_print('[*] Writing %d Output Errors results to report' % (len(report_error)))
        for error in report_error:
            report.append(error)


def main():
    global file_debug
    global time_process
    report = list()
    timeline = list()

    print('\n--===[ Norimaci v{}'.format(__VERSION__))
    print('--===[ Minoru Kobayashi [@unkn0wnbit]')

    # setup arguments
    parser = argparse.ArgumentParser(description="Light weight sandbox which works with OpenBSM or Fireeye's Monitor.app")
    parser.add_argument('-m', '--monitor', action='store', type=str, default=None,
                        help='Specify a program to monitor macOS activity. You can choose \'openbsm\' or \'monitorapp\'.')
    parser.add_argument('-j', '--json', action='store', type=str,
                        help='Path to a JSON file which is converted by \'openbsmconv.py\' or \'monitorappconv.py\'.')
    parser.add_argument('-bl', '--openbsm-log', action='store', type=str,
                        help='Path to an OpenBSM log file.')
    parser.add_argument('-p', '--proclist', action='store', default=None,
                        help='Path to a process list file to process OpenBSM log file. A file which has ".proclist" extnsion would be used, if this option is not specified.')
    parser.add_argument('-ml', '--monitorapp-log', action='store', type=str,
                        help='Path to a Monitor.app data file.')
    parser.add_argument('-o', '--output', action='store', type=str,
                        help='Path to an output directory.')
    parser.add_argument('--force', action='store_true', default=False,
                        help='Enable to overwrite output files.')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable debug mode.')
    args = parser.parse_args()

    if args.monitor not in (None, 'openbsm', 'monitorapp'):
        sys.exit('You must specify \'--monitor\' option properly.')

    if args.json and (args.openbsm_log or args.monitorapp_log):
        sys.exit('You can not specify \'--json\', \'--openbsm\' and \'--monitor\' at the same time.')

    if args.monitor == 'openbsm' and (args.openbsm_log or args.proclist):
        sys.exit('You can not specify \'--monitor openbsm\' with \'--openbsm-log\' or \'--proclist\' at the same time.')

    if args.monitor == 'monitorapp' and not has_applescript:
        sys.exit('Import Error: py-applescript and PyObjC are not installed.\n\
                py-applescript and PyObjC are needed to work in cooperation with Monitor.app.\n\
                Get them from https://github.com/rdhyee/py-applescript and https://bitbucket.org/ronaldoussoren/pyobjc \n\
                or from pip.')

    if args.monitor == 'monitorapp' and args.monitorapp_log:
        sys.exit('You can not specify both of \'--monitor monitorapp\' and \'--monitorapp-log\' at the same time.')

    if not (args.json or args.openbsm_log or args.monitorapp_log) and os.getuid() != 0:
        sys.exit('This script needs root privilege.')

    config['debug'] = args.debug

    if args.output:
        config['output_folder'] = os.path.abspath(args.output)
        if not os.path.exists(config['output_folder']):
            try:
                os.makedirs(config['output_folder'])
            except FileExistsError:
                sys.exit('[!] Fatal: Unable to create output directory: {}'.format(config['output_folder']))
    else:
        config['output_folder'] = get_script_dir()
    dbg_print('[*] Log output directory: {}'.format(config['output_folder']))

    if args.json:
        if os.path.exists(args.json):
            file_json = os.path.abspath(args.json)
            if not args.output:
                config['output_folder'] = os.path.dirname(file_json)
            file_basename = os.path.splitext(os.path.basename(args.json))[0]
            file_txt = os.path.join(config['output_folder'], file_basename + '.txt')
            file_timeline = os.path.join(config['output_folder'], file_basename + '_timeline.csv')
            file_debug = os.path.join(config['output_folder'], file_basename + '.log')
        else:
            sys.exit("[!] JSON file does not exist: {}\n".format(args.json))
    elif args.openbsm_log:
        if os.path.exists(args.openbsm_log):
            file_openbsm_log = os.path.abspath(args.openbsm_log)
            if args.proclist:
                file_proc_list = os.path.abspath(args.proclist)
            else:
                file_proc_list = os.path.splitext(file_openbsm_log)[0] + '.proclist'
            if not os.path.exists(file_proc_list):
                sys.exit('[!] Fatal: process list file does not exist: {}'.format(file_proc_list))
            if not args.output:
                config['output_folder'] = os.path.dirname(file_openbsm_log)
            file_basename = os.path.splitext(os.path.basename(args.openbsm_log))[0]
            file_json = os.path.join(config['output_folder'], file_basename + '.json')
            file_txt = os.path.join(config['output_folder'], file_basename + '.txt')
            file_timeline = os.path.join(config['output_folder'], file_basename + '_timeline.csv')
            file_debug = os.path.join(config['output_folder'], file_basename + '.log')
        else:
            sys.exit("[!] OpenBSM log file does not exist: {}\n".format(args.openbsm_log))
    elif args.monitorapp_log:
        if os.path.exists(args.monitorapp_log):
            file_monitorapp_log = os.path.abspath(args.monitorapp_log)
            if not args.output:
                config['output_folder'] = os.path.dirname(file_monitorapp_log)
            file_basename = os.path.splitext(os.path.basename(args.monitorapp_log))[0]
            file_json = os.path.join(config['output_folder'], file_basename + '.json')
            file_txt = os.path.join(config['output_folder'], file_basename + '.txt')
            file_timeline = os.path.join(config['output_folder'], file_basename + '_timeline.csv')
            file_debug = os.path.join(config['output_folder'], file_basename + '.log')
        else:
            sys.exit("[!] Monitor.app data file does not exist: {}\n".format(args.monitorapp_log))

    if not args.json:
        if not (args.openbsm_log or args.monitorapp_log):
            session_id = get_session_name()
            file_json = os.path.join(config['output_folder'], 'Norimaci_{}.json'.format(session_id))
            file_txt = os.path.join(config['output_folder'], 'Norimaci_{}.{}'.format(session_id, config['txt_extension']))
            file_timeline = os.path.join(config['output_folder'], 'Norimaci_{}_timeline.csv'.format(session_id))
            file_debug = os.path.join(config['output_folder'], 'Norimaci_{}.log'.format(session_id))

        if args.monitor == 'openbsm':
            file_openbsm_log = os.path.join(config['output_folder'], 'Norimaci_{}.bsm'.format(session_id))
            file_proc_list = os.path.join(config['output_folder'], 'Norimaci_{}.proclist'.format(session_id))
            fp_openbsm_log = open(file_openbsm_log, 'wt')
            print("[*] Launching OpenBSM agent...")
            save_proc_list(file_proc_list, get_proc_list())
            proc_openbsm = launch_openbsm(fp_openbsm_log)
        elif args.monitor == 'monitorapp':
            file_monitorapp_log = os.path.join(config['output_folder'], 'Norimaci_{}.mon'.format(session_id))
            print("[*] Launching Monitor.app...")
            launch_monitor_app()

        if args.monitor in ('openbsm', 'monitorapp'):
            if config['timeout_seconds']:
                print('[*] Running for %d seconds. Press Ctrl-C to stop logging early.' % (config['timeout_seconds']))
                # Print a small progress indicator, for those REALLY long time.sleeps.
                try:
                    for i in range(config['timeout_seconds']):
                        progress = (100 / config['timeout_seconds']) * i
                        sys.stdout.write('\r%d%% complete' % progress)
                        sys.stdout.flush()
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
            else:
                print('[*] When runtime is complete, press CTRL+C to stop logging.')
                try:
                    while True:
                        time.sleep(100)
                except KeyboardInterrupt:
                    pass

        if args.monitor == 'openbsm':
            print('\n[*] Termination of OpenBSM agent commencing... please wait')
            returncode = terminate_openbsm(proc_openbsm, fp_openbsm_log)
            if returncode != -2:  # -2 = SIGINT
                sys.exit('[!] Fatal: OpenBSM agent did not terminate properly: {}'.format(returncode))
        elif args.monitor == 'monitorapp':
            print('\n[*] Termination of Monitor.app commencing... please wait')
            terminate_monitor_app()
            save_monitor_app_data(config['output_folder'], 'Norimaci_{}.mon'.format(session_id))
            quit_monitor_app()

        time_convert_start = time.time()

        if args.monitor == 'openbsm' or args.openbsm_log:
            print('[*] Converting OpenBSM data ...')
            launch_data_converter('openbsm', file_openbsm_log, file_json, file_proc_list)
        elif args.monitor == 'monitorapp' or args.monitorapp_log:
            print('[*] Converting Monitor.app data ...')
            launch_data_converter('monitorapp', file_monitorapp_log, file_json)

        time_convert_end = time.time()
        time_process = time_convert_end - time_convert_start

    print('[*] Loading converted macOS activity data ...')
    event_records = load_json_file(file_json, whitelist_process + whitelist_file, auto_whitelist_pid)

    analyze_events(event_records, report, timeline)

    print('[*] Saving report to: {}'.format(file_txt))
    codecs.open(file_txt, 'w', 'utf-8').write('\r\n'.join(report))

    print('[*] Saving timeline to: {}'.format(file_timeline))
    codecs.open(file_timeline, 'w', 'utf-8').write('\r\n'.join(timeline))

    return 0


if __name__ == "__main__":
    if sys.version_info[0:2] >= (3, 5):
        sys.exit(main())
    else:
        sys.exit("This script needs greater than or equal to Python 3.5")
