#!/usr/bin/env python3
#
# monitorappconv.py
# Parses data of Fireeye Monitor.app and converts it to JSON format.
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
import struct
import json

try:
    import dnslib
except ImportError:
    sys.exit("Import Error: dnslib is not installed.\n\
                Get it from https://bitbucket.org/paulc/dnslib/ or from pip.")

debug_mode = False

# data type definitions
# record delimiter
record_delimiter                    = 0x92

# record types
record_type = {}
record_type['info']                 = {}
record_type['info']['str']          = b'osx.agent.info'
record_type['info']['post']         = 0x81
record_type['file_write']           = {}
record_type['file_write']['str']    = b'osx.agent.file.write'
record_type['file_write']['post']   = 0x8B
record_type['file_rename']          = {}
record_type['file_rename']['str']   = b'osx.agent.file.rename'
record_type['file_rename']['post']  = 0x8C
record_type['kext_load']            = {}
record_type['kext_load']['str']     = b'osx.agent.kext.load'
record_type['kext_load']['post']    = 0x87
record_type['dylib_load']           = {}
record_type['dylib_load']['str']    = b'osx.agent.dylib.load'
record_type['dylib_load']['post']   = 0x87
record_type['procexec']             = {}
record_type['procexec']['str']      = b'osx.agent.procexec'
record_type['procexec']['post']     = 0x8D
record_type['socket_connection']            = {}
record_type['socket_connection']['str']     = b'osx.agent.socket.connection'
record_type['socket_connection']['post']    = 0x8A
record_type['dns_request']          = {}
record_type['dns_request']['str']   = b'osx.agent.socket.dns.request'
record_type['dns_request']['post']  = 0x86
record_type['dns_reply']            = {}
record_type['dns_reply']['str']     = b'osx.agent.socket.dns.reply'
record_type['dns_reply']['post']    = 0x86
record_type['tty']                  = {}
record_type['tty']['str']           = b'osx.agent.tty'
record_type['tty']['post']          = 0x87

# elements (common)
epost_xor_len                       = -1
epost_str_len                       = -2
epost_num                           = -4
epost_bytes                         = -8

element_type                        = {}
element_type['procname']            = {}
element_type['procname']['str']     = b'procname'
element_type['procname']['post']    = epost_xor_len
element_type['pprocname']           = {}
element_type['pprocname']['str']    = b'pprocname'
element_type['pprocname']['post']   = epost_xor_len
element_type['pid']                 = {}
element_type['pid']['str']          = b'pid'
element_type['pid']['post']         = epost_num
element_type['ppid']                = {}
element_type['ppid']['str']         = b'ppid'
element_type['ppid']['post']        = epost_num
element_type['uid']                 = {}
element_type['uid']['str']          = b'uid'
element_type['uid']['post']         = epost_num
element_type['gid']                 = {}
element_type['gid']['str']          = b'gid'
element_type['gid']['post']         = epost_num
element_type['timestamp']           = {}
element_type['timestamp']['str']    = b'timestamp'
element_type['timestamp']['post']   = epost_num
element_type['timestamp_ns']            = {}
element_type['timestamp_ns']['str']     = b'timestamp_ns'
element_type['timestamp_ns']['post']    = epost_num
element_type['egid']            = {}
element_type['egid']['str']     = b'egid'
element_type['egid']['post']    = epost_num
element_type['euid']            = {}
element_type['euid']['str']     = b'euid'
element_type['euid']['post']    = epost_num
element_type['bytes']           = {}
element_type['bytes']['str']    = b'bytes'
element_type['bytes']['post']   = epost_bytes

# element sub-type (common)
element_type_str                    = {}
element_type_str['str_1byte']       = 0xD9  # D9 <length 1byte> <str>
element_type_str['str_2byte']       = 0xDA  # DA <length 2byte> <str>
element_type_str['str_with_null']   = 0xC4  # C4 <length 1byte> <str null termination>

element_type_num                    = {}
element_type_num['num_1byte']       = 0xCC
element_type_num['num_2byte']       = 0xCD
element_type_num['num_4byte']       = 0xCE

element_type_bytes                  = {}
element_type_bytes['bytes_1byte']   = 0xC4  # C4 <bytes length 1byte> <bytes>

# elements (information)
element_type['msg']             = {}
element_type['msg']['str']      = b'msg'
element_type['msg']['post']     = epost_str_len

# elements (file manipulation / process execution)
element_type['oldpath']         = {}
element_type['oldpath']['str']  = b'oldpath'
element_type['oldpath']['post'] = epost_str_len
element_type['newpath']         = {}
element_type['newpath']['str']  = b'newpath'
element_type['newpath']['post'] = epost_str_len
element_type['path']            = {}
element_type['path']['str']     = b'path'
element_type['path']['post']    = epost_str_len
element_type['is64']            = {}
element_type['is64']['str']     = b'is64'
element_type['is64']['post']    = epost_num
element_type['argc']            = {}
element_type['argc']['str']     = b'argc'
element_type['argc']['post']    = epost_num
element_type['argv']            = {}
element_type['argv']['str']     = b'argv'
element_type['argv']['post']    = epost_str_len

# elements (socket)
element_type['version']             = {}
element_type['version']['str']      = b'version'
element_type['version']['post']     = epost_num
element_type['direction']           = {}
element_type['direction']['str']    = b'direction'
element_type['direction']['post']   = epost_xor_len
element_type['srcport']             = {}
element_type['srcport']['str']      = b'srcport'
element_type['srcport']['post']     = epost_num
element_type['dstport']             = {}
element_type['dstport']['str']      = b'dstport'
element_type['dstport']['post']     = epost_num
element_type['srcip']               = {}
element_type['srcip']['str']        = b'srcip'
element_type['srcip']['post']       = epost_xor_len
element_type['dstip']               = {}
element_type['dstip']['str']        = b'dstip'
element_type['dstip']['post']       = epost_xor_len
element_type['proto']               = {}
element_type['proto']['str']        = b'proto'
element_type['proto']['post']       = epost_xor_len

# elements (TTY)
element_type['dev']                 = {}
element_type['dev']['str']          = b'dev'
element_type['dev']['post']         = epost_num
element_type['operation']           = {}
element_type['operation']['str']    = b'operation'
element_type['operation']['post']   = epost_xor_len


# setup arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Parses data of Fireeye Monitor.app and converts it to JSON format.\n\
                                                Please note that strings in JSON data are saved as UTF-8.")
    parser.add_argument('-f', '--file', action='store', type=str,
                        help='Path to a saved data of Monitor.app.')
    parser.add_argument('-o', '--out', action='store', type=str,
                        help='Path to an output file.')
    parser.add_argument('-c', '--console', action='store_true', default=False,
                        help='Output JSON data to stdout.')
    parser.add_argument('--force', action='store_true', default=False,
                        help='Enable to overwrite an output file.')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable debug mode.')
    args = parser.parse_args()

    return args

def check_arguments(args):
    if args.file == None:
        sys.exit('Need to specify save file of Monitor.app.\nPlease confirm options with "-h".')

    if args.out == None and args.console == False:
        sys.exit('Need to specify output direction (file and/or console).\nPlease confirm options with "-h".')

    global debug_mode
    debug_mode = args.debug


def parse_saved_data(data, current_pos):
    record_head = -1
    record_tail = -1
    pos = current_pos

    while pos <= len(data):
        if pos == len(data):
            if debug_mode:
                print("record_tail = {}".format(len(data)))
            return data[record_head:len(data)], -1

        if data[pos] == record_delimiter and data[pos+2:pos+12] == b'osx.agent.' and record_head == -1:
            record_head = pos
            record_tail = record_head + 1
            if debug_mode:
                print("record_head = {}".format(record_head))

        elif (data[pos] == record_delimiter and data[pos+2:pos+12] == b'osx.agent.' and record_head != -1) or (pos == len(data)):
            record_tail = pos
            if debug_mode:
                print("record_tail = {}".format(record_tail))
            break

        pos = pos + 1

    return data[record_head:record_tail], pos


def check_record_type(rtype, record):
    rtype_length =  record[0] ^ 0xA0
    if record[1:rtype_length+1] == record_type[rtype]['str'] and record[1+rtype_length] == record_type[rtype]['post']:
        return rtype

    else:
        return None


def parse_element(elements):
    while True:
        for etype in element_type.keys():
            element_value, element_size = check_element_type_value(etype, elements)
            if element_size:
                elements = elements[element_size:]
                return etype, element_value, elements

        print("-"*40)
        print("Unknown Element Type : {}".format(hex(elements[0])))
        print("Raw data : {}".format(elements))
        print("Cancel to parse this element.\n")
        return None, None, None


def parse_dns_packet(dns_packet):
    dns_entry = dnslib.DNSRecord.parse(dns_packet)
    dns_query = dns_entry.get_q().get_qname().idna()
    dns_replies = [str(x) for x in dns_entry.rr]
    if debug_mode:
        print("DNS Query : {}".format(dns_query))
        print("DNS Replies : {}".format(dns_replies))
    return {'dns_query': dns_query, 'dns_replies': dns_replies}


def check_element_type_value(etype, elements):
    etype_length = elements[0] ^ 0xA0

    if elements[1:etype_length+1] == element_type[etype]['str']:
        if debug_mode:
            print("Element Type : {}".format(etype))
        eheader_size = 1 + etype_length

        if element_type[etype]['post'] == epost_xor_len:
            length = elements[eheader_size] ^ 0xA0
            string = elements[eheader_size+1:eheader_size+1+length]
            if debug_mode:
                print("Length(XOR) : {}".format(length))
                print("String : {}".format(string))
            return string.decode('utf-8'), eheader_size + 1 + length

        elif element_type[etype]['post'] == epost_str_len:
            if elements[eheader_size] == element_type_str['str_1byte'] or elements[eheader_size] == element_type_str['str_with_null']:
                length = elements[eheader_size+1]
                string = elements[eheader_size+2:eheader_size+2+length]
                if debug_mode:
                    print("Length(1byte) : {}".format(length))
                    print("String : {}".format(string))
                return string.decode('utf-8'), eheader_size + 2 + length
            elif elements[eheader_size] == element_type_str['str_2byte']:
                length = struct.unpack_from(">H", elements[eheader_size+1:], 0)[0]
                string = elements[eheader_size+3:eheader_size+3+length]
                if debug_mode:
                    print("Length(2byte) : {}".format(length))
                    print("String : {}".format(string))
                return string.decode('utf-8'), eheader_size + 3 + length
            else:
                length = elements[eheader_size] ^ 0xA0
                string = elements[eheader_size+1:eheader_size+1+length]
                if debug_mode:
                    print("Length : {}".format(length))
                    print("String : {}".format(string))
                return string.decode('utf-8'), eheader_size + 1 + length

        elif element_type[etype]['post'] == epost_num:
            if elements[eheader_size] == element_type_num['num_1byte']:
                number = elements[eheader_size+1]
                if debug_mode:
                    print("Number(1byte) : {}".format(number))
                return number, eheader_size + 1 + 1
            elif elements[eheader_size] == element_type_num['num_2byte']:
                number = struct.unpack_from(">H", elements[eheader_size+1:], 0)[0]
                if debug_mode:
                    print("Number(2byte) : {}".format(number))
                return number, eheader_size + 1 + 2
            elif elements[eheader_size] == element_type_num['num_4byte']:
                number = struct.unpack_from(">I", elements[eheader_size+1:], 0)[0]
                if debug_mode:
                    print("Number(4byte) : {}".format(number))
                return number, eheader_size + 1 + 4
            else:
                number = elements[eheader_size]
                if debug_mode:
                    print("Number : {}".format(number))
                return number, eheader_size + 1

        elif element_type[etype]['post'] == epost_bytes:
            if elements[eheader_size] in element_type_bytes.values():
                length = elements[eheader_size+1]
                dns_packet = elements[eheader_size+2:eheader_size+2+length]
                if debug_mode:
                    print("Length : {}".format(length))
                    print("Raw data : {}".format(dns_packet))
                parsed_dns_packet = parse_dns_packet(dns_packet)
                return parsed_dns_packet, eheader_size + 2 + length

        else:
            print("-"*40)
            print("Unknown Element Value Type : {}".format(hex(elements[0])))
            print("Raw data : {}\n".format(elements))
            return None, None

    else:
        return None, None


def parse_record(record):
    # remove record delimiter
    record = record[1:]
    parsed_elements = {}
    for rtype in record_type.keys():
        if check_record_type(rtype, record):
            if debug_mode:
                print("Record Type : {}".format(str(rtype)))
            elements = record[1+len(record_type[rtype]['str'])+1:]
            while len(elements) > 0:
                etype, element_value, elements = parse_element(elements)
                if None in [etype, element_value, elements]:
                    break
                if (rtype == 'dns_request' or rtype == 'dns_reply') and etype == 'bytes':
                    etype = 'dns'
                parsed_elements[etype] = element_value

            return {**{'record_type': rtype}, **parsed_elements}

    print("-"*40)
    print("Unknown Record Type : {}".format(hex(record[0])))
    print("Raw data : {}\n".format(record))
    return None


def main():
    args = parse_arguments()
    check_arguments(args)

    if os.path.exists(os.path.abspath(args.file)):
        with open(args.file, 'rb') as fp:
            data = fp.read()
    else:
        sys.exit("{} does not exist.".format(args.file))

    if args.out:
        if os.path.exists(os.path.abspath(args.out)) and not args.force:
            sys.exit("{} has already existed.".format(args.out))
        out_file = open(args.out, 'wt')

    # parse Monitor.app's data
    current_pos = 0
    record_num = 0
    records = dict()
    while current_pos < len(data):
        if debug_mode:
            print("-"*40)
        record, current_pos = parse_saved_data(data, current_pos)
        if debug_mode:
            print("raw record : {}".format(record))
        records['record_' + str(record_num)] = {'record_num': record_num, **parse_record(record)}

        # output JSON data
        if args.console:
            print(json.dumps(records['record_' + str(record_num)], ensure_ascii=False, indent=4))

        # save JSON data
        if args.out:
            json.dump(records['record_' + str(record_num)], out_file, ensure_ascii=False)
            out_file.write('\n')

        record_num += 1

        if current_pos == -1:
            break

    if args.out:
        out_file.close()

    return 0


if __name__ == "__main__":
    if sys.version_info[0:2] >= (3, 0):
        sys.exit(main())
    else:
        sys.exit("This script needs Python 3.x")
