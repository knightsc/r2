#!/usr/bin/python

# Tested on macOS 10.14, 10.13, 10.12, 10.11, 10.10 and iOS 12
#
# The platform profile is examined to determine the total number of operation
# names.
#
# Assuming no changes in the file format the output should look something like
# this:
#
# found error string at 0x1af43
# found error string xref at 0x542e
# found profile_create() at 0x3f09
# found collection_data at 0x246c0 with size 0x11f1
# Dumped 4593 bytes from 0x000246c0 into 10.14/collection_data.sbc
# found platform_profile at 0x1e140 with size 0x657a
# Dumped 25978 bytes from 0x0001e140 into 10.14/platform_profile.sbc
# found 148 operation_names at 0x27c40
# Dumped operation_names into 10.14/operation_names.txt

import argparse
import r2pipe
import struct
import sys
import os

MH_DYLIB = 0x6
MH_KEXT_BUNDLE = 0xb

def u64hex(num):
    return hex(num & (2**64-1))[:-1]

def find_string(r2, str):
    obj = r2.cmdj('/j "%s"' % str)
    if len(obj) >= 1 and 'offset' in obj[0]:
        return u64hex(obj[0]['offset'])
    else:
        return None

def xref(r2, address):
    for xref in r2.cmdj('axtj %s' % address):
        yield u64hex(xref['from'])

def find_profile_create(r2, error_xref):
    r2.cmd('s %s' % error_xref)

    call_opcode = None
    while call_opcode == None:
        r2.cmd('so -1')
        opcode = r2.cmdj('aoj')[0]
        if opcode['type'] == 'call':
            call_opcode = opcode
            break

    return u64hex(call_opcode['jump'])

def run_basic_block(r2, address):
    r2.cmd('s %s' % address)
    r2.cmd('sb')
    r2.cmd('ar0')
    r2.cmd('aei')
    r2.cmd('aeim')
    r2.cmd('aeip')
    r2.cmd('aecu %s' % address)

    return r2.cmdj('aerj')

def get_offset_and_size(r2, registers):
    offset = None
    size = None

    obj = r2.cmdj('ij')
    if obj['bin']['arch'] == 'arm':
        x1 = registers['x1']
        file_offset = r2.cmd('?p %s' % u64hex(x1))
        if 'no map' not in file_offset:
            offset = x1
            size = registers['x3']
            if size == 0:
                size = registers['x2']

    elif obj['bin']['arch'] == 'x86':
        rsi = registers['rsi']
        file_offset = r2.cmd('?p %s' % u64hex(rsi)) 
        if 'no map' not in file_offset:
            offset = rsi
            size = registers['rcx']
            if size == 0:
                size = registers['rdx']
    
    return (offset, size)

def read_header_version3(data):
    header = {}

    header['regexp_table_offset']  = struct.unpack('<H', data[2:4])[0]
    header['pattern_table_offset'] = struct.unpack('<H', data[4:6])[0]
    header['global_table_offset']  = struct.unpack('<H', data[6:8])[0]
    header['regexp_table_count']   = struct.unpack('<H', data[8:10])[0]
    header['pattern_table_count']  = struct.unpack('B',  data[10:11])[0]
    header['global_table_count']   = struct.unpack('B',  data[11:12])[0]

    return header

def read_header_version2(data):
    header = {}

    header['regexp_table_offset'] = struct.unpack('<H', data[2:4])[0]
    header['regexp_table_count']  = struct.unpack('<H', data[4:6])[0]    
    header['global_table_offset'] = struct.unpack('<H', data[6:8])[0]
    header['global_table_count']  = struct.unpack('<H', data[8:10])[0]
    header['pattern_table_offset'] = 0
    header['pattern_table_count']  = 0

    return header

def read_header_version1(data):
    header = {}

    header['regexp_table_offset'] = struct.unpack('<H', data[2:4])[0]
    header['regexp_table_count']  = struct.unpack('<H', data[4:6])[0]
    header['global_table_offset']  = 0
    header['global_table_count']   = 0
    header['pattern_table_offset'] = 0
    header['pattern_table_count']  = 0

    return header

def get_op_count(filename):
    with open(filename, mode='rb') as file:
        data = file.read()
        
        # Try v3 format first
        header_length = 12
        header = read_header_version3(data)

        if header['pattern_table_offset'] < header['regexp_table_offset']:
            header_length = 10
            header = read_header_version2(data)

            if header['global_table_offset'] < header['regexp_table_offset']:
                header_length = 6
                header = read_header_version1(data)

        op_count = 0
        index = header_length
        while True:
            offset = struct.unpack('<H', data[index:index+2])[0]
            index = index + 2

            if offset == 0x0000:
                # skip padding
                continue
            elif offset & 0x00ff == 0x0000:
                # reached the start of the op nodes
                break
            else:
                op_count = op_count + 1

        return op_count

def main():
    parser = argparse.ArgumentParser(description='Extract sandbox profiles')
    parser.add_argument('kext', type=str, help='macOS/iOS Sandbox kext binary')
    args = parser.parse_args()

    r2 = r2pipe.open(args.kext)
    info = r2.cmdj('ij')
    headers = r2.cmdj('ihj')

    if info['core']['format'] != 'mach064':
        raise ValueError('not a mach-o file')

    if int(headers[3]['comment'], 16) != MH_KEXT_BUNDLE:
        raise ValueError('not a macho-o kext file')

    if info['bin']['arch'] == 'arm':
        r2.cmd('aa;aae;aad')
    else:
        r2.cmd('aa')

    # make sure we were given an actual kext check header FileType

    error = find_string(r2, 'failed to initialize platform sandbox')
    print('found error string at %s' % error)

    error_xref = list(xref(r2, error))[0]
    print('found error string xref at %s' % error_xref)

    profile_create = find_profile_create(r2, error_xref)
    print('found profile_create() at %s' % profile_create)

    profiles = []
    for profile_create_xref in xref(r2, profile_create):
        registers = run_basic_block(r2, profile_create_xref)
        profile = get_offset_and_size(r2, registers)
        if profile[0] != None:
            profiles.append(profile)

    collection_data = None
    platform_profile = None
    if len(profiles) == 2:
        collection_data = profiles[0]
        platform_profile = profiles[1]
    elif len(profiles) == 1:
        platform_profile = profiles[0]
    else:
        print('found extra profiles!')

    if collection_data:
        print('found collection_data at %s with size %s' % (u64hex(collection_data[0]), u64hex(collection_data[1])))
        filename = os.path.join(os.path.dirname(args.kext), 'collection_data.sbc')
        r2.cmd('wtf %s %s @ %s' % (filename, u64hex(collection_data[1]), u64hex(collection_data[0])))

    if platform_profile:
        print('found platform_profile at %s with size %s' % (u64hex(platform_profile[0]), u64hex(platform_profile[1])))
        filename = os.path.join(os.path.dirname(args.kext), 'platform_profile.sbc')
        r2.cmd('wtf %s %s @ %s' % (filename, u64hex(platform_profile[1]), u64hex(platform_profile[0])))

    default_string = r2.cmd('iz~default$')
    default_addr = default_string.split()[2]
    obj = r2.cmdj('/v8j %s' % default_addr)
    op_xref = u64hex(obj[0]['offset'])
    op_count = get_op_count(os.path.join(os.path.dirname(args.kext), 'platform_profile.sbc'))
    print('found %s operation_names at %s' % (op_count, op_xref))

    with open(os.path.join(os.path.dirname(args.kext), 'operation_names.txt'), 'w') as file:
        for i in range(op_count):
            obj = r2.cmdj('pfj S @ %s + %s' % (op_xref, i * 8))
            file.write('%s\n' % obj[0]['string'])

    print('Dumped operation_names into %s' % file.name)

    r2.quit()

if __name__== "__main__":
    main()
