# ASLR Buster
ASLR is used by the Linux Kernel to randomize memory space which makes the attacks on processes more difficult. To get around ASLR, an attacker has to identify an information leak vulnerability that exposes memory locations, or they can probe the memory until they find the correct area where another programme is running, and then adapt their code to target that memory address space. 

The ASLR Buster tool will bypass the ASLR protection and exploit Buffer Overflow Vulnerability in the 32 bit Linux system.

## Importance
Creating a buffer overflow attack is usually a manual process. The importance of having a tool that can automate some of these tasks saves time. This automated tool interests us because we found it tedious to try to use various commands and search tools inside other programs to build our payload.

## Prerequisite

### 1. Enable ASLR

~~~
$ sudo sysctl -w kernel.randomize_va_space=2
~~~

### 2. Install Dependencies:
- click: [Link](https://pypi.org/project/click/)
- capstone: [Link](https://www.capstone-engine.org/documentation.html)

## ASLR Bypass

### 1. Compile Vulnerable Program

~~~
$ cd test
~~~

Then, comiple the vulnerablt files:

~~~
$ gcc -m32 -o prog -z noexecstack -fno-stack-protector -no-pie prog.c
~~~

### 2. Start the program

To start the program, run:

~~~
$ python3 ../alsr_buster.py
~~~

Follow the guide and get a shell


## Important Notes:
Run this in a folder that contains only the vulnerable program.

## ASLR Buster Script

This script is the main script that is responsible for exploiting the buffer overflow vulnerability in a vulnerable C program.

We have imported various libraries and other scripts like payload generator, bin handler, seg fault finder etc., to achieve our objective.

The script starts off with prompting the user/attacker to enter the vulnerable c program name whose buffer overflow vulnerability is to be exploited. A user can then choose the probe method for the exploit. We have included 4 probe methods to perform the attack which are default probing, probing with payload as an argument, filename, and argument and filename together. The script also enables the user to enter the maximum payload size to be used for exploitation.

The generate_random_payload script comes to use which generates the payload by prompting the user to enter the name of the payload file. The main script will then run by taking above mentioned inputs from the user and searching for the segfault address and segfault offset in the vulnerable program. The script will continue to check for any libc vulnerability in the program using the bin handler script and throw the libc path address as on output. We then look for PLT (Procedure Linkage Table) sections by searching for any puts or printfs in the vulnerable program to leak the libc address. For GOT (Global Offset Table), we are interested in .got.plt section of readelf -S binary_file.

By using the bin handler script, our main script then starts to exploit the program and checks for the addresses of important functions including system, printf, puts, exit and start addresses and the offsets. Searching for gadgets allow an attacker to perform arbitrary operations on a machine with defenses. Hence, we call our gadget finder script to look for gadget addresses in the program like a pop and/or ret registers. We introduced a reg expression in the script which effectively checks the program using certain patterns that we have included in the regex. The script outputs the executable section within the vulnerable program containing the gadget along with the gadget addresses.

We are now interested in finding the bin/sh address which will allow a user to access the victim machine’s interactive shell. In order to achieve this, we try to obtain the readonlydata (rodata) sections of the program and make use of bin handler file to get the start and end addresses of the rodata which will eventually give us the offset of bin/sh string.

We now create our first payload using a payload handler (evil_payload_handler) which calls printf@plt our puts@plt and takes in maximum payload size and segfault offset found in above steps. This handler will make payload print random string, then print got address and pop the gadgets found in the vulnerable program. We then continue to add more content to the handler to be placed at the start of the program. Once the payload is created and ready to start the buffer overflow exploit, the attacker is prompted to begin the exploit. After the payload gets written, the exploit reads output of the payload in recv_str. 

### 1st payload:
address of puts@plt\
gadget: pop e?x; ret;\
address of a string\
address of puts@plt\
gadget: pop e?x; ret;\
address of puts@got\
address of _start\
address of a string

The script now continues to build second stage of exploit wherein if the printf statement is found in the vulnerable program, it will print the recvdata as a full leak and length of the string used in the payload. The script gives the leaked addresses of the prints and puts functions from the vulnerable program. The script now continues to calculate the libc base addresses in the form of printf address offset, put address offset, system address offset, binsh offset and exit address offset. We add these obtained addresses to the second payload which is written to the pipe. After the second payload is executed, an attacker successfully obtains the interactive shell of the victim’s machine.

### 2nd payload:
system_address\
exit_address\
address of /bin/sh

## References:
https://www.fortinet.com/blog/threat-research/tutorial-arm-stack-overflow-exploit-against-setuid-root-program


