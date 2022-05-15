<img src="media/aslr_buster.png" width=50%>

# ASLR Buster
ASLR (Address Space Layout Randomization) is used by the Linux Kernel to randomize memory space which makes the attacks on processes more difficult. To circumvent ASLR, an attacker must identify an information leak vulnerability that exposes memory locations during its runtime. They can probe the memory until they find the correct area where another program is running and then adapt their code to target that memory address space. 

The ASLR Buster tool will bypass the ASLR protection and exploit Buffer Overflow Vulnerability in the 32-bit Linux system.

## Importance
Creating a buffer overflow attack is usually a manual process. The importance of having a tool that can automate some of these tasks saves time. This automated tool interests us because we found it tedious to try to use various commands and search tools inside other programs to build our payload.

## Prerequisite

### 1. Python Version
Our tool requires python3 version 3.6.9 or greater.

### 2. Enable ASLR

~~~
$ sudo sysctl -w kernel.randomize_va_space=2
~~~

Run the following to verify ASLR is enabled. The expected value is 2.

~~~
$ sysctl -a --pattern randomize_va_space
~~~

### 3. Install Dependencies:
- click: [Link](https://pypi.org/project/click/)
~~~
$ pip3 install click
~~~

- capstone: [Link](https://www.capstone-engine.org/documentation.html)
~~~
$ pip3 install capstone
~~~

OR use the makefile:

~~~
$ make setup
~~~

## ASLR Bypass

### 1. Compile Vulnerable Programs

~~~
$ cd test
~~~

Install libc 32-bit version

~~~
$ sudo apt-get update
$ sudo apt-get install gcc-multilib
~~~

Compile the source code:

~~~
$ gcc -m32 -z noexecstack -fno-stack-protector -no-pie -o vuln_01 vuln_01.c
~~~

Verify that libc address is always different:

~~~
$ ldd vuln_01 | grep libc
~~~

### 2. Start the ASLR Buster Script

Run script in a folder that contains only the vulnerable program (assuming current directory is `test/`)

~~~
$ ../aslr_buster.py
~~~

Follow the instructions and get a shell

## How the ASLR Buster Script Works

The `aslr_buster.py` is the main script responsible for exploiting the buffer overflow vulnerability in a vulnerable C program.

To achieve our objective, we have imported various native libraries (notable ones include `subprocess`, `re`, `threading`, and `os`) and other user-defined scripts such as `payload_handler.py`, `bin_handler.py` `find_segfault.py`, etc. The only third-party libraries are the `click` (for UI and handling of user prompts) and `capstone`.

The `capstone` module is used to disassemble the bytes of the binary. We use capstone to disassemble only sections of the binary that has the executable flag as we have a non-executable stack enabled. We use the command `readelf -S binary_file` to obtain the section information. The `capstone` functions will output the assembly code equivalent of the bytes we input, where we can then use regex to match the output strings for the gadgets that interest us.

The script starts with prompting the user/attacker to enter the vulnerable C program's name. The script then prompts the user to enter the maximum payload size for exploitation.

Automation begins from this point forward.

The `payload_handler.py` script comes to use, which generates the generic payload. The main script will then run by taking brute-forcing the filename of the payload and searching for the segfault address and segfault offset in the vulnerable program. The script will continue to check for any libc linked to the vulnerable program using the `bin_handler.py`. We then examine the PLT (Procedure Linkage Table) sections by searching for any `puts` or `printf` the are required to leak the libc address. For GOT (Global Offset Table), we are interested in `.got.plt` section from the `readelf -S binary_file` output.

Using the `bin_handler.py` script, we check for the addresses and offsets of important functions, including `system`, `printf`, `puts`, `exit` and `start`. Searching for gadgets allows an attacker to perform arbitrary operations on a machine with defenses. Hence, we call our `gadget_finder.py` script to look for gadget addresses in the program like a `pop [any registers]; ret;`. We rely on many regex patterns in the script to check various outputs in the executable section(s) within the vulnerable program containing the gadget and the gadget addresses.

We are now interested in finding the `bin/sh` address that will allow a user to access the victim machine's interactive shell. We scan the read-only data (`.rodata`) sections using `bin_handler.py` to get the start and end addresses of the `.rodata` section, which will eventually give us the offset of `bin/sh` string through an iterative search for printable characters terminating with NULL bytes.

For the exploit to work, we will create a FIFO pipe where we can send the malicious payload. The idea of the pipe is to substitute the file that the vulnerable program performs its `fread` call. The pipe is an integral part of the exploit because it can block the flow of the program until a payload is written to it. Blocking control flows gives our script the time and opportunity to introduce two separate payloads.

We now create our first payload in `payload_handler.py`, which takes in maximum payload size and segfault offset found in above steps into account. The payload will instruct the program to execute `printf@plt` or `puts@plt` to output random string, call the `pop` gadget, output the `got` address, and redirect the flow to the `_start` of the program. Once the payload is created and ready to start the buffer overflow exploit, the attacker is prompted to begin the exploit. After the payload is written, the script reads the output in `recv_str`.

### 1st payload:
- address: `puts@plt`
- gadget: `pop [any register]; ret;`
- address: random string
- address: `puts@plt`
- gadget: `pop [any register]; ret;`
- address: `puts@got`
- address: `_start`
- address: random string
- address: random string*

*Note: The random string may be a part of the program's invocation (eg: `./vuln_02 payloadname`).

The script now continues to create the second payload wherein if the `printf` or `puts` function is found in the vulnerable program, its output will contain the leaked address of `printf` or `puts`. The script now calculates the libc base address, `printf` address, `puts` address, `system` address, `bin/sh` address, and `exit` address. We add these obtained addresses to the second payload, which is written to the pipe. After the second payload is executed, the attacker successfully obtains the interactive shell of the victim's machine.

### 2nd payload:
- address: `system`
- address: `exit`
- address: `"/bin/sh"`

## Test Cases

We have three vulnerable C programs. In all three programs, we can exploit them and obtain the shell. Below are the details: 

### vuln_01.c
This program reads the file with the name "benign_payload," and the vulnerability is in the `strcpy` function where it tries to copy more bytes than the buffer size. The `printf` is called before the `fread`.

Inputs needed: name of file and value of maximum payload size

### vuln_02.c
This program is opens a file with the name `evil_file`. No `printf` function is called prior to the execution of `fread`.

Inputs needed: name of file and value of maximum payload size

### vuln_03.c
This program is similar to `vuln_02.c` except that file of any name can provided as an argument. The vulnerability is in the `fread` function where it tries to read more bytes than the buffer size.

Inputs needed: name of file and value of maximum payload size


### Sample of Expected Output
Below is a sample of the successful exploitation. All three exploits will produce a similar shell. The libc address (`0xf7d18000`) will always be different due to ASLR.

~~~
Starting exploit
---------------------------------------------
First payload is written
Reading outputs from until the following bytes are received: b'benign_payload\n'
Receive from program with first payload: b'benign_payload\n'
Full leak b'\x90\x92\xd8\xf7\xf0m\xd3\xf7 w\xd8\xf70q\xe6\xf7\n'
Leaked address of puts: 0xf7d89290

[Demo pause] Press any key to continue calculating libc address [Y/n]:

Calculation of libc address = leaked address of puts - offset of puts
Calculation of libc address = f7d89290 - 00071290
Calculated libc address: 0xf7d18000
Function system address: 0xf7d5d420
String /bin/sh address: 0xf7ea7352
Function exit address: 0xf7d4ff80

[Demo pause] Press any key to get interactive shell [Y/n]:

whoami
johndoe
~~~

## Challenges
We had certain challenges faced when dealing with the development, and there were some behaviors that we could not automate:

- We could not automate the calculation of the payload size. The user must provide this information. We do not have a way to know the maximum bytes required in the `fread` parameter.

- Our options for finding gadgets are limited to only the executable bytes of the binary file, as the address we need must be static.

- We, at some point, relied on the `process` module of `pwntools` (a third-party library) to handle the interaction of the subprocess. However, we found the technique used to make this possible using python's native `subprocess` module along with using `pty` as the `stdout` to capture buffers as they become immediately available. Furthermore, importing `pwntools` caused the `click` module to behave strangely.

## Bugs & Known Issues

Please see [issues](https://github.com/jasonwubz/aslr_buster/issues)

## Disclaimer

This project is used for educational purposes only. It is illegal to run this tool on another party's system without their explicit permission. Also, buffer overflow exploits can sometimes crash a system. We recommend only testing this tool inside a virtual machine. We take no responsibility for any damages caused by our tool. Execute the ASLR Buster script at your own risk.

## References:
https://www.fortinet.com/blog/threat-research/tutorial-arm-stack-overflow-exploit-against-setuid-root-program
