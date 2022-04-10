# ASLR Buster
This is a tool for bypassing ASLR protection in buffer overflow for 32 bit Linux

## Prerequisite

### 1. Able ASLR

~~~
$ sudo sysctl -w kernel.randomize_va_space=2
~~~

### 2. Install Dependencies:
- click: [Link](https://pypi.org/project/click/)
- capstone: [Link](https://www.capstone-engine.org/documentation.html)

## ASLR BYPASS

### 1. Compile Sample Vulnerable Program
To compile the vulnerable program, navigate to test directory:

~~~
$ cd test
~~~

Then, comiple the vulnerablt files:

~~~
$ gcc -m32 -o prog -z noexecstack -fno-stack-protector -no-pie prog.c
~~~

### 3. Bypass:
~~~
$ python3 ../alsr_buster.py
~~~

Follow the guide and get a shell

## Important Notes:
Run this in a folder that contains only the vulnerable program.


## 1st payload:
address of puts@plt\
gadget: pop e?x; ret;\
address of a string\
address of puts@plt\
gadget: pop e?x; ret;\
address of puts@got\
address of _start\
address of a string

## 2nd payload:
system_address\
exit_address\
gadget: pop e?x; ret;\
address of /bin/sh
