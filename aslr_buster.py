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




# finally, do cleanup of file ??
# try:
#     if len(start_payload_name) > 0:
#         os.unlink(start_payload_name)
# except:
#     print("Unable to delete payload file during cleanup", start_payload_name)