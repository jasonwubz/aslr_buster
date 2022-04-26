import subprocess
import time
import threading
import signal
import re
from bin_handler import Bin_handler

from generate_random_payload import generic_payload
from generate_random_payload import Generic_payload_file_handler
from bin_handler import get_filename_strings


def find_segfault_address(test_str, arch=32):
    # address that we are looking for is in group 1
    regex = r"segfault\sat\s([0-9a-fA-F]{8})"

    # if architect is 64 bit
    if arch == 64:
        regex = r"segfault\sat\s([0-9a-fA-F]{16})"

    matches = re.finditer(regex, test_str, re.MULTILINE)

    address = ''
    for matchNum, match in enumerate(matches, start=1):
        address = match.group(1)
        break

    return address


def output_reader(proc):
    for line in iter(proc.stdout.readline, b''):
        print('Output from process: {0}'.format(line.decode('utf-8')), end='')


def probe_program(filename, arch=32, argument=''):
    offset = 0
    print("Argument:", argument)
    proc = subprocess.Popen([f'./{filename}', f'{argument}'],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)

    t = threading.Thread(target=output_reader, args=(proc,))
    t.start()

    has_segfault = False

    try:
        time.sleep(0.2)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=0.2)
            # we want to parse this info here

            if proc.returncode == -signal.SIGSEGV:
                has_segfault = True
                dmesg_output = subprocess.check_output('dmesg | tail -n 2',
                                                       shell=True)
                segfault_address = find_segfault_address(str(dmesg_output),
                                                         arch)
                if len(segfault_address) == 0:
                    return False, None, offset
                return has_segfault, segfault_address, offset
            else:
                print('process exited normally', proc.returncode)

        except subprocess.TimeoutExpired:
            print('subprocess did not terminate in time')
    t.join()

    return has_segfault, None, offset


def find_segfault(filename,
                  arch=32,
                  probe_mode=4,
                  max_payload_size=0,
                  start_payload_name=''):

    print("Generating generic payload...")
    gen_payload = generic_payload(max_payload_size)

    if probe_mode == 4:
        start_payload_name = '_generic_payload'

    if probe_mode == 2 or probe_mode == 3:
        gp_handler = Generic_payload_file_handler(gen_payload,
                                                  filename,
                                                  start_payload_name)

    argument = ''
    if probe_mode == 1 or probe_mode == 3:
        argument = gen_payload

    print("Payload is :", gen_payload)

    print("Begin probing for segfault...")

    if probe_mode == 4:
        # get list of possible strings to test
        print("Using automatic mode")
        gp_handler = Generic_payload_file_handler(gen_payload,
                                                  filename,
                                                  start_payload_name)

        # TODO: limit bruteforce to only strings found in .rodata for now
        # can be improved in future
        b_handler = Bin_handler(filename)
        b_results = b_handler.search_binary_section(filename, '.rodata')

        found_rodata, rodata_address, rodata_start, rodata_end = b_results

        rodata_address_int = int(rodata_address, 16)
        rodata_start_int = int(rodata_start, 16)
        rodata_end_int = rodata_start_int + int(rodata_end, 16)

        test_strings = get_filename_strings(filename,
                                            rodata_start_int,
                                            rodata_end_int,
                                            1)

        # recalcuate strings address
        new_test_strings = {}
        for key in test_strings:
            new_address = rodata_address_int + key
            new_test_strings[new_address] = test_strings[key]

        effective_address_of_string = ''
        for key in new_test_strings:
            temp_name = new_test_strings[key]
            print("----------------------------------")
            print("Trying string as the name of payload ->", temp_name)
            print("String address is ->", hex(key))
            gp_handler.rename_payload_file(temp_name)
            time.sleep(0.5)
            has_segfault, address, offset = probe_program(filename,
                                                          arch,
                                                          temp_name)
            if has_segfault is True:
                effective_address_of_string = key
                # decode hex and reverse for correct endianness
                address_str = bytearray.fromhex(address).decode()[::-1]
                offset = gen_payload.find(address_str)
                break
            else:
                print("Did not find segfault")
        print("Name of payload file name that worked", gp_handler.current_file)
        print("----------------------------------")
        return (has_segfault,
                address,
                offset,
                gp_handler.current_file,
                effective_address_of_string)
    else:
        has_segfault, address, offset = probe_program(filename,
                                                      arch,
                                                      argument)
        if has_segfault is True:
            # decode hex and reverse for correct endianness
            address_str = bytearray.fromhex(address).decode()[::-1]
            print("Found string address used in segfault", address_str)
            offset = gen_payload.find(address_str)
        return has_segfault, address, offset, '', 0

    return False, None, 0, '', 0
