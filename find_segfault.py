import subprocess
import time
import threading
import signal
import re
from bin_handler import Bin_handler

from payload_handler import generic_payload
from payload_handler import Generic_payload_handler
from bin_handler import get_filename_strings


def find_segfault_address_valgrind():
    """Expects content inside a file called
    _valgrind. This function will open the file to
    look for segfault
    """
    address = ''
    with open("_valgrind", mode='rb') as f:
        full_msg = f.read()
        print("Length of valgrind file:", len(full_msg))
        regex = r"Address\s0x([a-f0-9A-F]{8,16})\sis\snot"
        matches = re.finditer(regex, full_msg.decode('utf-8'), re.MULTILINE)

        for matchNum, match in enumerate(matches, start=1):
            address = match.group(1)
            break

    return address


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
    # print("Argument:", argument)
    # print("Arch:", arch)

    arguments_to_call = []
    if arch == 64:
        arguments_to_call.append("valgrind")
        arguments_to_call.append('-q')
        arguments_to_call.append('--log-file=_valgrind')
        arguments_to_call.append(f'./{filename}')
        arguments_to_call.append(argument)
    else:
        arguments_to_call.append(f'./{filename}')
        arguments_to_call.append(argument)

    proc = subprocess.Popen(arguments_to_call,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)

    t = threading.Thread(target=output_reader, args=(proc,))
    t.start()

    has_segfault = False

    try:
        if arch == 64:
            time.sleep(1)
        else:
            time.sleep(0.5)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=0.2)

            # we want to parse this info here
            if proc.returncode == -signal.SIGSEGV:
                has_segfault = True

                segfault_address = 0

                if arch == 64:
                    segfault_address = find_segfault_address_valgrind()
                else:
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
            print('Subprocess did not terminate in time')
    t.join()

    return has_segfault, None, offset


def find_segfault(filename,
                  arch=32,
                  probe_mode=4,
                  max_payload_size=0,
                  start_payload_name=''):

    # print("Generated generic payload")
    gen_payload = generic_payload(max_payload_size)
    gp_handler = None

    if probe_mode == 4:
        start_payload_name = '_generic_payload'

    if probe_mode == 2 or probe_mode == 3 or probe_mode == 4:
        gp_handler = Generic_payload_handler(gen_payload,
                                             filename,
                                             start_payload_name)

    argument = ''
    if probe_mode == 1 or probe_mode == 3:
        argument = gen_payload

    print("Generic payload:", gen_payload)

    print("")
    print("Begin probing for segfault...")

    if probe_mode == 4:
        # TODO: try sections other than .rodata
        b_handler = Bin_handler(filename)
        b_results = b_handler.search_section(filename, '.rodata')

        found_rodata, rodata_address, rodata_start, rodata_end = b_results

        rodata_address_int = int(rodata_address, 16)
        rodata_start_int = int(rodata_start, 16)
        rodata_end_int = rodata_start_int + int(rodata_end, 16)

        str_offsets = get_filename_strings(filename,
                                           rodata_start_int,
                                           rodata_end_int,
                                           1)

        # recalcuate strings address
        str_addresses = {}
        for offset_as_key in str_offsets:
            full_address = rodata_address_int + offset_as_key
            str_addresses[full_address] = str_offsets[offset_as_key]

        eff_address_of_string = ''
        for t_address in str_addresses:
            t_string = str_addresses[t_address]
            print("----------------------------------")
            print("Trying string as the name of payload ->", t_string)
            print("String address is ->", hex(t_address))
            gp_handler.rename_payload_file(t_string)
            time.sleep(0.5)
            has_segfault, address, offset = probe_program(filename,
                                                          arch,
                                                          t_string)
            if has_segfault is True:
                eff_address_of_string = t_address
                # decode hex and reverse for correct endianness
                t_address_str = bytearray.fromhex(address).decode()[::-1]
                offset = gen_payload.find(t_address_str)
                break
            else:
                print("Did not find segfault")
        # print("Name of payload file name that worked",
        #       gp_handler.current_file)
        print("----------------------------------")
        return (has_segfault,
                address,
                offset,
                gp_handler.current_file,
                eff_address_of_string)
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
