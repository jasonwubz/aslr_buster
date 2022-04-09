import sys
import subprocess
import re

from string_handler import search_string_in_file

class Bin_handler:

    """This class is for handling binary files

    The main idea is to use existing commands such as ldd, readelf to produce output
    of the binary and the regex is used to extract these information
    """

    # initialize
    def __init__(self, filename):
        self.filename = filename
        self.libc_exists = False
        self.libc_path = ''

    # check if the bin has libc linked to it
    def has_libc(self):
        ldd_output = subprocess.check_output(f'ldd {self.filename}', shell=True)

        # use regex to find if libc is used
        regex = r"(libc[a-zA-Z0-9-.]+)\s=\>\s([a-zA-Z0-9-.\/]*libc[a-zA-Z0-9-.]+)\s(\(0x[0-9a-fA-F]{8,16}\))?"
        matches = re.finditer(regex, str(ldd_output), re.MULTILINE)
        for matchNum, match in enumerate(matches, start=1):
            self.libc_path = match.group(2)
            self.libc_exists = True
        return self.libc_exists

    def search_function(self, filename, function_name):
        command_str = f"readelf -s {filename} | grep {function_name}"
        output = subprocess.check_output(command_str, shell=True)
        
        regex = "\d*:\s([0-9a-fA-F]{8,16})\s*\d*\s\w*\s*\w*\s*\w*\s*\d*\s"+function_name+"\@"
        matches = re.finditer(regex, str(output), re.MULTILINE)
        found_address = ''
        found = False
        for matchNum, match in enumerate(matches, start=1):
            found_address = match.group(1)
            found = True
            break
        return found, found_address

    def search_asm_function(self, filename, function_name):
        command_str = f"readelf -s {filename} | grep {function_name}"
        output = subprocess.check_output(command_str, shell=True)
        
        regex = "\d*:\s([0-9a-fA-F]{8,16})\s*\d*\s\w*\s*\w*\s*\w*\s*\d*\s"+function_name
        matches = re.finditer(regex, str(output), re.MULTILINE)
        found_address = ''
        found = False
        for matchNum, match in enumerate(matches, start=1):
            found_address = match.group(1)
            found = True
            break
        return found, found_address

    def search_plt_function(self, filename, function_name):
        command_str = f"objdump -d {filename}"
        output = subprocess.check_output(command_str, shell=True)
        
        regex = "([a-fA-F0-9]{8,16})\s<"+function_name+"@plt>"
        matches = re.finditer(regex, str(output), re.MULTILINE)
        found_address = ''
        found = False
        for matchNum, match in enumerate(matches, start=1):
            found_address = match.group(1)
            found = True
            break
        return found, found_address

    def search_plt_and_got_function(self, filename, function_name):
        command_str = f"objdump -d {filename}"
        output = subprocess.check_output(command_str, shell=True)
        
        regex = "([a-fA-F0-9]{8,16})\s<"+function_name+"@plt>:(\s.*?)jmp\s*\*0x([a-fA-F0-9]{7,16})"        
        matches = re.finditer(regex, str(output).replace('\\n', ' '), re.MULTILINE)
        found_address = ''
        found_got_address = ''
        found = False
        for matchNum, match in enumerate(matches, start=1):
            found_address = match.group(1)
            found_got_address = match.group(3)
            found = True
            break
        return found, found_address, found_got_address

    def get_executable_sections(self, filename):
        sections = {}

        command_str = f"readelf -S {filename}"
        output = subprocess.check_output(command_str, shell=True)
        regex = r"(\.[\w\-_.]+)\s+\w+\s+([a-f0-9A-F]{8,16})\s([a-f0-9A-F]+)\s([a-f0-9A-F]+)\s\d+\s+(\w?X\w?)"
        matches = re.finditer(regex, str(output), re.MULTILINE)

        for matchNum, match in enumerate(matches, start=1):
            section_name = match.group(1)
            found_address = match.group(2)
            found_offset = match.group(3)
            found_size = match.group(4)
            sections[section_name] = (found_address, found_offset, found_size)
        return sections

    def search_binary_section(self, filename, section_name):
        command_str = f"readelf -S {filename}"
        output = subprocess.check_output(command_str, shell=True)
        
        regex = r"(\.[\w\-_.]+)\s+\w+\s+([a-f0-9A-F]{8,16})\s([a-f0-9A-F]+)\s([a-f0-9A-F]+)"
        matches = re.finditer(regex, str(output), re.MULTILINE)
        
        found = False
        found_address = ''
        found_offset = ''
        found_size = ''
        for matchNum, match in enumerate(matches, start=1):
            section = match.group(1)
            if section == section_name:
                found = True
                found_address = match.group(2)
                found_offset = match.group(3)
                found_size = match.group(4)
                break
        return found, found_address, found_offset, found_size
