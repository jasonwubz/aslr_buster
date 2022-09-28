import subprocess
import re
import string


class Bin_handler:
    """This class is for handling binary files

    The main idea is to use existing commands such as ldd,
    readelf to produce output of the binary and the regex
    is used to extract these information
    """

    def __init__(self, filename):
        self.filename = filename
        self.libc_exists = False
        self.libc_path = ''
        self.arch = 0

    # check if the bin has libc linked to it
    def has_libc(self):
        ldd_output = subprocess.check_output(f'ldd {self.filename}',
                                             shell=True)

        # use regex to find if libc is used
        regex = r"(libc[a-zA-Z0-9-.]+)\s=\>\s([a-zA-Z0-9-_.\/]" + \
                r"*libc[a-zA-Z0-9-.]+)\s(\(0x[0-9a-fA-F]{8,16}\))?"
        matches = re.finditer(regex, str(ldd_output), re.MULTILINE)
        for matchNum, match in enumerate(matches, start=1):
            self.libc_path = match.group(2)
            self.libc_exists = True
        return self.libc_exists

    def search_function(self, filename, function_name):
        command_str = f"readelf -s -W {filename} | grep {function_name}"
        output = subprocess.check_output(command_str, shell=True)

        regex = r"\d*:\s([0-9a-fA-F]{8,16})\s*\d*\s\w*\s*\w*\s*\w*\s*\d*\s" + \
                function_name + \
                r"\@"
        matches = re.finditer(regex, str(output), re.MULTILINE)
        found_address = ''
        found = False
        for matchNum, match in enumerate(matches, start=1):
            found_address = match.group(1)
            found = True
            break
        return found, found_address

    def search_asm_function(self, filename, function_name):
        command_str = f"readelf -s -W {filename} | grep {function_name}"
        output = subprocess.check_output(command_str, shell=True)

        regex = r"\d*:\s([0-9a-fA-F]{8,16})\s*\d*\s\w*\s*\w*\s*\w*\s*\d*\s" + \
                function_name
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

        regex = r"([a-fA-F0-9]{8,16})\s<" + \
                function_name + \
                r"@plt>"
        matches = re.finditer(regex, str(output), re.MULTILINE)
        found_address = ''
        found = False
        for matchNum, match in enumerate(matches, start=1):
            found_address = match.group(1)
            found = True
            break
        return found, found_address

    def search_plt_got(self, filename, function_name, arch=32):
        """Searches for got in the binary
        """
        command_str = f"objdump -d {filename}"
        output = subprocess.check_output(command_str, shell=True)

        regex = None

        if arch == 32:
            regex = r"([a-fA-F0-9]{8,16})\s<" + \
                    function_name + \
                    r"@plt>:(\s.*?)jmp\s*\*0x([a-fA-F0-9]{7,16})"
        else:
            regex = r"([a-fA-F0-9]{8,16})\s<" + \
                    function_name + \
                    r"@plt>:(\s.*?)jmpq\s*\*0x[a-fA-F0-9]{4,16}" + \
                    r"\(%rip\)\s+#\s([a-fA-F0-9]{4,16})"

        matches = re.finditer(regex,
                              str(output).replace('\\n', ' '),
                              re.MULTILINE)
        found_address = ''
        found_got_address = ''
        found = False
        for matchNum, match in enumerate(matches, start=1):
            found_address = match.group(1)
            found_got_address = match.group(3)
            found = True
            break
        return found, found_address, found_got_address

    def get_ax_sections(self, filename):
        """Searches the binary file for AX sections (executable sections).
        Will return a dictionary of sections with AX flag
        """
        sections = {}

        command_str = f"readelf -S -W {filename}"

        try:
            output = subprocess.check_output(command_str, shell=True)
            regex = r"(\.[\w\-_.]+)\s+\w+\s+([a-f0-9A-F]{8,16})" \
                    r"\s([a-f0-9A-F]+)\s([a-f0-9A-F]+)\s\d+\s+(\w?X\w?)"
            matches = re.finditer(regex, str(output), re.MULTILINE)

            for matchNum, match in enumerate(matches, start=1):
                section_name = match.group(1)
                found_address = match.group(2)
                found_offset = match.group(3)
                found_size = match.group(4)
                sections[section_name] = (found_address,
                                          found_offset,
                                          found_size)
        except subprocess.CalledProcessError:
            print("Unable to find section in file")

        return sections

    def search_section(self, filename, section_name):
        command_str = f"readelf -S -W {filename}"
        output = subprocess.check_output(command_str, shell=True)

        regex = r"(\.[\w\-_.]+)\s+\w+\s+([a-f0-9A-F]{8,16})" + \
                r"\s([a-f0-9A-F]+)\s([a-f0-9A-F]+)"
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

    def check_architect(self):
        command_str = f"readelf -h {self.filename}"

        is_elf = False
        elf_type = ''

        try:
            output = subprocess.check_output(command_str, shell=True)

            regex = r"Class:\s+(ELF\d+)"
            matches = re.finditer(regex, str(output), re.MULTILINE)

            for matchNum, match in enumerate(matches, start=1):
                elf_type = match.group(1)
                is_elf = True
                break
            if elf_type.upper() == 'ELF32':
                self.arch = 32
            elif elf_type.upper() == 'ELF64':
                self.arch = 64
            else:
                self.arch = 0
                is_elf = False
        except subprocess.CalledProcessError:
            print("Unable to check architect")
        return is_elf


def get_raw_strings(filename,
                    min=4,
                    start_offset=0,
                    end_offset=0):
    """reference:
    https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility

    Get all possible strings from the binary file
    """
    with open(filename, mode='rb') as f:
        temp_str = f.read()
        if start_offset > 0 and end_offset > start_offset:
            temp_str = temp_str[start_offset:end_offset]
        result = ""
        last_idx = 0
        for i in range(len(temp_str)):
            last_idx = i
            if chr(temp_str[i]) in string.printable:
                result += chr(temp_str[i])
                continue
            if len(result) >= min:
                hex_char = temp_str[i:i+1].hex()
                if hex_char != "00":
                    result = ""
                    continue
                yield result, last_idx - len(result)
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result, last_idx - len(result)

def search_string(filename,
                  search_string,
                  start_offset=0,
                  end_offset=0,
                  minlen=4):

    """Search for a string in the binary
    and return its offset
    """
    try:
        for s, str_offset in get_raw_strings(filename,
                                             minlen,
                                             start_offset,
                                             end_offset):
            if s == search_string:
                return str_offset
    except IOError:
        print('Error checking binary for strings!')
    return ''

def get_filename_strings(filename, start_offset=0, end_offset=0, minlen=4):
    """Find strings that can be used as filenames.
    The returned result is a dictionary where the
    index is the address offset and the value is the
    string.

    Sample:
    results = {
        123: "I'm a string",
        400: "hello"
    }
    """
    results = {}
    try:
        filename_regex = re.compile('^[\\w\\-. ]+$')
        for s, str_offset in get_raw_strings(filename,
                                             minlen,
                                             start_offset,
                                             end_offset):
            matches = re.finditer(filename_regex, s)
            for matchNum, match in enumerate(matches, start=1):
                i_filename = match.group()
                results[str_offset] = i_filename
    except IOError:
        print('Error checking binary for strings!')

    return results
