from capstone import CS_OPT_SYNTAX_INTEL, Cs, CS_ARCH_X86
from capstone import CS_MODE_32, CS_MODE_64
import re


class Gadget_finder:
    def __init__(self, filename, arch=32):
        self.filename = filename
        self.arch = arch
        try:
            f = open(filename, 'rb')
            self.filebinary = f.read()
        except OSError:
            print('Unable to load binary for gadget search')
            self.filebinary = b'00'

    # expect regular expression for pattern
    def find(self, pattern, start_offset=0, end_offset=0, section_address=0):
        md = None
        if self.arch == 32:
            md = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.syntax = CS_OPT_SYNTAX_INTEL

        gadget_found = False
        gadget_address = 0

        if start_offset > 0 and end_offset > 0:
            bin_section = self.filebinary[start_offset:end_offset]
        else:
            bin_section = self.filebinary
        temp_str = ''
        for i in md.disasm(bin_section, 0x0):
            temp_str += "0x%x: %s %s;" % (i.address, i.mnemonic, i.op_str)

        matches = re.finditer(pattern,
                              str(temp_str).replace('\\n', ''),
                              re.MULTILINE)
        for matchNum, match in enumerate(matches, start=1):
            gadget_address = match.group(1)
            gadget_found = True
            print("Match found:", match.group())

            break

        return gadget_found, gadget_address
