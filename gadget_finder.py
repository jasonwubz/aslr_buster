from capstone import CS_OPT_SYNTAX_INTEL, Cs, CS_ARCH_X86, CS_MODE_32
from bin_handler import Bin_handler
import re


class Gadget_finder:
    def __init__(self, filename):
        self.filename = filename
        try:
            f = open(filename, 'rb')
            self.filebinary = f.read()
        except OSError:
            print('Unable to load binary for gadget search')
            self.filebinary = b'00'

    # expect regular expression for pattern
    def find(self, pattern, start_offset=0, end_offset=0, section_address=0):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
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

        return gadget_found, gadget_address


if __name__ == '__main__':
    program_name = 'vuln_01'
    b_handler = Bin_handler(program_name)
    ax_sections = b_handler.get_ax_sections(program_name)
    gfinder = Gadget_finder(program_name)
    found_gadget = False
    gadget_address = ''
    for esection in ax_sections:
        print("Checking executable section", esection)
        esec_add_int = int(ax_sections[esection][0], 16)
        esec_start_int = int(ax_sections[esection][1], 16)
        esec_end_int = esec_start_int + int(ax_sections[esection][2], 16)
        find_regex = r"0x([a-f0-9]+):\spop\se\w?x;\s?(0x[a-f0-9]+):\s?ret\s?;"
        found_gadget, gadget_address = gfinder.find(find_regex,
                                                    esec_start_int,
                                                    esec_end_int)
        if found_gadget:
            print("Found gadget in section",
                  esection,
                  "at offset",
                  gadget_address)
