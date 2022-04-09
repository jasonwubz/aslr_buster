import sys
import re
import string

def get_strings_from_bin(filename, minlen=4):
    """ reference: https://stackoverflow.com/questions/17195924/python-equivalent-of-unix-strings-utility """
    with open(filename, errors="ignore") as f:
        temp_str = f.read()
        result = ""
        last_idx = 0
        for idx, c in enumerate(temp_str):
            last_idx = idx
            if c in string.printable:
                result += c
                continue
            if len(result) >= minlen:
                hex_char = str(temp_str[idx:idx+1]).encode('utf-8').hex()
                if hex_char != "00" :
                    result = ""
                    continue
                yield result
            result = ""
        if len(result) >= minlen:
            yield result

def get_better_strings_from_bin(filename, min=4, start_offset = 0, end_offset = 0):
    with open(filename, mode = 'rb') as f:
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
                if hex_char != "00" :
                    result = ""
                    continue
                yield result, last_idx - len(result)
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result, last_idx - len(result)

def generate_strings(filename, start_offset = 0, end_offset= 0, minlen=4):
    results = {}
    try:
        filename_regex = re.compile('^[\w\-. ]+$')
        for s, str_offset in get_better_strings_from_bin(filename, minlen, start_offset, end_offset):
            matches = re.finditer(filename_regex, s)
            for matchNum, match in enumerate(matches, start=1):
                i_filename = match.group()
                results[str_offset] = i_filename
    except IOError:
        print('Error checking binary for strings!')
    
    return results

def search_string_in_file(filename, search_string, start_offset = 0, end_offset= 0, minlen = 4):
    results = ''
    try:
        for s, str_offset in get_better_strings_from_bin(filename, minlen, start_offset, end_offset):
            if s == search_string:
                return str_offset
    except IOError:
        print('Error checking binary for strings!')    
    return ''