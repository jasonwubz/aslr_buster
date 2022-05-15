import os
from os import path


class Fifo_handler:
    def __init__(self, filename):
        self.filename = filename
        self.fhandle = False
        self.open()

    def unlink(self):
        try:
            os.unlink(self.filename)
        except OSError:
            pass

    def create_new(self):
        created = False
        try:
            os.mkfifo(self.filename)
            created = True
        except OSError:
            pass
        return created

    def open(self, open_mode='wb'):
        try:
            self.fhandle = open(f'./{self.filename}', open_mode, 0)
            return True
        except OSError:
            print("Error opening file")
            return False
        except IOError:
            print("Error opening file")
            return False

    def write(self, content):
        self.fhandle.write(content)

    def close(self):
        self.fhandle.close()


class Generic_payload_handler:
    def __init__(self,
                 payload,
                 target_program,
                 current_file='_generic_payload'):

        self.current_file = current_file
        self.payload = payload
        self.target_program = target_program
        file = open(current_file, "wb", 0)
        file.write(bytearray(payload, 'utf_8'))
        file.close()

    def rename_payload_file(self, new_name):
        if new_name == self.target_program:
            # do nothing if new file is the same target program
            return
        previous_name = self.current_file

        try:
            # expect previous file to exist, but if not, create new
            if path.exists(previous_name):
                os.rename(previous_name, new_name)
            else:
                file = open(new_name, "wb", 0)
                file.write(bytearray(self.payload))
                file.close()
        except OSError:
            print("Debug: unable to rename payload")
        self.current_file = new_name


def generic_payload(size=600):
    """This will generate a pattern that looks like this:
        Aa0Aa1Aa2...to Zz9
    The max length from this pattern is 20306.

    reference:
    https://blog.devgenius.io/buffer-overflow-tutorial-part3-98ab394073e3

    Notes:
        65-90 = A-Z
        97-122 = a-z
        48-57 = 0-9
    """

    return_str = ''
    c1 = 65
    c2 = 97
    c3 = 48

    while len(return_str) < size:
        return_str += chr(c1)
        return_str += chr(c2)
        return_str += chr(c3)

        c3 += 1
        if c3 > 57:
            c3 = 48
            c2 += 1
            if c2 > 122:
                c2 = 97
                c1 += 1
                if c1 > 90:
                    break
    return return_str


class Evil_payload_handler:
    def __init__(self, maxsize, offset=0, mode=32):
        self.maxsize = maxsize
        self.content = bytearray(b"A" * self.maxsize)
        self.offset = offset
        self.mode = mode

    def get_payload(self):
        return self.content

    # adds content to payload and auto-increment offset counter
    def add_content(self, segment_int=0):
        bit_size = 0
        if self.mode == 32:
            bit_size = 4
        else:
            bit_size = 8

        seg_bytes = (segment_int).to_bytes(bit_size, byteorder='little')
        self.content[self.offset:self.offset + bit_size] = seg_bytes
        self.offset += bit_size

    def change_offset(self, offset=0):
        self.offset = offset

    def write_to_plaintext(self, current_file):
        file = open(current_file, "wb", 0)
        file.write(self.content)
        file.close()


def has_null_bytes(hexstr):
    if "00" in hexstr:
        return True
    return False
