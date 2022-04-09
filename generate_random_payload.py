
import sys
import os
from os import path
import select
import click
import subprocess

class Fifo_handler:
    def __init__(self, filename, maxsize):
        self.filename = filename
        self.fhandle = False
        self.maxsize = int(maxsize)
        self.open()
        
    
    def create_new(self):
        try:
            self.fhandle.close()
            os.unlink(self.filename)
        except:
            pass
        os.mkfifo(self.filename)
        self.open()

    def open(self):
        try:
            print("opening", self.filename)
            self.fhandle = open(f'./{self.filename}','ab', 0)
            
            return True
        except:
            print("Error opening file")
            return False

    def write(self, content):
        self.fhandle.write(content)


class Generic_payload_file_handler:
    def __init__(self, payload, original_program, current_file = 'generic_payload_by_aslr_buster'):
        self.current_file = current_file
        self.payload = payload
        self.original_program = original_program
        file = open(current_file, "wb", 0)
        file.write(bytearray(payload, 'utf_8'))
        file.close()
    
    def rename_payload_file(self, new_name):
        print("Debug [rename_payload_file]:", new_name)
        if new_name == self.original_program:
            # we do nothing if new file is the same target program
            return
        previous_name = self.current_file
        
        try:
            # we expect previous file to exists, but if not, create new
            if path.exists(previous_name):
                os.rename(previous_name, new_name)
            else:
                file = open(new_name, "wb", 0)
                file.write(bytearray(self.payload))
                file.close()
        except:
            print("Debug: unable to rename payload")
        self.current_file = new_name

# this will generate a pattern that looks like this: Aa0Aa1Aa2...to Zz9
# max length from this pattern is 20306
# reference of idea: https://blog.devgenius.io/buffer-overflow-tutorial-part3-98ab394073e3
def generic_payload(size = 300):
    # 65-90 = A-Z
    # 97-122 = a-z 
    # 48-57 = 0-9
    
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
            c2 +=1
            if c2 > 122:
                c2 =97
                c1 +=1
                # return_str += chr(10)
                if c1 > 90:
                    break
    # print("total length", len(return_str))
    return return_str


if __name__ == '__main__':
    mystr = bytearray(b"A" * 20)
    myfifo = Fifo_handler("benign_payload", len(mystr))
    myfifo.create_new()
    myfifo.open_write(mystr)
  