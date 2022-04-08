class Evil_payload_handler:
    def __init__(self, maxsize, offset = 0, mode = 32):
        self.maxsize = maxsize
        self.content = bytearray(b"A" * self.maxsize)
        self.offset = offset
        self.mode = mode

    def get_payload(self):
        return self.content

    # adds content to payload and auto-increment offset counter
    def add_content(self, segment_int = 0):
        if self.mode == 32:
            self.content[self.offset:self.offset + 4] = (segment_int).to_bytes(4,byteorder='little')
            self.offset += 4
        else:
            self.content[self.offset:self.offset + 8] = (segment_int).to_bytes(8,byteorder='little')
            self.offset += 8

    def change_offset(self, offset = 0):
        self.offset = offset

    def write_to_plaintext(self, current_file):
        file = open(current_file, "wb", 0)
        file.write(self.content)
        file.close()

# if __name__ == '__main__':
#     evil = Evil_payload_handler(300, 34, 32)
#     evil.add_content(0xdeadbeef)
#     evil.add_content(0x00000000)
#     print(evil.get_payload())
#     evil.write_to_plaintext('random_test')