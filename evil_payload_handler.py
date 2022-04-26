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
