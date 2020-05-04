import struct

def i2v(value):
    out = bytes()
    while True:
        byte = value & 0x7F
        value >>= 7
        out += struct.pack("B", byte | (0x80 if value > 0 else 0))
        if value == 0:
            break
    return out
    
def v2i(var_string):
    bytes_encountered = 0
    number = 0
    for byte in b2s(var_string):
        byte = ord(byte)
        number |= (byte & 0x7F) << 7 * bytes_encountered
        if not byte & 0x80:
            break
        bytes_encountered += 1
        if bytes_encountered > 10:
            raise ValueError("Tried to read too long of a VarInt")
    return number

def b2s(a):
    return "".join(list(map(chr, a)))

def int2byte(a):
    return struct.pack('>B', a)

def int2short(a):
    return struct.pack('>H', a)

def hexdump(a):
    for i in a:
        print(hex(ord(i)).replace("0x","").zfill(2), end="")
    print("--")
