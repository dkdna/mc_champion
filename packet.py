from utils import *

class Packet(object):
    def __init__(self, SERVER, PORT, VERSION):
        self.server = SERVER
        self.port = PORT
        self.version = VERSION

    def gen_handshake1(self, val):
        content = ""
        content += "\x00"
        content += b2s(i2v(self.version))
        content += b2s(int2byte(len(self.server)))
        content += self.server
        content += b2s(int2short(self.port))
        content += b2s(i2v(val))
        content += "\x01\x00"
        hexdump(content)
        return content
    
    def gen_handshake(self, val):
        content = ""
        content += "\x00"
        content += b2s(i2v(self.version))
        content += b2s(int2byte(len(self.server)))
        content += self.server
        content += b2s(int2short(self.port))
        content += b2s(i2v(val))
        hexdump(content)
        return content

    def gen_login(self, nickname):
        content = ""
        content += "\x00"
        content += b2s(int2byte(len(nickname)))
        content += nickname
        hexdump(content)
        return content
    
    def gen_chat(self, text):
        content = ""
        content += "\x03"
        content += b2s(int2byte(len(text)))
        content += text
        hexdump(content)
        return content

    def gen_keepalive(self, text):
        content = ""
        content += "\x0c"
        content += text
        return content