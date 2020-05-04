from pwn import *
from packet import *
from utils import *
from threading import Thread
import time
import json

SERVER = "144.202.79.93"
BIND_IP = "localhost"
PORT = 25565
LISTEN_PORT = 33784
VERSION = 997

def main():
    global status
    global payload
    Thread(target=packet_main).start()
    packet = Packet(SERVER, PORT, VERSION)
    hs_pack = packet.gen_handshake(2)
    r.send(b2s(int2byte(len(hs_pack))))
    r.send(hs_pack)
    # Login request
    pack = packet.gen_login("r3x")
    r.send(b2s(int2byte(len(pack))))
    r.send(pack)
    # Login success 
    commands = (["/buy 13", "/buy 5", "/exchange 6","/exchange 6"]*5 + ["/buy 13", "/buy 18", "/exchange 6", "/exchange 6"]*6 + ["/buy 15", "/buy 17", "/exchange 6","/exchange 6"]* 10 + ["/buy 5"]*10 + ["/buy 19", "/use 19"]*25 + ["/attack"]+ ["/buy 5"]*10 + ["/buy 19", "/use 19"]*25 + ["/attack"]) + ["/status"]
    print(commands)
    time.sleep(1)
    while True:
        for command in commands:
            if payload:
                pack = packet.gen_keepalive(b2s(payload))
                r.send(b2s(int2byte(len(pack))))
                r.send(pack)
                payload = ""
                print("[+] keepalive sent")
                time.sleep(0.2)
            pack = packet.gen_chat(command)
            r.send(b2s(int2byte(len(pack))))
            r.send(pack)
            time.sleep(1.5)

    print("SUCK")

status = 1
payload = ""
def packet_main():
    global status
    global payload
    while True:
        if status == 1:
            print(r.recv(1)) # possible size of next packet
            uid, uname = login_packet()
            print(uid)
            status = 2
        elif status == 2:
            dump = ord(r.recv(1))
            print(read_until(dump))
            dump = ord(r.recv(1))
            print(read_until(dump))
            print(r.recv(2))
            chat_packet()
            print(r.recv(3))
            chat_packet()
            # recieve dump packet
            print(read_until(270))
            # keep alive packet
            #print("Keep alive")
            pc = "x"
            temp = ""
            while ord(pc) != 0x1f:
                pc = r.recv(1)
                temp += chr(ord(pc))
            print(temp)
            payload = r.recv(5)
            hexdump(b2s(payload))
            status = 3
        elif status == 3:
            print(r.recv(2))
            chat_packet()

def read_until(size):
    fin = ""
    ctr = 0
    while ctr < size:
        temp = b2s(r.recv(size - ctr, 2))
        ctr = ctr + len(temp)
        fin += temp
    return fin 

def handshake_packet():
    packet_type = ord(r.recv(1))
    assert(packet_type == 0x00)
    size = v2i(r.recv(3))
    payload = read_until(size)
    print(payload)

def chat_packet():
    global payload
    packet_type = "x"
    temp = ""
    while ord(packet_type) != 0xf:
        packet_type = r.recv(1)
        if ord(packet_type) == 0x1f:
            payload = r.recv(5)
            hexdump(b2s(payload))
        temp += chr(ord(packet_type))
    print(temp)
    size = v2i(r.recv(2))
    payld = read_until(size)
    #print("[+] recieved a chat packet that has %d type and has size of %d and got a payload of %d" % (packet_type, size, len(payload)))
    try:
        json_data = json.loads(payld.strip()) 
        print(json_data["text"], end="")
        for line in json_data["extra"]:
            print(line["text"], end="")
    except:
        print("No json decode")
        print(payld)

def login_packet():
    packet_type = ord(r.recv(1))
    assert(packet_type == 0x2)
    uid_len = ord(r.recv(1))
    uid = r.recv(uid_len)
    uname_len = ord(r.recv(1))
    uname = r.recv(uname_len)
    return uid, uname

if __name__ == "__main__":
    context.log_level = "DEBUG"
    r = remote(SERVER, PORT)
    main()