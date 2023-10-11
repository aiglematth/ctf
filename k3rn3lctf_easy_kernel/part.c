//
// Code to get some stack leaks and analyze them
//
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DEVICE_PATH "/proc/pwn_device"

int main(void) {
    unsigned long buffer[0x20];
    int device_fd = open(DEVICE_PATH, O_RDWR);

    memset(buffer, 0, sizeof(buffer));
    printf("Read %ld bytes...\n", read(device_fd, buffer, sizeof(buffer)));

    for(int i=0; i<(sizeof(buffer)/8); i++) {
        printf("[%d] = %lx\n", i, buffer[i]);
    }

    return 0;
}