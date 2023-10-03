#!/bin/bash
qemu-system-x86_64 \
    -m 128M \
    -kernel ./bzImage \
    -initrd ./newrootfs.cpio \
#    -nographic \
    -monitor /dev/null \
    -append "console=ttyS0 root=/dev/ram oops=panic panic=1"