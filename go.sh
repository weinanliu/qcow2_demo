#!/bin/bash

set -x

rm *.raw

qemu-img convert -O qcow2 -o compat=0.10 rootfs.busybox.qcow2 rootfs.busybox.version2.qcow2
qemu-img convert -O raw rootfs.busybox.version2.qcow2 the_currect_raw.raw

gcc halo.c
./a.out rootfs.busybox.version2.qcow2
chmod +r rootfs.busybox.version2.qcow2.raw

md5sum the_currect_raw.raw rootfs.busybox.version2.qcow2.raw
