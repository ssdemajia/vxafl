#!/bin/sh
stty intr ^]
echo "[*] ctrl+c remapped to ctrl+] for host"
KERNEL=/home/ss/linux-4.8.1
#KERNEL=/home/ss/linux
IMG=/home/ss/IMAGE
/home/ss/qemu-4.2.0/x86_64-softmmu/qemu-system-x86_64 \
  -hda $IMG/stretch.img \
	-m 4096 \
	-smp 1 \
	-s \
	-append "root=/dev/sda console=ttyS0 nokaslr nosmep nosmap quiet" \
	-serial stdio \
	-display none \
  -kernel $KERNEL/arch/x86_64/boot/bzImage

  #-nic tap \
# -net nic -net user,hostfwd=tcp::8022-:22 \
#	-monitor telnet:127.0.0.1:1235,server,nowait
#	-enable-kvm \
# -s makes qemu listen on 1234
# -smp 1 sets it to single core
