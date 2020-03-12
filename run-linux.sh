#!/bin/sh
stty intr ^]
echo "[*] ctrl+c remapped to ctrl+] for host"
KERNEL=/home/ss/linux-4.8.1
#KERNEL=/home/ss/linux
IMG=/home/ss/IMAGE
QEMU_VERSION="2.10.0"
CPU_TARGET="x86_64"
QEMU_EXEC="./qemu-$QEMU_VERSION/$CPU_TARGET-softmmu/qemu-system-$CPU_TARGET"
$QEMU_EXEC -hda $IMG/stretch.img \
	-m 2048 \
	-smp 1 \
	-s \
	-append "root=/dev/sda console=ttyS0 nokaslr nosmep nosmap quiet" \
	-serial stdio \
	-display none \
  -kernel $KERNEL/arch/x86_64/boot/bzImage \
  -net nic,model=pcnet,macaddr=DE:CD:AE:EF:3E:10 \
  -net tap,ifname=tap0,script=no,downscript=no \
    # -net nic \
  # -net user,hostfwd=tcp::8022-:22 \
  # -S
  # -net user,host=10.0.2.10,hostfwd=tcp::10022-:22 -net nic
  #-nic tap \
# -net nic -net user,hostfwd=tcp::8022-:22 \
#	-monitor telnet:127.0.0.1:1235,server,nowait
#	-enable-kvm \
# -s makes qemu listen on 1234
# -smp 1 sets it to single core
