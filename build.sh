#!/bin/sh
#
# Copyright 2019 shaoshuai All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------
# american fuzzy lop - QEMU build script
# --------------------------------------
#
# Written by shaoshuai <2chashao@gmail.com>
#

QEMU_VERSION="2.10.0"
CPU_CORE_NUMS=`cat /proc/cpuinfo| grep processor | wc -l`
echo "++++++++++++++++++++++++++++++++++++++++++++++++"
echo "+  AFL base vxworks image fuzzer build script  +"
echo "++++++++++++++++++++++++++++++++++++++++++++++++"

# vxworks指令集
CPU_TARGET="i386"
echo "[*] Configuring QEMU"
cd qemu_mode/qemu-$QEMU_VERSION

CFLAGS="-O3 -ggdb" ./configure \
  --disable-gtk --enable-sdl --disable-vnc \
  --target-list="$CPU_TARGET-softmmu" || exit 1
# 目前先打开sdl，之后在正式版本中关闭

echo "[*] Build QEMU"
make -j $CPU_CORE_NUMS || exit 1
echo "[+] Build QEMU successful!"

cd ../..

echo "[*] Build AFL"
make -j $CPU_CORE_NUMS || exit 1
echo "[+] Build AFL successful!"


