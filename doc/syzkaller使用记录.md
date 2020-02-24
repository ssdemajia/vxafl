syzkaller https://lwn.net/Articles/677764/
用户空间模糊测试
模糊测试的基本方法是大量生成随机的输入到程序中，然后观察程序的状态，但是这种方法仅仅盲目地生成随机数据，无法找到深层次的程序漏洞，效率十分低下。另一种模糊测试技术使用模板来生成合法输入来发现深层漏洞，针对每一种目标需要手动创建模板用于测试，需要要目标相关的领域知识。
最近出现了以覆盖率作为指导的模糊测试技术，比如Michał Zalewski写的American fuzzy lop AFL和clang的LibFuzzer，这些模糊测试技术不需要目标模板，而是使用二进制编译时插入的指令来获得运行时的覆盖信息，为获得更高的覆盖率，这些模糊测试技术会尽可能的扩大测试输入变异。同时这些模糊测试技术能够很好的与内存检测技术一同发现潜在的错误，比如ASAN、TSAN
syzkaller需要基于每个任务跟踪覆盖率数据，并将其从内核导出到外部，syzkaller使用的是/sys/kernel/debug/kcov，同时为了与内存检测工具一起配合，需要使用KASAN（kernel adddress sanitizer）打开。
syzkaller使用QEMU来运行已经编译好的内核，有内核系统中的syz-fuzzer和syz-executor来运行指定系统调用，然后使用/sys/kernel/debug/kcov来获得覆盖信息
对于不使用模拟的测试方法速度会很快，但是他们缺少对无源码系统的测试方法。
syzkaller创建x86_64内核测试环境 https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md

在Syzkaller之前的Trinity
while (true) syscall(rand(), rand(), rand());
在知道参数类型的时候：
while (true) syscall(rand(), rand_fd(), rand_addr());
只能找到浅层的漏洞

而Syzkaller是Coverage-guided grammar based kernel fuzzer

算法： 1.一开始是空的程序预料库 2.生成一个新的程序语料或者选择一个已有程序作为语料 3.运行程序，收集覆盖信息 4.如果新的代码被覆盖，最小化程序，然后添加至预料库


Skzkaller使用：
https://github.com/google/syzkaller/blob/master/docs/linux/setup.md
首先安装go语言
wget https://dl.google.com/go/go1.13.5.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.13.5.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
然后下载syzkaller，go get -u -d github.com/google/syzkaller/...
cd $HOME/go/src/github.com/google/syzkaller
make
生成的二进制程度在bin文件夹中

制作镜像
sudo apt-get install debootstrap
syzkaller/tools/create-images.sh

在使用tools/create-image.sh后会生成公钥私钥
mkdir ~/img
装载镜像 sudo mount -o loop stretch.img ~/img
将公钥拷贝 sudo cp stretch.id_rsa.pub ~/img/root
之后 ssh -p 10021 -i IMAGE/stretch.id_rsa root@127.0.0.1 就能免密码登录了
ss.cfg
{
 "target": "linux/amd64",
 "http": "127.0.0.1:10233",
 "workdir": "/home/ss/go/src/github.com/google/syzkaller/workdir",
 "kernel_obj": "/home/ss/linux",
 "image": "/home/ss/IMAGE/stretch.img",
 "sshkey": "/home/ss/IMAGE/stretch.id_rsa",
 "syzkaller": "/home/ss/go/src/github.com/google/syzkaller",
 "procs": 4,
 "type": "qemu",
 "vm": {
  "count": 4,
  "kernel": "/home/ss/linux/arch/x86_64/boot/bzImage",
  "cpu": 2,
  "mem": 2048
 }
}
需要将bin文件夹也拷贝到镜像stretch.img中
然后就能运行了sudo bin/syz-manager -config=ss.cfg

syzkaller的问题在于只模糊测试系统调用，而unicorefuzz也模糊测试内核所有代码，而且可以在任意位置运行
