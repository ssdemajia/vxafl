基于内核模糊测试
AFL的链接https://lwn.net/Articles/657959/

## 镜像准备工作
使用buildroot来构建 参考https://medium.com/@daeseok.youn/prepare-the-environment-for-developing-linux-kernel-with-qemu-c55e37ba8ade
构建后需要使用
配置buildroot，添加sudo软件

创建用户"ss"
adduser ss

a) 切换至root账户，为sudo文件增加写权限，默认是读权限
chmod u+w /etc/sudoers

b) 打开文件vim /etc/suduers，在root ALL=(ALL) ALL这一行下面添加
ss ALL=(ALL) ALL
### 挂载example模块
参考 https://stackoverflow.com/questions/4356224/how-to-load-a-custom-module-at-the-boot-time-in-ubuntu
需要将编译好的模块，放入挂载点
```c
sudo mount -o loop stretch.img ~/img
sudo cp example_module/procfs1.ko ~/img
sudo echo 'mymodule' | sudo tee -a  ~/img/etc/modules
sudo cp mymodule.ko /lib/modules/$(uname -r)/kernel/drivers/
sudo umount ~/img
```
有可能需要创建`modules.order`和`modules.builtin`两个文件，用于之后使用`depmod`命令。这里的4.8.1是我实验镜像的linux版本。
```c
touch /lib/modules/4.8.1/modules.order
touch /lib/modules/4.8.1/modules.builtin
```
Debian Linux或Ubuntu Linux使用`/etc/modules`文件来配置启动模块，因此需要将模块名字写入`modules`文件中。
如果遇到问题，查看启动错误指令：`journalctl | grep systemd-modules`

之后在虚拟机中/etc/init.d/S40network中添加一行udhcpc来获取ip地址https://github.com/OP-TEE/build/issues/103

如何获得模块代码段地址：https://stackoverflow.com/questions/6384605/how-to-get-the-address-of-a-kernel-module-that-was-inserted-using-insmod

在linux4级页表中linux module所在内存地址范围：https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt

Linux模块与普通程序的不同 http://tldp.org/LDP/lkmpg/2.6/html/x427.html

> 程序通常以main（）函数开始，执行一堆指令，并在这些指令完成时终止。 内核模块的工作方式略有不同。 模块始终以`init_module`或您通过`module_init`调用指定的函数开头。 这是模块的输入功能； 它告诉内核模块提供了什么功能，并设置内核以在需要时运行模块的功能。 完成此操作后，入口函数将返回并且模块将不执行任何操作，直到内核想要对模块提供的代码进行处理为止。


调试kernel module https://medium.com/@navaneethrvce/debugging-your-linux-kernel-module-21bf8a8728ba

linux kernel被加载到固定的地址后，可以通过readelf -s procfs1.ko查看函数的在ko中的偏移，以及该函数的代码长度

avatar获取fs_base和gs_base会有问题 // todo

x64参数传递http://abcdxyzk.github.io/blog/2012/11/23/assembly-args/
参数个数大于 7 个的时候
H(a, b, c, d, e, f, g, h);
a->%rdi, b->%rsi, c->%rdx, d->%rcx, e->%r8, f->%r9
h->8(%esp)
g->(%esp)

在x64体系结构中FS寄存器与GS寄存器与GDT无关，他们的基值保存在MSR寄存器中



### 安装qemu

ubuntu apt安装

```c
sudo apt install qemu
```

ubuntu apt安装的qemu版本

```bash
➜  ~ qemu-system-x86_64 --version
QEMU emulator version 2.11.1(Debian 1:2.11+dfsg-1ubuntu7.21)
Copyright (c) 2003-2017 Fabrice Bellard and the QEMU Project developers
```

源码安装

```c
wget https://download.qemu.org/qemu-4.2.0.tar.xz
sudo apt install -y libsdl2-dev build-essential zlib1g-dev pkg-config libglib2.0-dev binutils-dev libboost-all-dev autoconf libtool libssl-dev libpixman-1-dev libpython-dev python-pip python-capstone virtualenv
./configure --target-list=x86_64-softmmu --enable-sdl
```

然后使用qemu运行

```bash
#!/bin/sh
stty intr ^]
echo "[*] ctrl+c remapped to ctrl+] for host"
KERNEL=/home/ss/linux
IMG=/home/ss/IMAGE
/home/ss/qemu-4.2.0/x86_64-softmmu/qemu-system-x86_64 \
  -hda $IMG/stretch.img \
	-net nic -net user,hostfwd=tcp::8022-:22 \
	-m 4096 \
	-smp 1 \
	-s \
	-append "root=/dev/sda console=ttyS0 debug nokaslr quiet" \
	-serial stdio \
	-enable-kvm \
	-display none \
  -kernel $KERNEL/arch/x86_64/boot/bzImage
```

## 获得目标函数地址

模块的地址加载后可以在`/sys/module/模块名/sections/.text`获得

在获得procfs1的地址`0xffffffffa0000000`后，通过`readelf -s procfs1.ko`得到模块内符号的相对位置，

```bash
Symbol table '.symtab' contains 35 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
    17: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS procfs1.c
    18: 0000000000000000    11 FUNC    LOCAL  DEFAULT    2 read_callback
    19: 000000000000000b    73 FUNC    LOCAL  DEFAULT    2 write_callback
    20: 0000000000000054    72 FUNC    LOCAL  DEFAULT    2 simple_init
```

通过计算得到write_callback地址``0xffffffffa0000000+b`等于`0xffffffffa000000b`

### QA

Q:出现`qemu-system-x86_64: -net user,hostfwd=tcp::8022-:22: Could not set up host forwarding rule 'tcp::8022-:22'`

A:之前的qemu进程没有关闭，需要手动kill它

## 参考

1. kernel physical page allocation https://www.kernel.org/doc/gorman/html/understand/understand009.html
2. slab allocator  https://www.kernel.org/doc/gorman/html/understand/understand011.html
3. 添加用户 https://blog.csdn.net/timothy93bp/article/details/77679000
# Linux namespace
https://www.cnblogs.com/sparkdev/p/9365405.html

namespace对系统资源进行封装隔离，使得处于不同命名空间的进程有独立的系统资源，改变某个namespace系统资源只会影响当前namespace里的进程
通过unshare函数可以在原进程上进行namespace隔离