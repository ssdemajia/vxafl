---
title: qemu
date: 2020-02-16 16:33:50
tags: qemu
---

tcg_qemu_tb_exec函数执行当前translation block

tcg_qemu_tb_exec：
`@env：CPU的CPUArchState *`
` @tb_ptr：TB执行的生成代码的地址`

从给定的翻译块开始执行代码。在链接翻译块的情况下，执行可以从给定的TB进行到连续的TB。控制仅在需要从顶层循环执行某些操作时才返回：要么控制必须传递到尚未直接链接的TB，要么需要处理诸如中断之类的异步事件。

返回值是指向下一个要执行的TB的指针（如果已知，则为零）。假定此指针是4对齐的，并且底部的两位用于返回更多信息：
 0、1：此TB与下一个TB之间的链接是通过指定的TB索引（0或1）。也就是说，我们通过`goto_tb <index>`（相当于）离开了TB。主循环使用它来确定如何将刚刚执行的TB链接到下一个。
 2：我们正在使用指令计数代码生成，并且由于该指令计数器在执行过程中途达到零，因此我们并未开始执行该TB。在这种情况下，返回的下一个TB指针是我们将要执行的TB，调用者必须安排执行剩余的指令数。
 3：我们停止是因为设置了CPU的`exit_request`标志（通常意味着有一个中断需要处理）。返回的下一个TB指针是当我们注意到待处理的退出请求时将要执行的TB。

如果底部两位指示"exit-via-index"，则CPU状态已正确同步并准备好执行下一个TB（尤其是来宾PC是下一个要执行的地址）。否则，我们放弃了执行此TB在启动之前，调用者必须使用返回的下一个TB指针调用`cpu_pc_from_tb()`来修复CPU状态。

请注意，TCG目标可能使用与默认值不同的`tcg_qemu_tb_exec`定义（该定义仅调用`tcg_target_qemu_prologue()`发出的`prologue.code`）。



## Triforce内部实现文档

### ProjectTriforce内部

ProjectTriforce的AFL版本与库存的AFL有所不同。标准AFL已经支持QEMU的模糊测试，因此许多工作已经完成。本文档总结了一些更改和设计选择。

### 模糊测试设计

通常，在使用AFL进行模糊测试时，会为每个测试用例启动一个驱动程序，并运行到完成或崩溃。在整个系统的环境中进行模糊测试时，这并非总是希望或不可能的。我们的设计允许托管的操作系统引导和加载驱动程序，该驱动程序控制模糊的生命周期以及托管测试用例。

驱动沟通
通过添加到CPU的特殊指令（称为“ aflCall”）与虚拟机连接。它支持多种操作：

* `startForkserver`-此调用使虚拟机启动AFL fork服务器。调用之后，虚拟机中的每个操作都将在虚拟机的`fork`副本中运行，该副本仅会持续到测试用例结束。副作用是，此调用将基于参数在每个派生的子级中启用或禁用CPU计时器。禁用CPU计时器可以使模糊测试更具确定性，但也可能会干扰某些guest操作系统功能的正常运行。
*  `getWork`-此调用使虚拟机从主机操作系统中的文件中读取下一个输入，并将其内容复制到来宾操作系统中的缓冲区中。
* `startWork`-这个调用可以追踪到AFL的边缘图（edge map)。仅对startWork调用中指定的虚拟地址范围执行跟踪。可以多次调用此命令以调整跟踪指令的范围。例如，您可以选择在分析输入文件时跟踪驱动程序本身，然后在基于输入文件执行系统调用时跟踪内核。 AFL的搜索算法只会知道被跟踪的边缘，此调用提供了一种方法来调整要跟踪的系统部分。
* `endWork`-此调用通知虚拟机测试用例已完成。它允许驱动程序传递退出代码。虚拟机的分支副本将以指定的退出代码退出，该退出代码由fork服务器传送回AFL，并用于确定测试用例的结果。

除了驱动程序调用`endWork`之外，如果检测到紧急情况，虚拟机可以结束测试用例。这是通过为QEMU虚拟机提供一个指定应急函数地址的参数来实现的。如果曾经调用过该函数，则测试用例的状态为32终止。请注意，此参数可以指定感兴趣的任何基本块，而不必表示操作系统的“ panic”函数。

虚拟机还可以通过使用Linux的log_store函数的地址指定QEMU的参数来拦截日志记录函数。虚拟机假定执行此地址时，寄存器中包含Linux`log_store`函数的参数，并且它将提取日志消息并将其写入`logstore.txt`文件。这个
不会触发测试用例的立即终止。但是，它确实设置了一个内部标志，指示该测试用例导致了日志记录。以后调用`doneWork`时，虚拟机可以选择将值64与退出代码进行或运算，以指示发生了日志记录。但是，由于我们已经在源代码中禁用了此功能，
并没有发现它特别有用。

典型的ProjectTriforce AFL模糊器将执行以下步骤：

1. 引导操作系统。

2. 操作系统将调用模糊驱动程序作为其一部分

启动过程。
驱动程序将：

1. 启动AFL fork服务器。
2. 获得一个测试用例。
3. 启用解析器的跟踪。
4. 解析测试用例。
5. 启用内核或内核某些部分的跟踪。
6. 根据已解析的输入调用内核功能。
7. 通知测试用例成功完成（如果测试用例并没有因为panic而提前终止)。

在开始对每个测试用例重复fork服务器之后，`afl-fuzz`程序将安排所有这些步骤。

请注意，由于模糊测试程序在虚拟机的fork副本中运行，因此每个测试用例的内核的整个内存状态都是隔离的。如果操作系统使用内存以外的任何其他资源，这些资源将不会在测试用例之间隔离。因此，通常希望使用内存文件系统（例如Linux ramdisk映像）来引导操作系统。

## QEMU

ProjectTriforce的QEMU版本大量借鉴了AFL QEMU补丁。这些补丁已经包含了将执行边缘追踪到AFL边缘图中的代码。但是，由于QEMU的执行策略，我们发现跟踪中存在一个细微的错误：有时QEM

### TranslationBlock的执行路径

```c
cpu_tb_exec
```

TB的执行路径:

```c
// cpu-exec.c
int cpu_exec(CPUState *cpu) {
    while (!cpu_handle_exception(cpu, &ret)) {
        TranslationBlock *last_tb = NULL;
        int tb_exit = 0;

        while (!cpu_handle_interrupt(cpu, &last_tb)) {
            TranslationBlock *tb = tb_find(cpu, last_tb, tb_exit);
            cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);
        }
    }
}
```

然后需要tb_find来找到对于的Translation Block

```c
static inline TranslationBlock *tb_find(CPUState *cpu,
                                        TranslationBlock *last_tb,
                                        int tb_exit)
{
    cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
    tb = tb_htable_lookup(cpu, pc, cs_base, flags); // 查找对应已翻译代码块
    if (!tb)
        tb = tb_gen_code(cpu, pc, cs_base, flags, 0);  //当没有已翻译的代码时
    return tb;
}
```

在tb_gen_code函数中

```c
TranslationBlock* tb_gen_code() {
    phys_pc = get_page_addr_code(env, pc); // 获得代码对应的物理地址
    gen_intermediate_code(cpu, tb); // 生成TCG-IR中间代码， qemu-2.10.0/target/i386/translate.c中
    tcg_gen_code(tcg_ctx, tb); // 根据TCG-IR生成主机代码
}
```

![](https://xzfile.aliyuncs.com/media/upload/picture/20190628103129-d5bf6336-994c-1.jpg)

在翻译时会在基本块前后添加prologue和epilogue，用于处理基本块之间跳转、恢复控制操作

在vxworks镜像中scanf的地址为0x31bdb0

```c
qemu_tcg_rr_cpu_thread_fn
    tcg_cpu_exec
    	cpu_exec
            cpu_handle_interrupt
                x86_cpu_exec_interrupt
                    do_interrupt_x86_hardirq
                        do_interrupt_all
                            do_interrupt_protected
                                cpu_ldl_kernel
```



## 内核模糊测试设计

内核模糊测试的困难：

1. 输入测试用例的放置
2. 目标系统的模拟
3. 目标系统的监控
4. 崩溃分类与检测



## GDB调试

1、程序运行参数。 
set args 可指定运行时参数。（如：set args -nographic -hda /home/ss/work/MS-DOS.vmdk -mem-path /home/ss/work/vxafl/qemu_mem_path） 
show args 命令可以查看设置好的运行参数。 

2、程序断点

break 10  

break test.c:10

break main

break test.c:main

break system

break open

b afl_forkserver

3、线程

显示线程 i threads

4、远程调试

target remote localhost:1234 需要qemu参数加上-s ，并且加上-S停止在最开始时。

读入vxworks镜像

symbol /home/ss/work/vxWorks

5、查看

查看当前程序栈的内容: x/10x $sp-->打印stack的前10个元素

查看栈帧

```bash
(gdb) info frame
Stack level 0, frame at 0x7f6fc60:
 eip = 0x30d4d6 in CrashFunc (../usrAppInit.c:33); saved eip = 0x30d54c
 called by frame at 0x7f6fcf0
 source language c.
 Arglist at 0x7f6fc58, args: buf=0x7f6fc84 "123"
 Locals at 0x7f6fc58, Previous frame's sp is 0x7f6fc60
 Saved registers:
  ebp at 0x7f6fc58, eip at 0x7f6fc5c
```

 这个saved eip就是当前函数返回后继续执行的eip。

6、attch到一个进程

gdb -p pid

7、用gdb调试程序的子进程
原创cjfeii 最后发布于2014-03-20 21:09:46 阅读数 13477  收藏
展开
follow-fork-mode

follow-fork-mode的用法为：

set follow-fork-mode [parent|child]

parent: fork之后继续调试父进程，子进程不受影响。
child: fork之后调试子进程，父进程不受影响。
因此如果需要调试子进程，在启动gdb后：

(gdb) set follow-fork-mode child

## QEMU内存

当模糊测试时需要保持当前虚拟机内存状态，用于每次测试后恢复虚拟机状态到函数入口时。

QEMU的内存api模拟了：内存、I/O总线、QEMU控制器。这些api允许建模：

- 普通内存
- 内存映射IO（MMIO）。常见的控制设备的方式是在每个控制器上有几个寄存器用来与CPU进行通信，通过写入这些寄存器，操作系统可以命令设备进行特定操作，也读取这些寄存器来了解设备的状态。而内存映射I/O将控制器映射到内存空间中，每个控制器分配的空间是唯一的。
- 可以动态将物理内存区域重新路由到不同目的地的内存控制器

QEMU内存提供：

- 跟踪客户操作系统的RAM变化
- 为kvm设置合并内存
- 为kvm设置ioeventfd区域

内存被建模为`MemoryRegion`对象的非循环图。最底层（叶子节点）是RAM和MMIO区域，其他的节点则表示为总线（bus）、已路由内存区域的内存控制器。

除了`MemoryRegion`对象外，内存api还为每个根节点以及可能的中间`MemoryRegion`对象提供`AddressSpace`对象。从CPU或设备的角度来看它们代表内存。

### 内存区域类型

有多种类型的内存区域（全部由单个C类型的MemoryRegion表示）：

- RAM：RAM区域只是可供客户操作系统使用的一系列宿主内存。
    您通常使用`memory_region_init_ram（）`初始化它们。一些特殊目的需要变体`memory_region_init_resizeable_ram（）`，`memory_region_init_ram_from_file（）`或`emory_region_init_ram_ptr（）`。

- MMIO：由主机回调实现的来宾存储器范围；每次读取或写入都会导致在主机上调用回调。您可以使用`memory_region_init_io（）`初始化它们，并向其传递一个描述回调的`MemoryRegionOps`结构。

- ROM：ROM存储区的工作方式类似于RAM，用于读取（直接访问主机存储区），并禁止写操作。您可以使用`memory_region_init_rom（）`初始化它们。

- ROM设备：ROM设备的内存区域的工作方式类似于RAM用于读取（直接访问主机内存区域），但类似于MMIO进行写入（调用回调）。您可以使用`memory_region_init_rom_device（）`初始化它们。

- IOMMU区域：IOMMU区域会转换对其的访问地址，并将其转发到其他目标内存区域。顾名思义，这些仅用于为IOMMU建模，而不是用于简单设备。您可以使用`memory_region_init_iommu（）`初始化它们。

- 容器：容器仅包含其他存储区域，每个存储区域具有不同的偏移量。容器可用于将多个区域分组为一个单元。例如，PCI BAR可以由RAM区域和MMIO区域组成。容器的子区域通常是不重叠的。在某些情况下，重叠区域会很有用；例如，可以用MMIO或ROM覆盖RAM子区域的内存控制器，或者不阻止卡声明重叠BAR的PCI控制器。您可以使用`memory_region_init（）`初始化一个纯容器。

- 别名：另一个区域的子部分。别名允许将一个区域拆分为不连续的区域。使用的示例是当来宾地址空间小于所寻址的RAM量时使用的存储库，或者是将主内存拆分为暴露“ PCI孔”的内存控制器。别名可以指向任何类型的区域，包括其他别名，但是别名不能直接或间接指向自身。您可以使用`memory_region_init_alias（）`初始化它们。

- 保留区：保留区主要用于调试。它声明了QEMU本身不应该处理的I / O空间。典型的用途是跟踪启用KVM时由主机内核处理的地址空间部分。  您可以使用`memory_region_init_reservation（）`或通过将NULL回调参数传递给`memory_region_init_io（）`来初始化它们。

将子区域添加到不是纯容器的区域（即，添加到MMIO，RAM或ROM区域）是有效的。 这意味着该区域将像容器一样工作，除了容器区域内未被任何子区域声明的任何地址都由容器本身（即，通过其MMIO回调或RAM支持）来处理。 但是，通常可以用一个纯容器实现相同的效果，该容器的子区域之一是覆盖整个地址范围的低优先级“背景”区域。 这通常更清晰，更可取。 不能将子区域添加到别名区域。

### 内存迁移

如果内存区域由主机内存（RAM，ROM和ROM设备内存区域类型）支持，则此主机内存需要在迁移时复制到目标。 这些分配的API
您的主机内存还将注册该内存，以便将其迁移：

- memory_region_init_ram（）
- memory_region_init_rom（）
- memory_region_init_rom_device（）

对于大多数设备和板卡来说，这是正确的。 如果您有特殊情况需要自己管理后备存储器的迁移，则可以调用以下函数：

- memory_region_init_ram_nomigrate（）
- memory_region_init_rom_nomigrate（）
- memory_region_init_rom_device_nomigrate（）
  它仅初始化`MemoryRegion`并保留向调用者的处理迁移。

函数：

- memory_region_init_resizeable_ram（）
- memory_region_init_ram_from_file（）
- memory_region_init_ram_from_fd（）
- memory_region_init_ram_ptr（）
- memory_region_init_ram_device_ptr（）

仅用于特殊情况，因此它们不会自动注册要迁移的后备内存； 呼叫者必须在必要时管理迁移。

### 内存区域

区域由构造函数分配名称。 对于大多数区域，这些区域仅用于调试目的，但RAM区域也使用该名称来标识实时迁移部分。 这意味着RAM区域名称需要具有ABI稳定性。

### 内存区域生命周期

一个内存区域是由`memory_region_init *（）`函数创建的，并附加到对象，该对象充当其所有者或父对象。只要来宾（host）对区域可见，或者只要虚拟CPU或其他设备正在使用该区域，QEMU就会确保所有者对象保持活动状态。例如，所有者对象不会在`address_space_map`操作和相应的`address_space_unmap`之间死亡。

创建后，可以使用`memory_region_add_subregion（）`将区域添加到地址空间或容器中，并使用`memory_region_del_subregion（）`删除区域。

可以在区域生命周期中更改各种区域属性（只读，脏日志，合并的mmio，ioeventfd）。一旦使该区域可见，它们就会生效。这可以是立即，以后或永远不会。

当所有者对象死亡时，存储区域的析构会自动发生。

但是，如果内存区域是动态分配的数据结构的一部分，则应在释放数据结构之前调用`object_unparent（）`销毁内存区域。有关示例，请参见hw / vfio / pci.c中的`VFIOMSIXInfo`和`VFIOQuirk`。

只要设备或CPU正在使用内存区域，就不得破坏它。为此，通常不要在设备的生存期内动态创建或破坏内存区域，而只能在内存区域所有者的`instance_finalize`回调中调用`object_unparent（）`。然后，显然也应该在`instance_finalize`回调中释放包含内存区域的动态分配的数据结构。

如果违反此规则，可能会发生以下情况：

- 内存区域的所有者通过`memory_region_ref`获得了一个引用（例如，由`address_space_map`获取）

- 该区域是非父区域，并且不再拥有所有者

- 调用`address_space_unmap`时，对内存区域所有者的引用将泄漏。


上述规则有一个例外：可以随时为别名或容器区域调用object_unparent。因此，也可以在设备的生命周期内动态创建或销毁别名和容器区域。

这种特殊用法是有效的，因为别名和容器仅帮助QEMU建立来宾的内存映射。他们从来没有直接停止过。永远不会在别名或容器上调用`memory_region_ref`和`memory_region_unref`，因此不会发生上述情况。利用此异常几乎是没有必要的，因此不鼓励使用它，但是尽管如此，它还是在少数地方使用。

对于“没有所有者”的区域（在创建时传递NULL），实际上将机器对象用作所有者。由于从不为机器对象调用`instance_finalize`，因此您绝不能在没有所有者的区域上调用`object_unparent`，除非它们是别名或容器。

### 重叠内存区域和优先级

通常，内存区域可能不会相互重叠。一个内存地址解码成一个目标。在某些情况下，允许区域重叠，有时控制客户操作系统可以看到哪个重叠区域是有用的。这是通过`memory_region_add_subregion_overlap（）`完成的，它允许区域与同一容器中的任何其他区域重叠，并指定一个优先级，该优先级允许核心决定在同一地址的两个区域中的哪个可见（最高获胜）。

优先级值是带符号的，默认值为零。这意味着您可以使用`memory_region_add_subregion_overlap（）`来指定必须位于其他任何“上方”的区域（优先级为正），也可以指定位于其他“以下”背景的区域（优先级为负）。

如果重叠中的较高优先级区域是容器或别名，则较低优先级区域将通过不将子区域映射到其地址范围的该区域而出现在较高优先级区域留下的任何“空洞”中。 （这适用于递归操作-如果子区域本身是容器或别名，它们会留下漏洞，则优先级较低的区域也将出现在这些漏洞中。）

例如，假设我们有一个大小为0x8000的容器A，其中有两个子区域B和C。B是一个映射为0x2000，大小为0x4000，优先级为2的容器； C是映射为0x0，大小为0x6000，优先级为1的MMIO区域。B当前具有其自己的两个子区域：D在偏移量0处的大小为0x1000，E在偏移量0x2000处的大小为0x1000。如图所示：

```c
        0      1000   2000   3000   4000   5000   6000   7000   8000
        |------|------|------|------|------|------|------|------|
  A:    [                                                      ]
  C:    [CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC]
  B:                  [                          ]
  D:                  [DDDDD]
  E:                                [EEEEE]
```

那么，将在该地址范围内看到的区域是： `[CCCCCCCCCCCCCC] [DDDDD] [CCCCC] [EEEEE] [CCCCC]`

由于B的优先级高于C，因此即使其与C重叠，其子区域也将显示在平面图中。在B尚未映射任何C区域的范围内，将出现C。

如果B提供了自己的MMIO操作（即它不是纯容器），则这些操作将用于D或E未处理的其范围内的任何地址，结果将是：`[CCCCCCCCCCCCCC] [DDDDD] [BBBBB] [EEEEE] [BBBBB]`

优先级值对于容器而言是本地的，因为仅当两个区域都是同一个容器的子级时才比较它们的优先级。这意味着负责容器的设备（通常是对总线或内存控制器进行建模）可以使用它们来管理其子区域的交互，而不会对系统的其他部分产生任何副作用。在上面的示例中，D和E的优先级并不重要，因为它们彼此不重叠。是B和C的相对优先级导致D和E出现在C的顶部：D和E的优先级从未与C的优先级进行比较。

### 可见性

当客户操作系统访问地址时，内存核心使用以下规则选择一个内存区域：

- 根区域的所有直接子区域均按优先级降序与地址匹配
  - 如果地址位于区域偏移量/大小之外，则丢弃该子区域。
  - 如果子区域是叶子（RAM或MMIO），则搜索会终止，并返回该叶子区域
  - 如果子区域是容器，则在子区域内使用相同的算法（在通过子区域偏移量调整地址之后）
  - 如果子区域是别名，则在别名目标处继续搜索（在通过子区域偏移量和别名偏移量调整地址之后）
  - 如果在容器或别名子区域内进行的递归搜索未找到匹配项（由于容器在其地址范围的覆盖范围内出现“空洞”），则如果这是一个具有自己的MMIO或RAM支持的容器，搜索将终止，返回容器本身。否则，我们将按优先级顺序继续下一个分区
- 如果所有子区域均与地址不匹配，则搜索将终止，且找不到匹配项

### 内存映射示例

```c
system_memory: container@0-2^48-1
 |
 +---- lomem: alias@0-0xdfffffff ---> #ram (0-0xdfffffff)
 |
 +---- himem: alias@0x100000000-0x11fffffff ---> #ram (0xe0000000-0xffffffff)
 |
 +---- vga-window: alias@0xa0000-0xbffff ---> #pci (0xa0000-0xbffff)
 |      (prio 1)优先级1
 |
 +---- pci-hole: alias@0xe0000000-0xffffffff ---> #pci (0xe0000000-0xffffffff)

pci (0-2^32-1)
 |
 +--- vga-area: container@0xa0000-0xbffff
 |      |
 |      +--- alias@0x00000-0x7fff  ---> #vram (0x010000-0x017fff)
 |      |
 |      +--- alias@0x08000-0xffff  ---> #vram (0x020000-0x027fff)
 |
 +---- vram: ram@0xe1000000-0xe1ffffff
 |
 +---- vga-mmio: mmio@0xe2000000-0xe200ffff

ram: ram@0x00000000-0xffffffff
```

这是一个（简化的）PC内存映射。 4GB RAM块通过两个别名映射到系统地址空间：`lomem`是前3.5GB的1：1映射； ` himem`将最后的0.5GB映射到地址4GB。 这样就留有0.5GB的空间用于所谓的PCI hole，该hole允许在具有4GB内存的系统中存在32位PCI总线。

内存控制器将640K-768K范围内的地址转移到PCI地址空间。 这是使用“ vga-window”别名建模的，该别名以较高的优先级进行映射，因此会掩盖相同地址的RAM。 可以通过对内存控制器进行编程来删除vga窗口。 这是通过删除别名并在下面公开RAM来建模的。

pci地址空间不是系统地址空间的直接子级，因为我们只希望它的一部分可见（我们使用别名来实现）。 它有两个子区域：vga-area对传统的vga窗口进行建模，并由指向帧缓冲区两个部分的两个32K内存库占用。 此外，该vram被映射为地址为e1000000的BAR，并在其后映射了另一个包含MMIO寄存器的BAR。

请注意，如果guest虚拟机将BAR映射到PCI孔之外，则它将不可见，因为pci-hole别名将其限制为0.5GB范围。

### MMIO操作

MMIO区域提供`-> read（）`和`-> write（）`回调；另外，可以提供各种约束来控制如何调用这些回调：

- `.valid.min_access_size`，`.valid.max_access_size`定义设备接受的访问大小（以字节为单位）；超出此范围的访问将具有特定于设备和总线的行为（忽略或机器检查）
- `.valid.unaligned`指定**正在建模的设备**支持未对齐的访问；如果为false，则未对齐的访问将调用相应的总线或CPU特定的行为。
- `.impl.min_access_size`，`.impl.max_access_size`定义**实现**支持的访问大小（以字节为单位）；其他访问大小将使用可用的大小进行模拟。例如，如果`.impl.max_access_size = 1`，则将使用四个1字节写入来模拟4字节写入。
- `.impl.unaligned`指定**实现**支持未对齐的访问；如果为false，则将由两个对齐的访问模拟未对齐的访问。
- `.old_mmio`简化了以前使用`cpu_register_io_memory（）`的代码的移植。不应在新代码中使用它。

### 内存基础

#### 页表

页表负责将虚拟地址（virtual address）转换为物理内存地址（physical），在转换时，先从CR3寄存器中读取页表在内存中地址，通过页号加上对应页表项得到对应页的物理地址，再通过偏移得到物理内存地址。

### 内存寻址过程

QEMU使用MMAP系统调用，在进程的虚拟地址空间中申请连续大小的空间，作为Guest的物理内存。而QEMU作为Host上运行的一个进程，在Guest中模拟的vCPU都是QEMU进程的一个子线程，Guest实际使用的仍是Host上的物理内存，因此对于Guest而言，在内存操作时，内存地址需要经过下面的地址转换

```c
  Guest虚拟内存地址(GVA)
          |
    Guest线性地址 
          |
   Guest物理地址(GPA)
          |             Guest
   ------------------
          |             Host
    Host虚拟地址(HVA)
          |
      Host线性地址
          |
    Host物理地址(HPA)
```

其中GVA到GPA的地址转换由Guest管理，而GPA到HVA的转换由QEMU管理，HVA到HPA的转换由Host操作系统管理。

QEMU使用`AddressSpace`来表示一段内存地址空间，在这个结构体中`MemoryRegion *root`指向MemoryRegion根节点。

在`exec.c`中定义了两个静态变量、以及全局变量。其中`system_memory`作为`address_space_memory`的根节点。

```c
static MemoryRegion *system_memory;
static MemoryRegion *system_io;
AddressSpace address_space_io; 
AddressSpace address_space_memory;
```

使用`MemoryRegion`表示Guest操作系统中一段物理内存。

可以表示RAM、ROM、IOMMU等类型内存，根据MemoryRegionOps不同。对于不同类型的内存，使用对应的`memory_region_init_*`函数来构建。

其中系统内存通过：

```c
pc_memory_init
 memory_region_allocate_system_memory(ram, NULL, "pc.ram",
                                         machine->ram_size);
  memory_region_init_ram_nomigrate(mr, owner, name, ram_size, &error_fatal) {
    memory_region_init(mr, owner, name, size);
    mr->ram = true;
    mr->terminates = true;
    mr->destructor = memory_region_destructor_ram;
    mr->ram_block = qemu_ram_alloc(size, mr, errp);
    mr->dirty_log_mask = tcg_enabled() ? (1 << DIRTY_MEMORY_CODE) : 0;
  }
```

而`MemoryRegion`主要是描述逻辑层面的内存区域，`RAMBlock`记录实际分配的内存地址。

```c
struct RAMBlock {
    uint8_t *host;
    ram_addr_t offset;
    ....
};
```

host表示在Host对应的虚拟地址，offset表示Guest对应的虚拟地址。在`exec.c`定义了一个RAMList类型的RAMBlock链表

![](https://abelsu7.top/2019/07/07/kvm-memory-virtualization/ram_list.jpg)

```c
cpu_physical_memory_map
	address_space_map 将一个guest物理内存区域映射到host虚拟地址
```

### 内存加载和写入api

QEMU内部有许多函数用于加载和写入指定内存地址。这些函数传入的地址为host虚拟内存地址。

函数遵循下面的模板：

```c
load: ld{type}{sign}{size}_{endian}_p(ptr)
store: st{type}{size}_{endian}_p(ptr, val)
```

```
type
```

- (empty) : 整形访问
- `f` :浮点数访问

```
sign
```

- (empty) : 32或64位大小
- `u` : 无符号
- `s` : 有符号

```
size
```

- `b` : 8 bits
- `w` : 16 bits
- `l` : 32 bits
- `q` : 64 bits

```
endian
```

- `he` : host endian
- `be` : 大端
- `le` :小端

虚拟内存技术解决了程序模块化以及程序大小大于内存的问题，让每个程序都有自己的内存地址空间，地址空间被分割成多个以页为单位的块。每一页包含的是连续的内存地址，页同时被映射到物理内存，使用虚拟内存的操作系统使用的地址为虚拟地址，在没有虚拟内存的计算机上，系统直接将虚拟内存地址送到内存总线上，读写操作使用同样的物理内存内容。而使用虚拟内存系统的情况下，虚拟地址是被送到内存管理单元（MMU），MMU把虚拟地址映射被物理内存地址。

如图MMU的位置与功能

而在系统模拟中QEMU中默认使用softmmu也就是使用软件来模拟内存管理功能。在这个模式中每次内存访问都进行guest虚拟地址到物理内存地址的转换。同时QEMU使用TLB来缓存地址转换结果，加速地址转换效率。为了避免MMU映射变化导致的TB链无效的情况，QEMU会对所有地址转换结果进行物理缓存。

有两个内存写入访问分别是tcg中的tcg_out_qemu_st(包含tcg_out_st、tcg_out_ld）这些函数输出TCG到host的转换

```c
/* 
执行对TLB的加载，addrlo、addrhi分别表示地址的高位和低位，MEM_INDEX表示内存上下文，S_bits表示log2计算后的大小，which表示CPUTLBEntry结构中slot的偏移，应该是addr_read或addr_write的偏移。LABEL_PTRS填充有1个（32位地址）或2个（64位地址）前向跳转到TLB未命中情况的位移位置。
第二个参数寄存器加载地址的低位部分。在TLB命中的情况下，它已经按照TLB的指示进行了调整，因此是主机host地址。 在TLB未命中的情况下，它将继续保留guest地址。

*/
static inline void tcg_out_tlb_load(TCGContext *s, TCGReg addrlo, TCGReg addrhi,
                                    int mem_index, TCGMemOp opc,
                                    tcg_insn_unit **label_ptr, int which)
{
    const TCGReg r0 = TCG_REG_L0;
    const TCGReg r1 = TCG_REG_L1;
    TCGType ttype = TCG_TYPE_I32;
    TCGType tlbtype = TCG_TYPE_I32;
    int trexw = 0, hrexw = 0, tlbrexw = 0;
    unsigned a_bits = get_alignment_bits(opc);
    unsigned s_bits = opc & MO_SIZE;
    unsigned a_mask = (1 << a_bits) - 1;
    unsigned s_mask = (1 << s_bits) - 1;
    target_ulong tlb_mask;

    if (TCG_TARGET_REG_BITS == 64) {
        if (TARGET_LONG_BITS == 64) {
            ttype = TCG_TYPE_I64;
            trexw = P_REXW;
        }
        if (TCG_TYPE_PTR == TCG_TYPE_I64) {
            hrexw = P_REXW;
            if (TARGET_PAGE_BITS + CPU_TLB_BITS > 32) {
                tlbtype = TCG_TYPE_I64;
                tlbrexw = P_REXW;
            }
        }
    }

    tcg_out_mov(s, tlbtype, r0, addrlo);
    /* If the required alignment is at least as large as the access, simply
       copy the address and mask.  For lesser alignments, check that we don't
       cross pages for the complete access.  */
    if (a_bits >= s_bits) {
        tcg_out_mov(s, ttype, r1, addrlo);
    } else {
        tcg_out_modrm_offset(s, OPC_LEA + trexw, r1, addrlo, s_mask - a_mask);
    }
    tlb_mask = (target_ulong)TARGET_PAGE_MASK | a_mask;

    tcg_out_shifti(s, SHIFT_SHR + tlbrexw, r0,
                   TARGET_PAGE_BITS - CPU_TLB_ENTRY_BITS);

    tgen_arithi(s, ARITH_AND + trexw, r1, tlb_mask, 0);
    tgen_arithi(s, ARITH_AND + tlbrexw, r0,
                (CPU_TLB_SIZE - 1) << CPU_TLB_ENTRY_BITS, 0);

    tcg_out_modrm_sib_offset(s, OPC_LEA + hrexw, r0, TCG_AREG0, r0, 0,
                             offsetof(CPUArchState, tlb_table[mem_index][0])
                             + which);

    /* cmp 0(r0), r1 */
    tcg_out_modrm_offset(s, OPC_CMP_GvEv + trexw, r1, r0, 0);

    /* Prepare for both the fast path add of the tlb addend, and the slow
       path function argument setup.  There are two cases worth note:
       For 32-bit guest and x86_64 host, MOVL zero-extends the guest address
       before the fastpath ADDQ below.  For 64-bit guest and x32 host, MOVQ
       copies the entire guest address for the slow path, while truncation
       for the 32-bit host happens with the fastpath ADDL below.  */
    tcg_out_mov(s, ttype, r1, addrlo);

    /* jne slow_path */
    tcg_out_opc(s, OPC_JCC_long + JCC_JNE, 0, 0, 0);
    label_ptr[0] = s->code_ptr;
    s->code_ptr += 4;

    if (TARGET_LONG_BITS > TCG_TARGET_REG_BITS) {
        /* cmp 4(r0), addrhi */
        tcg_out_modrm_offset(s, OPC_CMP_GvEv, addrhi, r0, 4);

        /* jne slow_path */
        tcg_out_opc(s, OPC_JCC_long + JCC_JNE, 0, 0, 0);
        label_ptr[1] = s->code_ptr;
        s->code_ptr += 4;
    }

    /* TLB Hit.  */

    /* add addend(r0), r1 */
    tcg_out_modrm_offset(s, OPC_ADD_GvEv + hrexw, r1, r0,
                         offsetof(CPUTLBEntry, addend) - which);
}
```



### QEMU翻译过程

QEMU使用Just-In-Time编译Guest客户操作系统的代码。关键是将Guest代码转换为中间语言代码表示，这里的中间语言是Tiny Code Generator（TCG），然后再将TCG转换为QEMU所运行的宿主机器码。翻译过程以代码块为单位，每个代码块以分支跳转指令为边界，比如x86汇编中的call、jmp、ret等。

下面表示代码块翻译成TCG后再翻译成宿主可执行二进制的例子：

图表：左边是mips、中间tcg、右边x86

TB会被链接成链表，当每个TB被执行完后，控制权将会回到QEMU

在target/i386/translate.c中翻译target也就是客户操作系统代码到TCG

## Ubuntu下安装MIPS编译器

```bash
sudo apt-get update
sudo apt-get install emdebian-archive-keyring
sudo apt-get install linux-libc-dev-mips-cross libc6-mips-cross libc6-dev-mips-cross binutils-mips-linux-gnu gcc-7-mips-linux-gnu g+±7-mips-linux-gnu
```

然后使用`/usr/bin/mips-linux-gnu-gcc-7 test.c -o test -static`编译

运行程序`qemu-mips -d in_asm,op,out_asm -D output.txt test`得到HOST代码、TCG中间代码、Guest代码。

## 名词解释

guest：guest operating system 客户操作系统

host：host operating system 宿主操作系统


## 参考

qemu老版本的流程图 http://v4kst1z.top/2019/01/09/QEMU-shadowstack/

qemu设备模拟原理 https://www.qemu.org/2018/02/09/understanding-qemu-devices/

对QEMU二进制转换讲解 https://coscup.org/2018/en/programs/how-qemu-works/

对应的ppt https://www.slideshare.net/ChenWei15/from-binary-to-binary-how-qemu-works

airbus 基于qemu与afl的模糊测试工具GUSTAVE https://airbus-seclab.github.io/GUSTAVE_thcon/GUSTAVE_thcon.pdf

Evaluating Techniques for Full System Memory Tracing https://os.itec.kit.edu/downloads/ba_2017_Thomas-Schmidt_Techniques-for-full-system-memory-tracing.pdf

QEMU for Dynamic Memory Analysis of Security Sensitive Software https://www.researchgate.net/publication/334258953_QEMU_for_Dynamic_Memory_Analysis_of_Security_Sensitive_Software

MIPS指令集参考 https://www.anquanke.com/post/id/162992#h3-2

qemu tcg原理 http://www.hellogcc.org/?p=46

提升afl qemu mode速度 https://andreafioraldi.github.io/articles/2019/07/20/aflpp-qemu-compcov.html

https://abiondo.me/2018/09/21/improving-afl-qemu-mode/