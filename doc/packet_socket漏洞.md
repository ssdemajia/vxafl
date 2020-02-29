https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
在linux源码目录下输入gdb vmlinux
break ip_do_fragment
continue
然后在虚拟机需要ping 192.168.1.1 -s 3000
这个函数主要是用于IP数据报太大了，无法在一片中发送，需要将其切分为更小的片段（每一个大小相当于IP头部加原来数据的一部分），使其符合设备帧大小，然后将这些帧放入队列中等待发送



	sk_buff {
	    struct {
	        struct sk_buff *next;  链表中下一个buffer
	        struct sk_buff *prev;  链表中上一个buffer
	        union {
				struct net_device	*dev;  到达/离开所用的设备
				unsigned long		dev_scratch;
				int			ip_defrag_offset;
			};
	    }
	    struct sock *sk;     归属的socket
	    ktime_t tstamp;      到达/离开的时间
	    char cb[48] __aligned(8);   控制块，存放私有信息
	    union {
			struct {
				unsigned long	_skb_refdst;  目的条目
				void		(*destructor)(struct sk_buff *skb);
			};
			struct list_head	tcp_tsorted_anchor;
		};
	    unsigned int	len,  实际数据长度，包括各个片段大小
					    data_len; 数据长度，当前片段的大小
		__u16			mac_len,  链路层大小
					    hdr_len;  cloned skb的可写头部长度
	    __u16			queue_mapping;
	    	__u8			__cloned_offset[0];
		__u8			cloned:1,  头部是否被克隆
					    nohdr:1,   负载引用
					    fclone:2,  skbuff的clone状态
					    peeked:1,  这个数据包已经准备好了
					    head_frag:1,
					    xmit_more:1,
					    pfmemalloc:1;
	    __u32			headers_start[0];
	    __u8			__pkt_type_offset[0];
		__u8			pkt_type:3;  Packet类型
		__u8			ignore_df:1;  允许本地分段 allow local fragmentation
		__u8			nf_trace:1;   netfiler包追踪标志位
		__u8			ip_summed:2;  驱动提供的IP校验和
		__u8			ooo_okay:1;
	    __u8			l4_hash:1;
	    __u8			sw_hash:1;
	    __u8			wifi_acked_valid:1;
	    __u8			wifi_acked:1;
	    __u8			no_fcs:1;
	
	    __u8			encapsulation:1;
	    __u8			encap_hdr_csum:1;
	    __u8			csum_valid:1;
	
	    __u8			csum_complete_sw:1;
	    __u8			csum_level:2;
	    __u8			csum_not_inet:1;
	    __u8			dst_pending_confirm:1;
	
	    __u8			ipvs_property:1;
	
	    __u8			inner_protocol_type:1;
	    __u8			remcsum_offload:1;
	
	    union {
	        __wsum		csum;  校验和
	        struct {
	            __u16	csum_start;  从skb->head开始的偏移，从这里开始进行校验和计算
	            __u16	csum_offset; 从csum_start开始计算的偏移，在这里存放checksum
	        };
	    };
	    __u32			priority;  数据包排队优先级
	    int			    skb_iif;
	    __u32			hash;
	    __be16			vlan_proto;
	    __u16			vlan_tci;
	
	    union {
	        __u32		mark;
	        __u32		reserved_tailroom;
	    };
	    union {
	        __be16		inner_protocol;  Protocol (encapsulation)
	        __u8		inner_ipproto;
	    };
	
	    __u16			inner_transport_header; 传输层头部
	    __u16			inner_network_header;  网络层头部
	    __u16			inner_mac_header;  链路层头部
	
	    __be16			protocol;  驱动提供的数据包协议
	    __u16			transport_header;
	    __u16			network_header;
	    __u16			mac_header;
	
	    /* private: */
	    __u32			headers_end[0];
	    sk_buff_data_t		tail;  尾部指针
	    sk_buff_data_t		end;
	    unsigned char		*head,  buffer头部指针
	                *data;    数据头部指针
	    unsigned int		truesize;  buffer大小
	    refcount_t		users;   用户数量
	}

可以确定data的位置
sk_buff的图示https://www.cnblogs.com/qq78292959/archive/2012/06/06/2538358.html

在ip_finish_output中会因为数据包大于链路mtu，进入ip_fragment分片，如果ip中支持分片（没有设置don't fragment标志位），那么进入ip_do_fragment进行分片

linux源码阅读vscode配置，https://jekton.github.io/2018/05/11/how-to-read-android-source-code/

在include/linux/skbuff.h中定义了对sk_buff结构的操作
net/core/skbuff.c定义的skb_copy_bits将字节从skbuffer拷贝到内核buffer



https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
(CVE-2017-7308)测试
需要开启packet：CONFIG_PACKET=y
遇到内核编译出错https://blog.csdn.net/jasonlee_lijiaqi/article/details/84651138
在Makefile里的KBUILD_CFLAGS尾部添加-fno-pie
编译时出错
/home/ubuntu/linux-4.10.4/kernel/time/timekeeping.c:2088: undefined reference to `____ilog2_NaN'
需要打patch https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/diff/?id=474c90156c8dcc2fa815e6716cc9394d7930cb9c
将补丁信息保存分别为a.diff, b.diff分别使用patch a.diff 和patch b.diff然后填入两个文件路径


这个bug由syzkaller发现，它由syzkaller一个覆盖率驱动的系统调用模糊测试工具和KASAN，一个动态内存错误检测器组成。Syzkaller生成随机的程序，这些程序由随机顺序、随机参数的系统调用组成，每个系统调用使用模板https://github.com/google/syzkaller/tree/master/sys描述参数如何生成，模糊器在虚拟机中执行这些程序，然后通过kcov来收集代码覆盖率。Syzkaller使用这些代码覆盖率信息来维持一些程序集合
，每个程序能够包含不同的代码执行路径。每当有一个新的程序触发了一条新的路径时，Syzkaller会将其添加到程序集合中，在每次测试前，syzkaller会对某些程序进行变异（如何获得系统调用输入，输入需要变异么？）
{syzkaller使用它自己的声明式语言来描述系统调用模板，docs目录下的syscall_descriptions.md中可以找到相关的说明。这些系统调用模板被翻译成syzkaller使用的代码需要经过两个步骤。第一步是使用syz-extract从linux源代码中提取符号常量的值，结果被存储在.const文件中，例如/sys/linux/tty.txt被转换为sys/linux/tty_amd64.const。第二步是根据系统调用模板和第一步中生成的const文件使用syz-sysgen生成syzkaller用的go代码。可以在/sys/linux/gen/amd64.go和/executor/syscalls.h中看到结果。最后，重新编译生成带有相应规则的syzkaller二进制可执行文件。}使用Syzkaller&QEMU捕捉内核堆溢出Demo https://www.jianshu.com/p/790b733f80a2

packetsocket manul http://man7.org/linux/man-pages/man7/packet.7.html
首先定义一个使用socket(AF_PACKET, flags, proto)来创建Packet socket，Packet socket用于在设备驱动层（TCPIP中的链路层）发送和接收raw packet，当protocol被设置为htons(ETH_P_ALL)时，所有的协议都会被传送到这个packet类型socket。
然后使用setsockopt配置packet socket。PACKET_RX_RING会创建一个内存映射的ring buffer，用于异步报文接收，packet socket会在应用的地址空间保留一个连续的区域，将其布置为packet数组的槽，然后将packet拷贝到这些槽中。在其中的每个packet都包含tpacket_auxdata结构。
## Ring Buffer
为了在packet 发送和接收数据包，packet socket允许使用PACKET_RX_RING来创建内核空间与用户空间之间的ring buffer。In the other hand PACKET_MMAP is very efficient. PACKET_MMAP provides a size 
configurable circular buffer mapped in user space that can be used to either
send or receive packets. This way reading packets just needs to wait for them,
most of the time there is no need to issue a single system call.
当前的提到的bug影响TPACKET_V3版本的ring buffer，一个ring buffer是一块用于存放数据报文的内存区域，每个packet被保存在单独的帧中，帧被分组到blocks块中。TPACKET_V3 ring buffer 帧大小没有固定，可以是随意的值，只要帧能够放进块中。
使用PACKET_RX_RING socket选项来创建一个TPACKET_V3 ring buffer，用户程序必须提供关于ring buffer额外的参数。这些参数通过setsockopt传入，传入的是一个tpacket_req3结构体指针。
```
struct tpacket_req3 {
	unsigned int	tp_block_size;	/* Minimal size of contiguous block */
	unsigned int	tp_block_nr;	/* Number of blocks */
	unsigned int	tp_frame_size;	/* Size of frame */
	unsigned int	tp_frame_nr;	/* Total number of frames */
	unsigned int	tp_retire_blk_tov; /* timeout in msecs */
	unsigned int	tp_sizeof_priv; /* offset to private data area */
	unsigned int	tp_feature_req_word;
};
```
1. tp_block_size - 每个块大小，the size of each block.
2. tp_block_nr - 块数量，the number of blocks.
3. tp_frame_size - 每个帧大小，the size of each frame, ignored for TPACKET_V3.
4. tp_frame_nr - 帧数量the number of frames, ignored for TPACKET_V3.
5. tp_retire_blk_tov -当一个块超时后即使没有完全填充也将退出，timeout after which a block is retired, even if it’s not fully filled with data (see below).
6. tp_sizeof_priv - 每个块的私有区域大小，这个区域用于用于储存与每个块关联的任意信息，the size of per-block private area. This area can be used by a user to store arbitrary information associated with each block.
7. tp_feature_req_word - 标志位，a set of flags (actually just one at the moment), which allows to enable some additional functionality.

每个块有一个相关联的header，header存放在block内存区域的起始处。这个block header的结构体叫`tpacket_block_desc`,里面包含一个block_status的字段，用于指示当前block用于kernel还是user。常见的工作流是，kernel存放packet到block中，直到block满，然后设置block_status为TP_STATUS_USER。用户从块中读取数据时，然后将block_status设置为TP_STATUS_KERNEL来将其释放会内核。
```
struct tpacket_hdr_v1 {
	__u32	block_status;
	__u32	num_pkts;
	__u32	offset_to_first_pkt;

	/* Number of valid bytes (including padding)
	 * blk_len <= tp_block_size
	 */
	__u32	blk_len;

	/*
	 * Quite a few uses of sequence number:
	 * 1. Make sure cache flush etc worked.
	 *    Well, one can argue - why not use the increasing ts below?
	 *    But look at 2. below first.
	 * 2. When you pass around blocks to other user space decoders,
	 *    you can see which blk[s] is[are] outstanding etc.
	 * 3. Validate kernel code.
	 */
	__aligned_u64	seq_num;

	/*
	 * ts_last_pkt:
	 *
	 * Case 1.	Block has 'N'(N >=1) packets and TMO'd(timed out)
	 *		ts_last_pkt == 'time-stamp of last packet' and NOT the
	 *		time when the timer fired and the block was closed.
	 *		By providing the ts of the last packet we can absolutely
	 *		guarantee that time-stamp wise, the first packet in the
	 *		next block will never precede the last packet of the
	 *		previous block.
	 * Case 2.	Block has zero packets and TMO'd
	 *		ts_last_pkt = time when the timer fired and the block
	 *		was closed.
	 * Case 3.	Block has 'N' packets and NO TMO.
	 *		ts_last_pkt = time-stamp of the last pkt in the block.
	 *
	 * ts_first_pkt:
	 *		Is always the time-stamp when the block was opened.
	 *		Case a)	ZERO packets
	 *			No packets to deal with but atleast you know the
	 *			time-interval of this block.
	 *		Case b) Non-zero packets
	 *			Use the ts of the first packet in the block.
	 *
	 */
	struct tpacket_bd_ts	ts_first_pkt, ts_last_pkt;
};

union tpacket_bd_header_u {
	struct tpacket_hdr_v1 bh1;
};

struct tpacket_block_desc {
	__u32 version;
	__u32 offset_to_priv;
	union tpacket_bd_header_u hdr;
};
```
在每个帧都包含一个header，叫`tpacket3_hdr`:
```
struct tpacket3_hdr {
	__u32		tp_next_offset;
	__u32		tp_sec;
	__u32		tp_nsec;
	__u32		tp_snaplen;
	__u32		tp_len;
	__u32		tp_status;
	__u16		tp_mac;
	__u16		tp_net;
	/* pkt_hdr variants */
	union {
		struct tpacket_hdr_variant1 hv1;
	};
	__u8		tp_padding[8];
};

```
当一个block充满了数据后，它会被关闭然后从用户空间释放到内核。因为用户希望尽快的看到数据包，因此即使没有完全填充数据，内核也可以是否数据块。这种功能需要设置tp_retire_blk_tov参数，作为计数器。
![每个block](https://2.bp.blogspot.com/-XS_7TYA1mkY/WRM9nzyhE9I/AAAAAAAABq0/Tk3ZJGs_n1ULyrZiWuQ901UQz-N7K86EwCEw/s640/ak02.png)
## AF_PACKET类型socket实现
一旦packet socker被创建，相关联的数据结构packet_sock被内核分配
```c
struct packet_sock {
	/* struct sock has to be the first member of packet_sock */
	struct sock		sk;
	struct packet_fanout	*fanout;
	union  tpacket_stats_u	stats;
	struct packet_ring_buffer	rx_ring;
	struct packet_ring_buffer	tx_ring;
	int			copy_thresh;
	spinlock_t		bind_lock;
	struct mutex		pg_vec_lock;
	unsigned int		running:1,	/* prot_hook is attached*/
				auxdata:1,
				origdev:1,
				has_vnet_hdr:1;
	int			pressure;
	int			ifindex;	/* bound device		*/
	__be16			num;
	struct packet_rollover	*rollover;
	struct packet_mclist	*mclist;
	atomic_t		mapped;
	enum tpacket_versions	tp_version; // ring buffer版本
	unsigned int		tp_hdrlen;
	unsigned int		tp_reserve;
	unsigned int		tp_loss:1;
	unsigned int		tp_tx_has_off:1;
	unsigned int		tp_tstamp;
	struct net_device __rcu	*cached_dev;
	int			(*xmit)(struct sk_buff *skb);
	struct packet_type	prot_hook ____cacheline_aligned_in_smp;
};
```
`tp_version`字段指示ring buffer版本，我们使用setsockopt来设置。rx_ring、tx_ring分别是接收发送ring buffer，这两个字段是`packet_ring_buffer`结构体:
```c
struct packet_ring_buffer {
	struct pgv		*pg_vec; 

	unsigned int		head;
	unsigned int		frames_per_block;
	unsigned int		frame_size;
	unsigned int		frame_max;

	unsigned int		pg_vec_order;
	unsigned int		pg_vec_pages;
	unsigned int		pg_vec_len;

	unsigned int __percpu	*pending_refcnt;

	struct tpacket_kbdq_core	prb_bdqc;
};
struct pgv {
    char *buffer;
};
```
pg_vec字段是一个指向结构提pgv数组的指针。
![](https://2.bp.blogspot.com/-ksSoY6KUN5M/WRM9n6mLVWI/AAAAAAAABq8/ZIzN2X3OyL8pvS-e-VF5zRj4eXAzjESygCEw/s640/ak03.png)
```c
/* kbdq - kernel block descriptor queue */
struct tpacket_kbdq_core {
	struct pgv	*pkbdq;
	unsigned int	feature_req_word;
	unsigned int	hdrlen;
	unsigned char	reset_pending_on_curr_blk;
	unsigned char   delete_blk_timer;
	unsigned short	kactive_blk_num;
	unsigned short	blk_sizeof_priv;

	/* last_kactive_blk_num:
	 * trick to see if user-space has caught up
	 * in order to avoid refreshing timer when every single pkt arrives.
	 */
	unsigned short	last_kactive_blk_num;

	char		*pkblk_start;
	char		*pkblk_end;
	int		kblk_size;
	unsigned int	max_frame_len;
	unsigned int	knum_blocks;
	uint64_t	knxt_seq_num;
	char		*prev;
	char		*nxt_offset;
	struct sk_buff	*skb;

	atomic_t	blk_fill_in_prog;

	/* Default is set to 8ms */
#define DEFAULT_PRB_RETIRE_TOV	(8)

	unsigned short  retire_blk_tov;
	unsigned short  version;
	unsigned long	tov_in_jiffies;

	/* timer to retire an outstanding block */
	struct timer_list retire_blk_timer;
};
```
blk_sizeof_priv字段表示每个block中私有数据大小，
nxt_offset指向当前活动block到下一个数据包的偏移，
retire_blk_timer字段为`timer_list`类型，表示当前block的定时器。

## RingBuffer设置
内核使用packet_setsockopt()函数来处理packet sockets的setsockopt。PACKET_VERSION直接使用`po->tp_version = val;`。

PACKET_RX_RING选项，如果ringbuffer版本为TPACKET_V3那么使用rpacket_req3结构体，内部使用`packet_set_ring`函数，这个函数最为重要：

首先进行边界检查：
```c
err = -EINVAL;
if (unlikely((int)req->tp_block_size <= 0))
	goto out;
if (unlikely(!PAGE_ALIGNED(req->tp_block_size)))
	goto out;
if (po->tp_version >= TPACKET_V3 &&
	(int)(req->tp_block_size -
		BLK_PLUS_PRIV(req_u->req3.tp_sizeof_priv)) <= 0)
	goto out;
if (unlikely(req->tp_frame_size < po->tp_hdrlen +
			po->tp_reserve))
	goto out;
if (unlikely(req->tp_frame_size & (TPACKET_ALIGNMENT - 1)))
	goto out;

rb->frames_per_block = req->tp_block_size / req->tp_frame_size;
if (unlikely(rb->frames_per_block == 0))
	goto out;
if (unlikely((rb->frames_per_block * req->tp_block_nr) !=
			req->tp_frame_nr))
	goto out;
```
然后分配ringbuffer blocks， alloc_pg_vec使用kernel的页分配器
```c
err = -ENOMEM;
order = get_order(req->tp_block_size);
pg_vec = alloc_pg_vec(req, order);
if (unlikely(!pg_vec))
	goto out;
```
然后packet_set_ring调用`init_prb_bdqc`来执行而外的TPACKET_V3类型接收ringbuffer设置
```c
switch (po->tp_version) {
case TPACKET_V3:
/* Transmit path is not supported. We checked
	* it above but just being paranoid
	*/
	if (!tx_ring)
		init_prb_bdqc(po, rb, pg_vec, req_u);
	break;
default:
	break;
}
```
init_prb_bdqc会初始化结构体packet_ring_buffer中的prb_bdqc字段，然后使用`prb_open_block`打开第一个block
```c
static void init_prb_bdqc(struct packet_sock *po,
			struct packet_ring_buffer *rb,
			struct pgv *pg_vec,
			union tpacket_req_u *req_u)
{
	struct tpacket_kbdq_core *p1 = GET_PBDQC_FROM_RB(rb);
	struct tpacket_block_desc *pbd;

	memset(p1, 0x0, sizeof(*p1));

	p1->knxt_seq_num = 1;
	p1->pkbdq = pg_vec;
	pbd = (struct tpacket_block_desc *)pg_vec[0].buffer;
	p1->pkblk_start	= pg_vec[0].buffer;
    ...
	p1->blk_sizeof_priv = req_u->req3.tp_sizeof_priv;

	p1->max_frame_len = p1->kblk_size - BLK_PLUS_PRIV(p1->blk_sizeof_priv);
	prb_init_ft_ops(p1, req_u);
	prb_setup_retire_blk_timer(po);
	prb_open_block(p1, pbd);
}
```
在prb_open_block函数中将tpacket_kbdq_core->nxt_offset指向正确的位置（在每个块私有区域后）
```c
static void prb_open_block(struct tpacket_kbdq_core *pkc1,
	struct tpacket_block_desc *pbd1)
{
	....
	pkc1->pkblk_start = (char *)pbd1;
	pkc1->nxt_offset = pkc1->pkblk_start + BLK_PLUS_PRIV(pkc1->blk_sizeof_priv);
    ...
}
```

## Packet接收
每当一个新数据包接收，内核会保存它到ring buffer中。关键函数是`__packet_lookup_frame_in_block()`
```c
static void *__packet_lookup_frame_in_block(struct packet_sock *po,
					    struct sk_buff *skb,
						int status,
					    unsigned int len
					    )
{
	struct tpacket_kbdq_core *pkc;
	struct tpacket_block_desc *pbd;
	char *curr, *end;

	pkc = GET_PBDQC_FROM_RB(&po->rx_ring);
	pbd = GET_CURR_PBLOCK_DESC_FROM_CORE(pkc);
	...
	curr = pkc->nxt_offset;
	pkc->skb = skb;
	end = (char *)pbd + pkc->kblk_size;

	/* 1.第一次尝试当前block是否有空间存放 */
	if (curr+TOTAL_PKT_LEN_INCL_ALIGN(len) < end) {
		prb_fill_curr_block(curr, pkc, pbd, len);
		return (void *)curr;
	}

	/* 2.如果当前block没有空间，那么关闭它 */
	prb_retire_current_block(pkc, po, 0);

	/* 3.保存到下一个块中 */
	curr = (char *)prb_dispatch_next_block(pkc, po);
	if (curr) {
		pbd = GET_CURR_PBLOCK_DESC_FROM_CORE(pkc);
		prb_fill_curr_block(curr, pkc, pbd, len);
		return (void *)curr;
	}

	/*
	 * No free blocks are available.user_space hasn't caught up yet.
	 * Queue was just frozen and now this packet will get dropped.
	 */
	return NULL;
}
```
在packet_set_ring函数中有一个条件，需要block的大小必须大于block header(tpacket_block_desc)加上private data，但是这个条件可以被绕过
```c
if (po->tp_version >= TPACKET_V3 &&
	(int)(req->tp_block_size -
		BLK_PLUS_PRIV(req_u->req3.tp_sizeof_priv)) <= 0)
	goto out;
```
因为结果是将其转为int类型，那么就会出现小数减去大数后，还是正数
A = req->tp_block_size = 4096 = 0x1000
B = req_u->req3.tp_sizeof_priv = (1 << 31) + 4096 = 0x80001000
BLK_PLUS_PRIV(B) = (1 << 31) + 4096 + 48 = 0x80001030
A - BLK_PLUS_PRIV(B) = 0x1000 - 0x80001030 = 0x7fffffd0
(int)0x7fffffd0 = 0x7fffffd0 > 0

之后req_u中的tp_sizeof_priv会被拷贝到ringbuffer中的tpacket_kbdq_core*p1中
```c
p1->blk_sizeof_priv = req_u->req3.tp_sizeof_priv;
```
而p1->blk_sizeof_priv是一个unsigned short类型

## 使用序列
之后tp_sizeof_priv还被使用在计算ingbuffer中的tpacket_kbdq_core*p1的max_frame_len，这个max_frame_len字段被用在校验帧大小不能超过它，使用在tpacket_rcv函数2213行，如果我们通过修改tp_sizeof_priv使得这个字段变得非常大，那么就能允许将skb拷贝到边界外，kernel heap out of bounds write。

第二个使用到tp_sizeof_priv的地方就是每次打开一个新的block时都会调用prb_open_block（）这个函数会修改下一个下一个新的packet时存放的地址（也就是nxt_offset。
```c
pkc1->pkblk_start = (char *)pbd1;
pkc1->nxt_offset = pkc1->pkblk_start + BLK_PLUS_PRIV(pkc1->blk_sizeof_priv);
```
这样我们修改blk_sizeof_priv这个unsigned short字段来控制写入内核堆的最大64Kb的范围。

## Exploitation
需要关闭smap（不允许内核访问用户空间数据）、smep（不运行内核执行用户空间代码）
漏洞利用的思想是使用堆越界写入来覆盖已经溢出的block相邻内存中的函数指针。为了这个目的，我们必须解释堆的形状，使得需要被触发的函数指针就在ringbuffer的block后面。
ring buffer使用packet_setsockopt/packet_set_ring/alloc_pg_vec来创建，使用的是kernel_page_allocation，每个分配都是2^n个page的连续内存地址，当2^n大小的内存所指向的freelist是empty时，那么就会从更高层分一块，然后切半，这样两个内存是连续的。

packet_sock使用kmalloc函数（slab allocator）来分配内存，slab分配器主要用于小于1页大小的内存分配。它首先分配了一个大块内存，然后将其且分为小的对象，相当于对象cache，之后分配内存n，会将n向上去为2的幂

CONFIG_USER_NS=y

