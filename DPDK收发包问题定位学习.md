# DPDK收发包问题定位学习

```javascript
###网卡收包：
	rte_eth_rx_burst 应用层
			(*dev->rx_pkt_burst)(dev->data->rx_queues[queue_id],rx_pkts,nb_pkts);
			|
	nbl_sf50_recv_pkts

###网卡发包：
		rte_eth_tx_burst
        	(*dev->tx_pkt_burst)(dev->data->tx_queues[queue_id], tx_pkts, nb_pkts);
				|
        nbl_sf50_xmit_pkts
```

# 编译命令

```javascript
工具链GCC编译DPDK：
    sudo meson build
    cd build
    sudo ninja -j8
    sudo ninja install
    编译带调试信息的testpmd
    	在 DPDK 根目录下，执行
        meson build -Dbuildtype=debug
		meson configure -Dexamples=test-pmd
		ninja -C build 
        ninja -C build install
        ldconfig
    `testpmd启动`
        启动前把需要用的网口手动绑定到 vfio-pci 驱动，红色字体为网卡 pci 地址：
        modprobe vfio-pci
		lsmod | grep vfio
        /usr/bin/chmod a+x /dev/vfio
		/usr/bin/chmod 0666 /dev/vfio/*
		dpdk-devbind.py -b vfio-pci `61:00.0`
		启动命令:
		cd  build/app
		./dpdk-testpmd  -l  1-4  -n  4  --  -i  --nb-cores=2
        
工具链GCC编译内核：
	cd nm-kernel-driver/drivers/net/ethernet/nbl/
    [sudo apt install linux-headers-5.13.0-39-generic]
    make -C /usr/src/linux-headers-`uname -r` M=$PWD modules
    
工具链GCC编译spdk：
	release版本：
	./configure --with-iscsi-initiator --without-isal
	make
	debug版本：
	./configure --with-iscsi-initiator --without-isal --enable-debug
	make

`OVS-DPDK交叉编译`
ARM64-debug
sudo dpkg --add-architecture arm64
sudo apt install -y libssl-dev:arm64 openssl:arm64 build-essential  python3-pyelftools libnuma-dev libunwind-dev autoconf automake libtool libffi-dev pkg-config libunwind8 crossbuild-essential-arm64
sudo pip3 install meson ninja
git clone -b  bootis-mainline "http://gerrit.dpu.tech/dpdk"
cd dpdk
PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig \
meson aarch64-build --cross-file config/arm/arm64_armv8_linux_gcc \
--prefix /usr \
--includedir /usr/include/aarch64-linux-gnu \
--libdir /usr/lib/aarch64-linux-gnu \
-Dbuildtype=debug
ninja -C aarch64-build
sudo ninja install -C aarch64-build
cd ..
git clone -b bootis-mainline "http://gerrit.dpu.tech/ovs"
cd ovs
./boot.sh
PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig \
CC=aarch64-linux-gnu-gcc \
CXX=aarch64-linux-gnu-g++ \
./configure --host=arm-linux  --with-dpdk=static  \
--prefix=/usr --localstatedir=/var --sysconfdir=/etc \
--with-logdir=/var/log/nebulamatrix/openvswitch \
CFLAGS="-g -Ofast"
make -j40
./package.sh arm64

AMD64-debug
sudo dpkg --add-architecture amd64
sudo apt install -y build-essential  python3-pyelftools libnuma-dev libunwind-dev
sudo apt install -y autoconf automake libtool libffi-dev pkg-config libunwind8
sudo pip3 install meson ninja
git clone -b bootis-mainline "http://gerrit.dpu.tech/dpdk"
cd dpdk
sudo meson build -Dc_args="-mno-avx512f" -Dbuildtype=debug
sudo ninja -C build
sudo ninja install -C build
sudo ldconfig
cd ..
git clone -b bootis-mainline http://gerrit.dpu.tech/ovs
cd ovs
./boot.sh
./configure --with-dpdk=static --prefix=/usr \
--localstatedir=/var --sysconfdir=/etc --with-logdir=/var/log/nebulamatrix/openvswitch \
CFLAGS="-g -Ofast"
make -j40
./package.sh amd64

ARM64-release
sudo dpkg --add-architecture arm64
sudo apt install -y libssl-dev:arm64 openssl:arm64
sudo apt install -y build-essential  python3-pyelftools libnuma-dev libunwind-dev
sudo apt install -y autoconf automake libtool libffi-dev pkg-config libunwind8
sudo pip3 install meson ninja
sudo apt install crossbuild-essential-arm64
git clone -b  bootis-mainline "http://gerrit.dpu.tech/dpdk"
cd dpdk
PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig \
meson aarch64-build --cross-file config/arm/arm64_armv8_linux_gcc \
--prefix /usr \
--includedir /usr/include/aarch64-linux-gnu \
--libdir /usr/lib/aarch64-linux-gnu
ninja -C aarch64-build
sudo ninja install -C aarch64-build
cd ..
git clone -b bootis-mainline "http://gerrit.dpu.tech/ovs"
cd ovs
./boot.sh
PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig \
CC=aarch64-linux-gnu-gcc \
CXX=aarch64-linux-gnu-g++ \
./configure --host=arm-linux  \
--with-dpdk=static  --prefix=/usr \
--localstatedir=/var --sysconfdir=/etc \
--with-logdir=/var/log/nebulamatrix/openvswitch
make -j40
./package.sh arm64

AMD64-release
sudo dpkg --add-architecture amd64
sudo apt install -y build-essential  python3-pyelftools libnuma-dev libunwind-dev 
sudo apt install -y autoconf automake libtool libffi-dev pkg-config libunwind8
sudo pip3 install meson ninja
git clone -b bootis-mainline "http://gerrit.dpu.tech/dpdk"
cd dpdk
sudo meson build -Dc_args="-mno-avx512f"
sudo ninja -C build
sudo ninja install -C build
sudo ldconfig
cd ..
git clone -b bootis-mainline http://gerrit.dpu.tech/ovs
cd ovs
./boot.sh
./configure --with-dpdk=static --prefix=/usr --localstatedir=/var --sysconfdir=/etc \
--with-logdir=/var/log/nebulamatrix/openvswitch
make -j40
./package.sh amd64


```

# OVS DPDK环境搭建



# 总体流程

## 网卡设备注册到全局设备链表

初始化EAL环境抽象层时才会进行驱动与设备匹配加载。

![1660621696939](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660621696939.png)



## 网卡设备驱动初始化

初始化EAL环境抽象层时才会进行网卡设备驱动初始化。

![1660622065453](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660622065453.png)

![1660622083709](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660622083709.png)

![1660622106748](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660622106748.png)

## 网卡收发资源分配

![1660622137965](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660622137965.png)

## 网卡收发报文

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202109261101485948.png)



# OVS调用DPDK接口流程

OVS代码中对DPDK的接口调用都集中在lib/netdev-dpdk.c文件中。下面简单分析一下OVS调用DPDK接口的代码流程。

## 创建新端口和修改老端口流程

OVS创建新端口的函数调用栈如下

![1660622882655](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660622882655.png)

port_reconfigure函数是OVS创建新端口或修改老端口配置的总入口，在这个函数中会调用netdev_reconfigure函数，netdev_reconfigure函数中根据端口的类型，会挂接到不同端口类型的操作函数。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202204211544288599.png)

dpdk一共有4种端口类型：dpdk_class、dpdk_vhost_class、dpdk_vhost_client_class和dpdk_vdpa_class。这4种类型端口的操作函数是通过netdev_dpdk_register函数来注册的。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202204211545499286.png)

我们现在ecpu上的DPDK使用的端口都属于dpdk_class，dpdk_class的操作函数如下：

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202204211547228496.png)

netdev_reconfigure函数中调用reconfigure接口时实际调用的函数就是**netdev_dpdk_reconfigure**，此函数就是OVS调用DPDK接口来创建新端口和修改老端口配置的`总入口`。netdev_dpdk_reconfigure函数代码流程总的来说就是先停止老的netdev，然后再设置netdev，最后再启动netdev。

下面详细分析下netdev_dpdk_reconfigure函数： 

![1660623123874](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660623123874.png)

首先判断新的netdev配置和老的netdev配置是否相同，这些配置有tx队列数，rx队列数，mtu，中断模式，tx队列长度，rx队列长度，netdev的mac地址和netdev所在的socketid。如果相同那么就退出，不同就接着往下走配置流程。在创建新端口时，由于新端口的初始配置都没有，所以必然是不同的，会往下接着走配置流程。

然后判断netdev是否需要reset，如果需要那么就调用rte_eth_dev_reset函数，不然就调用rte_eth_dev_stop函数，一般是走rte_eth_dev_stop函数。rte_eth_dev_stop函数是dpdk中的函数，逻辑比较简单，就是调用pmd驱动的dev->dev_ops->dev_stop接口。

接下来调用netdev_dpdk_mempool_configure函数来创建一个mempool，用来保存收到的报文。

![1660623197408](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660623197408.png)

在netdev被stop之后，netdev_dpdk_reconfigure函数会设置新的netdev的tx队列和rx队列的数量、tx队列和rx队列的长度和中断模式，然后调用dpdk_eth_dev_init函数来启动新的netdev。dpdk_eth_dev_init函数对dpdk接口的调用流程如下：

```javascript
dpdk_eth_dev_init
-- rte_eth_dev_info_get（读取dev硬件能力）
--dpdk_eth_dev_port_config
-- rte_eth_dev_info_get（读取dev硬件能力）
​    --rte_eth_dev_configure(配置dev)
​    --rte_eth_dev_set_mtu（设置mtu）
​    --rte_eth_tx_queue_setup(设置tx队列)
​    --rte_eth_rx_queue_setup(设置rx队列)
--rte_eth_dev_start(dev启动)
--rte_eth_promiscuous_enable(杂收模式使能);
--rte_eth_allmulticast_enable(组播使能);
```

## 收发包流程

### 收包流程调用栈

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202204211549418032.png)

OVS的收包函数是netdev_dpdk_rxq_recv，它的逻辑比较简单，先调用dpdk的收包函数rte_eth_rx_burst收包，然后如果设置了policer，就丢掉一部分。最后如果本次收到了32个包，那么就调用rte_eth_rx_queue_count函数去读一下这个收包队列里面一共有多少个等待收包的描述符（只有在vhost场景下才有此步骤，其他场景下qfill是0，不会调用rte_eth_rx_queue_count函数）。另外要说明的是如果收到报文之后，查询流表是单播流表的话，那么发包报文的mbuf会直接复用收包的mbuf，不会先释放收包的mbuf再申请发包的mbuf。

![1660630313508](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660630313508.png)

### 发包流程调用栈

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202204211550125779.png)

OVS的收包函数是netdev_dpdk_eth_tx_burst，它的处理逻辑如下：如果使能了tso，那么就调用rte_eth_tx_prepare函数做一下准备，把保存报文的mbuf修改一下，然后会循环调用rte_eth_tx_burst函数进行发包，如果一次报文没有全部发完，且发包成功的数目不为0，那么就调用rte_eth_tx_burst函数发送剩下的报文，直到报文全部发完，或者是发包成功的数目为0才停止发送，最后将剩余没有发送的报文的mbuf释放。根据这个代码流程，在写DPDK PMD中的发包函数时要注意一点，没有发送成功的报文的mbuf中的data_offset、data_len等字段不能修改，不然会出现反复修改同一字段导致报文错误的情况。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202204211550228351.png)

# 内核协议栈队列选择机制

总的来说，Linux内核协议栈发包时使用的网卡队列有2种选择方法，一种由网卡驱动程序在net_device_ops结构体中挂接的ndo_select_queue函数来选择，其二是由协议栈自己来选择。不管是哪一种方式选择的队列，最终都会保存在sk_buff中的queue_mapping字段中，需要注意这个queue_mapping是给每个PF或VF分配的软件队列号，而不是网卡芯片中的硬件队列号，两者需要做一个转换。

 

下面我们来详细看一下linux协议栈中队列选择逻辑的源码

linux协议栈中队列选择的入口函数是dev_queue_xmit，而队列选择的关键逻辑在dev_queue_xmit -> __dev_queue_xmit -> netdev_core_pick_tx函数中。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201201088546.png)

 

dev->real_num_tx_queues参数是网卡驱动在注册net_dev时需要填写的参数，是当前网卡设备分配的发包队列数。当此参数不为1时，会先判断驱动挂接的ops->ndo_select_queue函数指针是否为空，如果不为空，那么就调用ops->ndo_select_queue函数来选择发包队列。如果为空，那么就使用netdev_pick_tx函数来选择发包队列。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201201381509.png)

 

首先queue_index = sk_tx_queue_get(sk)这行代码表示队列使用socket中保存的队列，也就是上次发包选择的队列，这样避免每次发包都要进行路径选择，既节省时间，又避免报文走不同队列导致乱序。

如果socket中保存的队列是0，那么就代表之前没有选择过队列，那么就使用get_xps_queue函数来选择队列。XPS的全称为**Transmit Packet Steering**。XPS主要是为了避免cpu由RX队列的中断进入到TX队列的中断时发生切换，导致cpu cache-miss损失性能。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201202110864.png)

 

从get_xps_queue函数中可以看出，xps有2个选择队列的机制，其一是根据收包队列来选择发包队列，其二是根据发包cpu来选择发包队列。在默认情况下是根据发包cpu来选择发包队列的。具体的选择逻辑在__get_xps_queue_idx函数中。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201202341882.png)

 

__get_xps_queue_idx函数的选择队列逻辑可以用下图来表示

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201203049381.png)

根据当前发包cpuid即skb->sender_cpu的来选择网卡发包队列，如果发送队列通过tc qdisc mqprio命令配置了硬件队列优先级，则还会根据报文的优先级（skb->priority）来映射硬件队列的tc并获取硬件队列总的tc数目num_tc，然后用sender_cpu * num_tc + tc得到的索引来查找发送队列，如果有多个发送队列匹配此索引，则根据hash值从中选出一个发送队列。

 

XPS的配置数据保存在/sys/class/net/dev/queues/路径下的xps_cpus、xps_rxqs和traffic_class文件里，这3个文件里面的数据是由网卡驱动来生成的。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201203250852.png)

 

在810驱动中有3处涉及XPS的配置，一处是设置网卡的tc的总数netdev_set_num_tc。

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201203475959.png)

 

一处是设置队列和cpu的对应关系netif_set_xps_queue，也就是xps_cpus文件

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201203599184.png)

 

还有一个是设置队列的优先级netdev_set_tc_queue，也就是traffic_class文件

![img](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\202110201204254303.png)



# 定位手段

**查看log日志**



**查看core文件**



**反汇编**



# 问题实例546

http://jira.dpu.tech/browse/DPUBUG-546

【Bootis-DF50】【B306】【软件】长稳测试导致ovs core dump



**测试表述：**

 1、“从环境上的日志看有手动触发kill -11信号的记录，不排除有人手动杀ovs”。
kill -11是在发现环境上不能生成coredump文件后，安装软件解决该问题时所做的验证测试，发生成OVS coredump之后，可以排除有人手动刹OVS触发了coredump.

2、问题不复现。
该OVS coredump的问题第一次出现，是在长稳测试运行了一夜之后发生的。后面尝试复现过程中，总是有其他问题发生，长稳测试没有运行超过24小时过。所以，不能说问题不复现，只能说在尝试复现的过程中一直被阻塞。 



**开发分析：**

log日志如下：

![1660634114822](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660634114822.png)

挂死函数：

![1660633976399](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660633976399.png)

gdb对应的ovs进程后反汇编挂死函数：

```c
(gdb) disassemble nbl_sf50_recv_pkts
Dump of assembler code for function nbl_sf50_recv_pkts:
   0x0000000000721ba0 <+0>:     endbr64
   0x0000000000721ba4 <+4>:     push   %r15
   0x0000000000721ba6 <+6>:     push   %r14
   0x0000000000721ba8 <+8>:     push   %r13
   0x0000000000721baa <+10>:    push   %r12
   0x0000000000721bac <+12>:    push   %rbp
   0x0000000000721bad <+13>:    mov    %rdi,%rbp   =============== rdi = rx_queue
   0x0000000000721bb0 <+16>:    push   %rbx
   0x0000000000721bb1 <+17>:    mov    %edx,%ebx
   0x0000000000721bb3 <+19>:    sub    $0x68,%rsp
   0x0000000000721bb7 <+23>:    mov    %rsi,0x10(%rsp)
   0x0000000000721bbc <+28>:    mov    %dx,0x1e(%rsp)
   0x0000000000721bc1 <+33>:    movzwl 0x24(%rdi),%r13d
   0x0000000000721bc6 <+38>:    mov    %fs:0x28,%rax
   0x0000000000721bcf <+47>:    mov    %rax,0x58(%rsp)
   0x0000000000721bd4 <+52>:    xor    %eax,%eax
   0x0000000000721bd6 <+54>:    movzwl 0x28(%rdi),%eax
   0x0000000000721bda <+58>:    mov    %ax,0x1c(%rsp)
   0x0000000000721bdf <+63>:    callq  0x71cad0 <nbl_flow_get_profile_id_offset>
   0x0000000000721be4 <+68>:    mov    %eax,0x18(%rsp)
   0x0000000000721be8 <+72>:    mov    0x48(%rbp),%rax  ============= rax = rxq_info + 0x48
   0x0000000000721bec <+76>:    mov    0x8(%rax),%rax   ============= rax = 
   0x0000000000721bf0 <+80>:    mov    %rax,0x8(%rsp)
   0x0000000000721bf5 <+85>:    test   %bx,%bx
   0x0000000000721bf8 <+88>:    je     0x722470 <nbl_sf50_recv_pkts+2256>
   0x0000000000721bfe <+94>:    xor    %ecx,%ecx
   0x0000000000721c00 <+96>:    movl   $0x0,0x4(%rsp)
   0x0000000000721c08 <+104>:   mov    %cx,0x2(%rsp)
   0x0000000000721c0d <+109>:   xor    %r15d,%r15d
   0x0000000000721c10 <+112>:   jmpq   0x721d5d <nbl_sf50_recv_pkts+445>
   0x0000000000721c15 <+117>:   nopl   (%rax)
   0x0000000000721c18 <+120>:   movzwl 0x80(%rax),%eax
   0x0000000000721c1f <+127>:   lea    0x356c01a(%rip),%rdx        # 0x3c8dc40 <rep_qid_to_rep_id>
   0x0000000000721c26 <+134>:   shr    $0x3,%ax
   0x0000000000721c2a <+138>:   and    $0x7ff,%eax
   0x0000000000721c2f <+143>:   movzwl (%rdx,%rax,2),%eax
   0x0000000000721c33 <+147>:   cmp    $0x203,%ax
   0x0000000000721c37 <+151>:   ja     0x721e18 <nbl_sf50_recv_pkts+632>
   0x0000000000721c3d <+157>:   imul   $0x40c0,%rax,%rax
   0x0000000000721c44 <+164>:   add    0x9aff45(%rip),%rax        # 0x10d1b90
   0x0000000000721c4b <+171>:   mov    0x38(%rax),%rax   
```



1、 反汇编看  0x0000000000721c4b <+171>:   mov    0x38(%rax),%rax            dev->data  ，dev->data字段在生成rte_eth_dev时从eth_dev_get 获取，接口删除也不会删除这块资源。所以在没有core文件时不好确定问题根因

2、从环境上的日志看有手动触发kill -11信号的记录，不排除有人手动杀ovs

反汇编分析如下：

```c


   0x0000000000721c2f <+143>:   movzwl (%rdx,%rax,2),%eax
   0x0000000000721c33 <+147>:   cmp    $0x203,%ax      rax = port_id   if (port_id < 516)
   0x0000000000721c37 <+151>:   ja     0x721e18 <nbl_sf50_recv_pkts+632>
   0x0000000000721c3d <+157>:   imul   $0x40c0,%rax,%rax    dev = rte_eth_device[port_id]
   0x0000000000721c44 <+164>:   add    0x9aff45(%rip),%rax        # 0x10d1b90
   0x0000000000721c4b <+171>:   mov    0x38(%rax),%rax            dev->data             

   0x0000000000721c4f <+175>:   testb  $0x8,0x111a(%rax)  dev->data->dev_started != 1
   0x0000000000721c56 <+182>:   je     0x721e18 <nbl_sf50_recv_pkts+632>
   0x0000000000721c5c <+188>:   mov    0x60(%rax),%rdx  rdx=nbl_repr
   0x0000000000721c60 <+192>:   cmpl   $0x2,0xc(%rdx)  rdx = nbl_repr->status == 2
   0x0000000000721c64 <+196>:   jne    0x721e18 <nbl_sf50_recv_pkts+632>
```



# 问题实例554

http://jira.dpu.tech/browse/DPUBUG-554

【Bootis-DF50】【B308】【软件】rep2048口从br1删除，再添加到br-int会报错



如何修改解决该Bug（简要描述解决方案）

1）add_vport_match 函数在返回时先调用netdev_close，释放引用计数

![1660635664166](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660635664166.png)

# 问题实例547

http://jira.dpu.tech/browse/DPUBUG-547

【Bootis-DF50】【B306】【软件】长稳测试导致ovs core dump

![1660636085367](D:\gooo\-GOOOO\DPDK收发包问题定位学习.assets\1660636085367.png)

异常情况下PF先close，导致了触发了rep 口stop流程的残余无效代码的失败；从而导致bond rep slave close 异常，导致引起了死循环；

# 问题实例502

http://jira.dpu.tech/browse/DPUBUG-502

【Bootis-DF50】【B305】【开发自测】ovs restart概率出现收包卡死

**见后文**



# 遗留问题梳理

DF50板上内核lag发包arp没有双发问题：

只有一台交换机学到了arp的原因是br-int口没有配置IP，导致arp请求报文没有送到内核，之所以有一个交换机能学到arp是因为内核主动往外发的arp请求。只要给br-int配置一个IP，然后arp请求报文就送到了内核，内核回包也送到了br-int，之前ovs的bond已经做了arp双发，此时arp就是双发的。此问题非问题，是由于br-int没有配IP导致的。



ovs restart后收包队列挂死问题：http://jira.dpu.tech/browse/DPUBUG-502

之前在stop流程中rx队列去使能和DMA内存释放之间加了10ms延时解决此问题。但是由于未知原因，ovs restart的时候PF口的ref_cnt不为0，导致ovs没有调用stop函数。那么在ovs重新启动后，在初始化流程中rx队列是一直使能的，导致又出现收包队列卡死问题。解决方案是在填充收包描述符队列之前判断队列是否已经使能，如果已经使能，就先把队列去使能，再等待10ms。 



配置bond口后，删除PF口或修改PF口配置挂死问题 ：

问题根因已定位，是tx_queues指针数组只申请了2个成员大小，但是使用的时候用了18个成员，导致内存越界，把动态申请的内存堆信息和自旋锁信息写坏了，导致释放此内存时，在获取自旋锁时卡死。

另外业务组新加的提前创建PF口的流程是有问题的，因为这样会导致PF口被configure 2次，但是现在PF口驱动不支持被configure 2次，会出现收包队列内存写越界和内存泄露问题，因此需要配置ovs-vsctl -- set interface dpdk-pf0 ofport_request=1这个命令保证PF口被先创建。



# 代码修改梳理



