[toc]

# Linux命令

### 网络相关命令

```javascript
\# 获取逻辑cpu数量(包括超线程逻辑cpu数量):
~$ lscpu -p | egrep -v '^#' | wc -l
4

\# 获得物理cpu/核心的数量:
~$ lscpu -p | egrep -v '^#' | sort -u -t, -k 2,4 | wc -l
8

#查看消耗内存最多的几个进程：
ps aux --sort -rss | head

#top命令查找系统中消耗内存最多的进程
top -c -b -o +%MEM | head

#cat /proc/1063/status
查看进程内存占用，1063是进程id

~# dmidecode -t 4 | egrep 'Socket Designation|Count'
 Socket Designation: CPUSocket
 Core Count: 8
 Thread Count: 8

root@localhost:/home/ubuntu# route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         10.10.29.1      0.0.0.0         UG    0      0        0 usb0
10.10.29.0      0.0.0.0         255.255.255.0   U     0      0        0 usb0




ifconfig eth4 1.2.3.4/24后记得配置陆由
route add default gw 10.10.33.1 dev eth4

### cat /proc/interrupts
查看中断
```



### 驱动相关命令

```javascript
$ uname -a
Linux 7dgroup2 3.10.0-514.6.2.el7.x86_64 #1 SMP Thu Feb 23 03:04:39 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

ubuntu@localhost:~$ lspci
00:00.0 PCI bridge: Freescale Semiconductor Inc Device 8d99 (rev 20)
01:00.0 Ethernet controller: Device 1f0f:1220
01:00.1 Ethernet controller: Device 1f0f:1221
01:00.2 Ethernet controller: Device 1f0f:1222
01:00.3 Ethernet controller: Device 1f0f:1223

ubuntu@localhost:~$ lscpu
Architecture: x86_64 #架构 
CPU op-mode(s): 32-bit, 64-bit #运行方式
Byte Order: Little Endian #字节顺序
CPU(s): 2 #逻辑cpu颗数 
On-line CPU(s) list: 0,1 #在线CPU
Thread(s) per core: 2 #每个核心线程
Core(s) per socket: 1 #每个cpu插槽核数/每颗物理cpu核数 
Socket(s): 1 #cpu插槽数 
NUMA node(s): 1 #非统一内存访问节点
Vendor ID: GenuineIntel #cpu厂商ID 
CPU family: 6 #cpu系列 
Model: 63 #型号编号

root@localhost:/home/ubuntu# ifconfig
usb0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.29.40  netmask 255.255.255.0  broadcast 10.10.29.255
        inet6 fe80::20e:c6ff:fe34:648c  prefixlen 64  scopeid 0x20<link>
        ether 00:0e:c6:34:64:8c  txqueuelen 1000  (Ethernet)
        RX packets 915649  bytes 808050683 (808.0 MB)
        RX errors 0  dropped 63883  overruns 0  frame 0
        TX packets 264837  bytes 20699809 (20.6 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


root@iZ8vbbi54mgzr5g88hd3alZ:~# numactl -H //查看numa节点命令 
available: 1 nodes (0)
node 0 cpus: 0
node 0 size: 1901 MB
node 0 free: 1400 MB
node distances:
node   0
  0:  10


// 查看当前设备的所有存储设备
root@iZ8vbbi54mgzr5g88hd3alZ:~# sudo fdisk -l
Disk /dev/vda: 40 GiB, 42949672960 bytes, 83886080 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x6643525d

Device     Boot Start      End  Sectors Size Id Type
/dev/vda1  *     2048 83886046 83883999  40G 83 Linux
root@iZ8vbbi54mgzr5g88hd3alZ:~#


# lspci -s 01：00：1 -vvvxxx

# ethtool -k eth0
Features for eth0:
rx-checksumming: on [fixed]
tx-checksumming: on

# tar -zxvf filename.tar.gz
# tar -jxvf ×××.tar.bz2
# tar -czvf test.tar.gz a.c   //压缩 a.c文件为test.tar.gz
# tar -zcvf polo.tar.gz examples  
   tar -zcvf 打包后生成的文件名全路径 examples是要打包的目录
   
# tar -zxvf polo.tar.gz
	解压文件
   
# 内存最多的10个进程
# ps -aux | sort -k4nr | head -10
```



# OVS命令

### OVS 内核关系图

 ![img](D:\youdaoyunbiji\OVS-DPDK命令行总结.assets\1060878-20190925184030210-135832070.png) 

### OVS-DPDK关系图

 ![img](D:\youdaoyunbiji\OVS-DPDK命令行总结.assets\1060878-20210509130204033-1033930936.png) 



## DEB包相关命令

```javascript
apt install dpdk //安装dpdk包
apt install openvswitch-dpdk  //安装 ovs deb包
dpkg -l openvswitch-dpdk    //查询deb包版本
dpkg -P openvswitch-dpdk      //卸载deb包
systemctl start openvswitch-dpdk   //启动ovs
systemctl status openvswitch-dpdk  //查看ovs状态
systemctl stop openvswitch-dpdk   //停止ovs
```



## 启动类命令

### 启动ovsdb-server

ovsdb-server /etc/openvswitch/conf.db \

​	-vconsole:emer -vsyslog:err -vfile:info \

​	--remote=[punix:/var/run/openvswitch/db.sock](http://punix/var/run/openvswitch/db.sock) \

​	--private-key=db:Open_vSwitch,SSL,private_key \

​	--certificate=db:Open_vSwitch,SSL,certificate \

​	--bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert --no-chdir \

​	--log-file=/var/log/openvswitch/ovsdb-server.log \

​	--pidfile=/var/run/openvswitch/ovsdb-server.pid \

​	--detach --monitor



### 启动vswitchd进程

ovs-vswitchd [unix:/var/run/openvswitch/db.sock](http://unix/var/run/openvswitch/db.sock) \

​	-vconsole:emer -vsyslog:err -vfile:info --mlockall --no-chdir \

​	--log-file=/var/log/openvswitch/ovs-vswitchd.log \

​	--pidfile=/var/run/openvswitch/ovs-vswitchd.pid \

​	--detach --monitor





## 控制管理类命令

### CPU亲和性配置

CPU亲和性配置，简称绑核。就是某个端口的某个接收队列只使用固定的某个核，这样可以避免核之间的频繁切换，提升转发性能。

假设一台设备有10个核，核的序号是从0开始，并且从右往左排，我们选取编号为7、8的两个核：

![img](https://cdn.nlark.com/yuque/0/2021/png/421882/1640143579299-7ce9dda5-fb2c-4be5-b610-f89d694f77fa.png)

则掩码为 0x0180。

配置如下：

ovs-vsctl --no-wait set Open_vSwitch . other_config:pmd-cpu-mask=0x0180

ovs-vsctl set interface dpdk0 options:n_rxq=1 other_config:pmd-rxq-affinity="0:7"

ovs-vsctl set interface dpdk1 options:n_rxq=1 other_config:pmd-rxq-affinity="0:8"

ovs-vsctl set interface dpdk0 options:n_txq=1

ovs-vsctl set interface dpdk1 options:n_txq=1



### 绑定网口

ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

ovs-vsctl add-port br0 dpdk0 -- set interface dpdk0 type=dpdk options:dpdk-devargs=0000:16:00.0

### OVS XML命令

```javascript
/usr/share/openvswitch/scripts/ovs-bugtool-tc-class-show
ovs-vsctl show
ovs-vsctl --no-wait get Open_vSwitch . other_config
ovsdb-client -f csv dump unix:/var/run/openvswitch/db.sock Open_vSwitch


/usr/share/openvswitch/scripts/ovs-bugtool-fdb-show
ovs-appctl lacp/show

ovs-appctl cfm/show
ovs-appctl bfd/show
ovs-appctl dpctl/dump-conntrack
ovs-appctl coverage/show   一种类似于行统计的手段
ovs-appctl bond/show

ovs-appctl memory/show
/usr/share/openvswitch/scripts/ovs-bugtool-ovs-appctl-dpif

ovs-appctl -t ovsdb-server ovsdb-server/list-dbs
ovs-appctl dpctl/dump-flows netdev@ovs-netdev

ovs-appctl dpctl/dump-flows -m netdev@ovs-netdev
ovs-appctl dpctl/dump-flows system@ovs-system

ovs-appctl dpctl/show -s
/usr/share/openvswitch/scripts/ovs-bugtool-ovs-ofctl-loop-over-bridges "show"
/usr/share/openvswitch/scripts/ovs-bugtool-ovs-ofctl-loop-over-bridges "dump-flows"
/usr/share/openvswitch/scripts/ovs-bugtool-ovs-ofctl-loop-over-bridges "dump-ports"
/usr/share/openvswitch/scripts/ovs-bugtool-ovs-ofctl-loop-over-bridges "dump-groups"
/usr/share/openvswitch/scripts/ovs-bugtool-ovs-ofctl-loop-over-bridges "dump-group-stats"
/usr/share/openvswitch/scripts/ovs-bugtool-ovs-ofctl-loop-over-bridges "dump-tlv-map"
/usr/share/openvswitch/scripts/ovs-bugtool-get-dpdk-nic-numa

ip -s -s link show
/usr/share/openvswitch/scripts/ovs-bugtool-get-port-stats
```





### namespace相关命令

```javascript
ip netns add ns0
ip netns add ns1

ip link set enp3s0 netns ns0
ip netns exec ns0 ip addr add 1.1.1.1/24 dev enp3s0
ip netns exec ns0 ip link set enp3s0 up

ip link set enp4s0 netns ns1
ip netns exec ns1 ip addr add 1.1.1.2/24 dev enp4s0
ip netns exec ns1 ip link set enp4s0 up

ip netns exec ns1 ping 1.1.1.1


### plus
ip netns add ns1
ip netns add ns2
 
ovs-vsctl add-br br0
ovs-vsctl add-port br0 tap1 -- set Interface tap1 type=internal
 
ip link set tap1 netns ns1
ip netns exec ns1 ip link set dev tap1 up
 
ovs-vsctl add-port br0 tap2 -- set Interface tap2 type=internal
ip link set tap2 netns ns2
ip netns exec ns2 ip link set dev tap2 up
 
ip netns exec ns1 ip addr add 192.168.1.102/24 dev tap1
ip netns exec ns2 ip addr add 192.168.1.101/24 dev tap2
 
ip netns exec ns1 ip link set lo up
ip netns exec ns2 ip link set lo up
ip netns exec ns1 ping -c 4 192.168.1.101

ip netns exec ns1 ping -c 4 192.168.1.101
```



## ovs-dpctl命令

```
ovs-dpctl dump-dps				可以统计每条 datapath 上的设备通过的流量，打印流的信息

```

## ovs-ctl命令

```javascript
ovs-ctl --system-id=random|<uuid> [<options>] start
                                   
       ovs-ctl stop
       ovs-ctl --system-id=random|<uuid> [<options>] restart
       ovs-ctl status
       ovs-ctl version
       ovs-ctl [<options>] load-kmod
       ovs-ctl --system-id=random|<uuid> [<options>] force-reload-kmod

ovs-ctl [--protocol=<protocol>] [--sport=<sport>] [--dport=<dport>] enable-protocol

       ovs-ctl delete-transient-ports
       ovs-ctl help | -h | --help
       ovs-ctl --version
                                                          
### ovs-ctl restart
```



## ovs-appctl命令

```javascript
### 查看mac和端口关系表
ovs-appctl fdb/show br0

### 查询OVS三级流表
ovs-appctl dpif-netdev/pmd-stats-show
ovs-appctl dpif-netdev/pmd-rxq-show
ovs-appctl dpif-netdev/pmd-perf-show
ovs-appctl dpif-netdev/pmd-stats-show -pmd 7  #可用于计算emc命中率

### 清除统计信息
ovs-appctl dpif-netdev/pmd-stats-clear
ovs-appctl dpif-netdev/pmd-stats-show

### 配置日志等级
ovs-appctl  vlog/set dpdk::DBG

### 查询arp表项
ovs-appctl tnl/arp/show
```

### 	桥命令

```javascript
fdb/flush [bridge]
清除指定桥的MAC学习表，没有指定桥则应用于所有桥 

fdb/show bridge 列出指定桥上每个MAC直至与VLAN的对应信息，并且包含该学习到该MAC的端口号还有该条目的age信息，单位为秒 

bridge/reconnect [bridge]
命令桥断开和当前openFlow控制器的连接并且重连，如果没有指定桥，则应用于所有桥，这个命令可以在分析排查控制器错误的时候很有用 

bridge/dump-flows bridge 列出桥上所有的流，包括那些在其他命令中（例如 ovs-ofctl dump-flows）默认隐藏的流.一些机制比如带内管理等设置的流策略是不行允许修改和覆盖的，所以对控制器来说他们是隐藏的。
 

BOND命令 这些命令管理ovs桥上绑定端口。要了解这些命令，你需要了解一种叫做源负载分担（SLB）的实施细节。作为直接将源MAC地址设成SLAVE的做法，通过特定的计算将48bit的MAC自动化映射到一个8bit的值（MAC hash）。所有匹配这个hash值得mac地址被指定为slave。 

bond/list 列出所有的绑定配置，以及slaves，范围包含所有桥 

bond/show[port] 给出指定端口的所有绑定有关的信息（updelay，downdelay，距离下次进行重新平衡的时间），如果没指定端口，则列出所有bond的端口。同时也列出所有slave的信息，包括这些slave是处于enable还是disable状态、完成一个正在实施中的updelay或者一个downdelay的时间、是否是激活态的slave。任何关于LACP的信息可以使用lacp/show来查看。 

bond/migrate port hash slave 仅适用于配置了SLB的绑定。分配一个指定的machash值给一个新的slave。Port指定了bond的端口，hash则是将要迁移的mac hash值（十进制0到255之间），slave即是要新的slave。 这个重新制定的关系不是永久的：rebalanceing或者发生fail-over时，这个mac hash蒋辉按照常规的方式切换到新的slave上面
MAC hash值不能指定到一个disable态的slave上
 

bond/set-active-slave port slave 将给定slave设为激活态的slave。给定的slave必须是enable状态。
这个配置不是永久的：如果该slave变成disable，将会自动选择一个新的slave。 

bond/enable-slave port slave 

bond/disable-slave port slave Enable/disableslave在给定的bond port上，忽略任何updelay和downdelay。
这个设置不是永久的：他将保持到该slave的承载状态变化 

bond/hashmac [valn] [basis]
返回指定mac（伴随指定vlan和basis）的hash值 

lacp/show [port] 列出所有指定端口的lacp关联信息。包括active/passive、system id、systempriority。同时列出每个slave 的信息：enable/disable、连接上或者未连接上、端口id和优先级、主用信息和成员信息。如果没有指定端口，则显示所有应用了CFM的接口信息。
```

### 数据通道命令

```javascript
这些命令管理逻辑数据通道。类似ovs-dpctl的命令。 

dpif/dump-dps 在多行中显示所有配置的datapath名称 

dpif/show[dp….]
打印dp的汇总信息，包括dp的状态还有连接上的端口列表。端口的信息包括openFlow的端口号，datapath的端口号，以及类型（本地端口被标识为openflow port 65534）
如果指定了一个或多个datapath，将只显示指定的这些dp的信息。否则，则显示所有dp的信息。 

dpif/dump-flows dp 想控制端打印dp中流表的所有条目。
这个命令主要来与debug Open Vswitch.它所打印的流表不是openFlow的流条目。它打印的是由dp模块维护的简单的流。如果你想查看OpenFlow条目，请使用ovs-ofctl dump-flows。 dpif/del-fow dp 删除指定dp上所有流表。同上所述，这些不是OpenFlow流表。
```

### dpctl命令

```javascript
### 查看流表
ovs-appctl dpctl/dump-flows -m

### 查看流表数目
ovs-appctl dpctl/dump-flows -m | wc -l

### 添加datapath流表
ovs-appctl dpctl/add-flow netdev@ovs-netdev "in_port(3),eth(),eth_type(0x800),ipv4(src=9.9.9.9,dst=8.8.8.8)" 4

ovs-appctl dpctl/add-flow netdev@ovs-netdev "in_port(dpdk0),eth(),eth_type(0x800),ipv4(src=9.9.9.9,dst=8.8.8.8)" dpdk1

### 查询datapath流表
ovs-appctl dpctl/dump-flows netdev@ovs-netdev

### 查询datapath
ovs-appctl dpctl/dump-dps

### ovs-appctl dpctl/show
# ovs-appctl dpctl/show
netdev@ovs-netdev:
  lookups: hit:0 missed:0 lost:0
  flows: 0
  port 0: ovs-netdev (tap)
  port 1: br0 (tap)
  port 2: dpdk-pf0 (dpdk: configured_rx_queues=16, configured_rxq_descriptors=2048, 
```

### 通用命令

```javascript
exit 优雅关闭ovs-vswitchd进程 

qos/show interface 查询内核中关于qos的配置以及和给出端口有关的状态 

cfm/show [interface]
显示在指定端口上CFM配置的详细信息。如果没有指定接口，则显示所有使能了CFM的接口 

cfm/set-fault [interface] status 强制将指定端口的CFM模块的错误状态（如果没指定接口则是全部接口）设置成指定的状态。可以是”true”,”false”,”normal” 

stp/tcn [bridge]
在运行了stp的bridge上强制进行拓扑变更。之将导致该dp发送拓扑变更通知并且刷新MAC表。。如果没有指定桥，则应用到所有dp
```

### OpenFlow协议命令

```javascript
ofproto/list 列出所有运行中ofproto实例。这些名字可能在ofproto/trace中用到。 

ofproto/trace[dpname] odp_flow [-generate] [packet] ofproto/tracebridgebr_flow [-generate] [packet]追踪报告构造包在交换机中的路径。包头（例如源和目的）和元数据（比如：入端口），一起组成它的“flow”，根据这些“flow”决定包的目的地。你可以用些列途径地址流。 dpnameodp-flow odp-flow 是一个可以使用 ovs-dpctl dump-flows命令打印出来的流。如果你所有的桥都是同样样的类型，这也是通常的情况，那么你可以忽略 dp-name，但是如果你的桥拥有不同类型（即，ovs-netdev和ovs-system型），那么你必须要指定dp-name。 bridgebr_flow br_flow是一种可以使用ovs−ofctl  add−flow命令添加的流类型。（这不是一个OpenFlow流：除了其他的差异，这种流永远不会有通配符）bridge指定了被追踪的br-flow经过的桥名。
 
通常情况下，你可以只指定一个流，用以上提到的一种形式，但是有时候你可能需要值一个确切的数据包来代替流
  副作用 有些动作是由副作用的，比如，normal 动作能刷新MAC学习表，learn动作会改变OpenFlow表。ofproto/trace只有在指定包的时候发生副作用。如果你需要虚作用，那么你必须提供一个包。
（output 动作也是明显的副作用，但是ofproto/trace 永远不会执行这个动作，即便是你制定了包的时候）
  不完整的信息 大多数时候，Open Vswitch能够尽力用流就得出一个包所经路径的所有信息，但是在一些特定场景下，ovs可能需要查看一些不包含在流内的其他包的部分信息。这种情况下，如果你不提供一个包，那么ofproto/trace就会提示你需要一个包。
 
如果你希望在ofproto/trace 操作中包含一个包，你有两种方法实现：
  -generate 这个选项，附加在之前叙述的两种流方式后面用来在内生成该流的一个包并且使用这个包。如果你的目地是利用副作用，那么这个选项是你达成目标的最容易的方法。但是-generate 不是一个填充不完整信息的好方式，因为生成的包是基于流信息的，即是说这个包并不能带有任何这个流以外的信息。
  packet 这种形式提供了一个明确的以十六进制数字序列表示的包。一个以太网帧至少14 bytes长，即至少28个16进制的数字。很明显，使用手工输入是很不方便的。好在我们的ovs-pacp 和ovs-tcpundump 工具提供了简便的方法。
利用这种形式，包头直接从packet中提取，那么odp_flow或者br_flow应该只包含元数据。元数据可以是以下类型：
  skb_priority 报文的qos优先级 skb_mark 报文的SKB标记 tun_id 报文到达的隧道id号 in_port 报文到达的端口
第一种流格式的in_port的值是内核 datapath的端口号，而OpenFlow的端口号值是OpenFlow的端口号。这两种端口号一般都是不一样的，而且没什么关系可言。
  

ofproto/self-check [switch] 运行内部一致性检查，并且返回一个简要的汇总。指定桥的时候限定在该实例，否则是所有实例。如果汇总报告了任何错误，那么ovs的日志中会包含更多详细的信息。请将这些错误报告作为bug发送给ovs的开发者。
```

### VLOG命令

```javascript
这些命令管理ovs-vswitchd的日志配置
  

vlog/set [spec] 设置日志等级。没有spec时，设置所有模块和设施的日志等级为dbg。其他情况下，spec是一个用逗号或者空格或者冒号分隔的单词列表，最多支持下面所述范畴的每样配置一个。
l  一个可用模块名，可以用ovs-appctlvlog/list 命令来查看所有可用模块名。
l syslog、console、file改变着三项任意项的日志等级。
l off、emer、err、warn、info、dbg，这些用来控制日志等级，不低于这些等级的消息蒋辉被记录在日志中，所有低于该等级的将被过滤。参考ovs-appctl查看日志等级的详细定义。
如果没有指定spec， 对于file选项，不论日志等级是否设置，只有当ovs-vswitchd调用 –log-file选项时，日志才会被记录至文件。
为了保持和老版本的ovs的兼容性，any可以作为合法参数但是不会发生作用。 vlog/set PATTERN:facility:pattern 设置应用于每个设施日志的格式，可以参考ovs-appctl查看格式的可用语法信息。 

vlog/list 列出所有支持记录日志的模块和他们当前的日志等级。

vlog/reopen 让ovs-vswitchd关闭并且重新打开日志文件（可以用于在转换日志后，重新建立一个新日志文件来使用）
需要ovs-vswitchd 使能 –log-file选项时才有效 vlog/disable-rate-limit [module]… vlog/enable-rate-limit [module]… 默认情况下，ovs-vswitchd 限制了记录日志的速率。当消息发生的频率高于默认值时，该消息将会被抑制。这将节省磁盘空间，让日志更加可读，并且让进程更加流畅，但是有些情况下的排错需要更多的细节。这样，vlog/disable−rate−limit允许特定独立模块的日志记录不限制在默认速率下。你可以指定一个或多个模块名，这些模块名可以通过vlog/list查看。不指定模块名或者使用any关键字将应用到所有记录日志的模块。 vlog/enable−rate−limit命令，和vlog/disable−rate−limit的语法一样，可以恢复速率限制。 内存命令（MEMORYCOMMANDS） 报告内存的使用率 memory/show 显示一些ovs-vswitchd内存使用的基础状态信息。ovs−vswitchd也会在启动后并且周期性的检测内存的增长
  COVERAGE COMMANDS 这个命令管理ovs−vswitchd的“coverage counters”，即在守护进程运行期间发生的特殊事件的次数。除了使用这个命令意外，当ovs−vswitchd检测到主循环运行周期异常长的时候，会自动以INFO的日志等级记录coverage counters。
主要用于性能分析和debugging。 coverage/show 显示coverage counters值。
```



 ## ovs-vsctl命令

```php
ovs-vsctl show  查看网桥
ovs-vsctl add-br  br-test      添加网桥
ovs-vsctl add-port 网桥名 端口名     创建port
ovs-vsctl del-port br-test enp0s3  删除port
ovs-vsctl del-br br-test           删除网桥
    
配置卸载后记得要ovs-ctl restart
    
### 创建网桥
ovs-vsctl add-br br0
ovs-vsctl set bridge br0 datapath_type=netdev

### 配置连接控制器
ovs-vsctl set-controller br-test tcp:172.171.82.31:6633

ovs-vsctl get-fail-mode br0
ovs-vsctl set-fail-mode br0 secure
ovs-vsctl del-fail-mode br0 
fail_mode 故障模式有两种状态，一种是standalone，一种是secure状态。
standalone(default)：清除所有控制器下发的流表，ovs自己接管 
secure：按照原来流表继续转发

STP是Spanning Tree Protocol的缩写，意思是指生成树协议，可应用于计算机网络中树形拓扑结构建立，主要作用是防止网桥网络中的冗余链路形成环路工作。
ovs-vsctl get bridge s1 stp_enable          获取开启stp协议是否使能
ovs-vsctl set bridge br0 stp_enable=true    设置stp协议开启使能
    
ovs-vsctl list bridge br0					查看网桥配置信息
ovs-vsctl list port s1 s1-eth1 				查看端口配置信息

### 查看老化时间
ovs-vsctl list Open_vSwitch
    
### 查询绑核结果
ovs-vsctl list open-vSwitch

### 初始化ovs-db
ovs-vsctl --no-wait init
    
### 配置端口VLAN
ovs-vsctl set Port s1-eth1 tag=100
ovs-vsctl set Port s1-eth2 tag=200 
    
### 查看老化时间与卸载使能
ovs-vsctl get Open_vSwitch . other_config
    {dpdk-init="true", hw-offload="true", max-idle="10000", max-revalidator="10000"}

### ovs-vsctl set Open_vSwitch . other_config:hw-offload=true
配置卸载后记得要ovs-ctl restart(ovs-ctl的path是否导入)
    export PATH=$PATH:/home/test/ovs/share/openvswitch/scripts/

### 配置smc使能
ovs-vsctl --no-wait set Open_vSwitch .
    other_config:smc-enable=true
        
### emc-insert-prob 值越小，代表插入可能性越高。如果设置为1，则会百分百插入emc表项，如果设置为0，则关闭emc功能。       
ovs-vsctl set Open_vSwitch . other_config:emc-insert-prob=10
    
//读取enable_megaflows，用来控制是否开启megaflow。
//可以通过命令开启 "ovs-appctl upcall/enable-megaflows"
//如果关闭了megaflow，则将flow信息转换到wc，即megaflow也将变成精确匹配。
//如果开启megaflow，则wc查找openflow流表的通配符集合，小于等于flow信息。
```



### 添加端口

\# for system interfaces

ovs-vsctl add-port br0 eth1

ovs-vsctl del-port br0 eth1

\# for DPDK

ovs-vsctl add-port br0 dpdk1 -- set interface dpdk1 type=dpdk options:dpdk-devargs=0000:01:00.0

\# for DPDK bonds

ovs-vsctl add-bond br0 dpdkbond0 dpdk1 dpdk2 \

 -- set interface dpdk1 type=dpdk options:dpdk-devargs=0000:01:00.0 \

 -- set interface dpdk2 type=dpdk options:dpdk-devargs=0000:02:00.0

\# or new version

ovs-vsctl add-port br0 dpdkbond0 \

 -- set interface dpdkbond0 type=dpdk options:dpdk-devargs=0000:01:00.0,0000:02:00.0



### 查看队列

root@SN1000-arm-32:~# ovs-appctl dpif-netdev/pmd-rxq-show
pmd thread numa_id 0 core_id 7:
 isolated : false
 port: dpdk-pf0 queue-id: 0 (enabled) pmd usage: 0 %
 port: dpdk-rep-pf0-vf0 queue-id: 0 (enabled) pmd usage: 0 %
 port: dpdk-rep-pf0-vf1 queue-id: 0 (enabled) pmd usage: 0 %
 overhead: 0 %

root@SN1000-arm-32:~# ovs-vsctl set interface dpdk-pf0 options:n_rxq=2 other_config:pmd-rxq-affinity="0:2,1:4"

root@SN1000-arm-32:~# ovs-appctl dpif-netdev/pmd-rxq-show
pmd thread numa_id 0 core_id 7:
 isolated : false
 port: dpdk-pf0 queue-id: 0 (enabled) pmd usage: NOT AVAIL
 port: dpdk-pf0 queue-id: 1 (enabled) pmd usage: NOT AVAIL
 port: dpdk-rep-pf0-vf0 queue-id: 0 (enabled) pmd usage: NOT AVAIL
 port: dpdk-rep-pf0-vf1 queue-id: 0 (enabled) pmd usage: NOT AVAIL
 overhead: NOT AVAIL



### ovs中port类型

| **类型** | **说明**                                                     |
| -------- | ------------------------------------------------------------ |
| Normal   | 用户可以把操作系统中的网卡绑定到ovs上，ovs会生成一个普通端口处理这块网卡进出的数据包。 |
| Internal | 端口类型为internal时，ovs会创建一块虚拟网卡，虚拟网卡会与端口自动绑定。当ovs创建一个新网桥时，默认会创建一个与网桥同名的Internal Port。 |
| Patch    | 当机器中有多个ovs网桥时，可以使用Patch Port把两个网桥连起来。Patch Port总是成对出现，分别连接在两个网桥上，在两个网桥之间交换数据。 |
| Tunne    | 隧道端口是一种虚拟端口，支持使用gre或vxlan等隧道技术与位于网络上其他位置的远程端口通讯。 |



### 配置流表老化时间

\# 设置流表老化时间为2小时， max-idle单位为毫秒。

ovs-vsctl --no-wait set Open_vSwitch . other_config:max-idle="7200000"



## ovs-ofctl命令

```php

### 配置流表：
ovs-ofctl del-flows br0
ovs-ofctl add-flow br0 in_port=1,action=output:2
ovs-ofctl add-flow br0 dl_src=09:01:27:34:ac:f7,actions=output:2
ovs-ofctl add-flow br0 dl_type=0x0800,nw_src=27.27.27.27,actions=output:2
ovs-ofctl add-flow br0 dl_type=0x0800,nw_src=27.27.27.27/24,actions=output:2
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,dl_src:b6:f3:7f:86:0e:83,actions=output:dpdk1"
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,dl_src:9a:a2:c6:4c:67:a9,actions=output:dpdk1"    
    
### 删除流表：
ovs-ofctl del-flows + 网桥 + 匹配条件
eg:
ovs-ofctl del-flows br0 in_port=1
ovs-ofctl del-flows br0 ip,nw_src=27.27.27.27


### 查看流规则
ovs-ofctl dump-flows br0

### 查看流规则数目
ovs-ofctl dump-flows br0 | wc -l
    
### 查看接口流量统计
ovs-ofctl dump-ports br0
    
### 查看网桥流表
ovs-ofctl dump-flows br-tun | grep 0x222

```

| 字段名称                               | 说明                                                         |
| -------------------------------------- | ------------------------------------------------------------ |
| in_port=port                           | 传递数据包的端口的 OpenFlow 端口编号                         |
| dl_vlan=vlan                           | 数据包的 VLAN Tag 值，范围是 0-4095，0xffff 代表不包含 VLAN Tag 的数据包 |
| dl_vlan_pcp=priority                   | VLAN 优先级，改值取值区间为[0-7]。数字越大，表示优先级越高。 |
| dl_src=<MAC> dl_dst=<MAC>              | 匹配源或者目标的 MAC地址01:00:00:00:00:00/01:00:00:00:00:00 代表广播地址00:00:00:00:00:00/01:00:00:00:00:00 代表单播 |
| dl_type=ethertype                      | 匹配以太网协议类型，其中： dl_type=0x0800 代表 IPv4 协议 dl_type=0x086dd 代表 IPv6 协议 dl_type=0x0806 代表 ARP 协议 |
| nw_src=ip[/netmask]nw_dst=ip[/netmask] | 当 dl_typ=0x0800 时，匹配源或者目标的 IPv4 地址，可以使 IP 地址或者域名 |
| nw_proto=proto                         | 和 dl_type 字段协同使用。当 dl_type=0x0800 时，匹配 IP 协议编号 当 dl_type=0x086dd 代表 IPv6 协议编号 |
| table=number                           | 指定要使用的流表的编号，范围是 0-254。在不指定的情况下，默认值为 0 通过使用流表编号，可以创建或者修改多个 Table 中的 Flow |
| reg<idx>=value[/mask]                  | 交换机中的寄存器的值。当一个数据包进入交换机时，所有的寄存器都被清零，用户可以通过 Action 的指令修改寄存器中的值 |
| tp_src=number                          | TCP/UDP/SCTP 源端口                                          |
| tp_dst=number                          | TCP/UDP/SCTP 目的端口                                        |



### 配置流规则

\#对于入端口是dpdk0，源IP是192.168.0.5的流，修改其源MAC、目的MAC、源IP、目的IP，然后从dpdk1口转发出去

ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,ip,nw_src=192.168.0.5,actions=mod_dl_src:B8:CE:01:01:00:35,mod_dl_dst:B8:EE:01:01:00:88,mod_nw_src:192.169.0.2,mod_nw_dst:5.5.5.5,output:dpdk1"

```javascript
#正常转发（最简转发）`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=output:dpdk1"
ovs-ofctl add-flow br0 "table=0,in_port=dpdk1,actions=output:dpdk0"
 
`#2级流表转发`
ovs-ofctl add-flow br0 "table=0,actions=goto_table=1"
ovs-ofctl add-flow br0 "table=1,in_port=dpdk0,actions=output:dpdk1"
ovs-ofctl add-flow br0 "table=1,in_port=dpdk1,actions=output:dpdk0"
 
`#3级流表转发`
ovs-ofctl add-flow br0 "table=0,actions=goto_table=1"
ovs-ofctl add-flow br0 "table=1,actions=goto_table=2"
ovs-ofctl add-flow br0 "table=2,in_port=dpdk0,actions=output:dpdk1"
ovs-ofctl add-flow br0 "table=2,in_port=dpdk1,actions=output:dpdk0"
 
`#匹配SMAC流转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,ip,dl_src=B8:CE:01:01:00:33,actions=output:dpdk1"
 
`#匹配DMAC流转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,ip,dl_dst=B8:EE:01:01:00:99,actions=output:dpdk1"
 
`#匹配S+DMAC流转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,ip,ip,dl_src=B8:CE:01:01:00:33,dl_dst=B8:EE:01:01:00:99,actions=output:dpdk1"
 
`#匹配VLAN流转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,dl_vlan=100,actions=output:dpdk1"
 
`#匹配SMAC+SIP转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,ip,nw_src=192.168.0.0/32,dl_src=B8:CE:01:01:00:33,actions=output:dpdk1"
 
`#匹配DMAC+DIP转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,ip,nw_dst=3.3.3.3,dl_dst=B8:EE:01:01:00:99,actions=output:dpdk1"
 
`#匹配SMAC+DMAC+SIP+DIP转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,ip,nw_src=192.168.0.0/32,dl_src=B8:CE:01:01:00:33,nw_dst=3.3.3.3,dl_dst=B8:EE:01:01:00:99,actions=output:dpdk1"
 
`#匹配SMAC+DMAC+SIP+DIP+S_TCP+D_TCP转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,tcp,nw_src=192.168.0.0/32,dl_src=B8:CE:01:01:00:33,nw_dst=3.3.3.3,dl_dst=B8:EE:01:01:00:99,tp_src=1024,tp_dst=1024,actions=output:dpdk1"
 
`#匹配SMAC+DMAC+SIP+DIP+S_UCP+D_UCP转发`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,udp,nw_src=192.168.0.0/32,dl_src=B8:CE:01:01:00:33,nw_dst=3.3.3.3,dl_dst=B8:EE:01:01:00:99,tp_src=1024,tp_dst=1024,actions=output:dpdk1"
 
`#加一层vlan`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_vlan_vid:10,output:dpdk1"
 
`#剥一层vlan`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,dl_vlan=100,actions=strip_vlan,output:dpdk1"
 
`#修改单层vlan`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,dl_vlan=100,actions=mod_vlan_vid:10,output:dpdk1"
 
`#修改源mac`
`ovs``-ofctl` `add``-flow` `br0 ``"table=0,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,output:dpdk1"`
 
`#修改目的mac`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_dl_dst:B8:EE:01:01:00:88,output:dpdk1"
 
`#修改源+目的mac`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,mod_dl_dst:B8:EE:01:01:00:88,output:dpdk1"
 
`#修改源mac+vlan`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,mod_vlan_vid:10,output:dpdk1"
 
`#修改源+目的mac+vlan`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,mod_dl_dst:B8:EE:01:01:00:88,mod_vlan_vid:10,output:dpdk1"
 
`#修改源ip`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_nw_src:192.169.0.2,output:dpdk1"
 
`#修改目的ip`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_nw_dst:5.5.5.5,output:dpdk1"
 
`#修改源+目的ip`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_nw_src:192.169.0.2,mod_nw_dst:5.5.5.5,output:dpdk1"
 
`#修改源mac+目的mac+源IP+目的IP`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,mod_dl_dst:B8:EE:01:01:00:88,mod_nw_src:192.169.0.2,mod_nw_dst:5.5.5.5,output:dpdk1"
 
`#修改源mac+目的mac+源IP+目的IP+vlan`
ovs-ofctl add-flow br0 "table=0,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,mod_dl_dst:B8:EE:01:01:00:88,mod_nw_src:192.169.0.2,mod_nw_dst:5.5.5.5,mod_vlan_vid:10,output:dpdk1"
 
`#修改源mac+目的mac+源IP+目的IP+vlan+tcp源端口+tcp目的端口`
ovs-ofctl add-flow br0 "table=0,tcp,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,mod_dl_dst:B8:EE:01:01:00:88,mod_nw_src:192.169.0.2,mod_nw_dst:5.5.5.5,mod_vlan_vid:10,mod_tp_src=1000,mod_tp_dst=1000,output:dpdk1"
 
`#修改源mac+目的mac+目的IP+vlan+tcp源端口+tcp目的端口`
ovs-ofctl add-flow br0 "table=0,tcp,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,mod_dl_dst:B8:EE:01:01:00:88,mod_nw_dst:5.5.5.5,mod_vlan_vid:10,mod_tp_src=1000,mod_tp_dst=1000,output:dpdk1"
 
`#修改源mac+目的mac+目的IP+vlan+tcp目的端口`
ovs-ofctl add-flow br0 "table=0,tcp,in_port=dpdk0,actions=mod_dl_src:B8:CE:01:01:00:35,mod_dl_dst:B8:EE:01:01:00:88,mod_nw_dst:5.5.5.5,mod_vlan_vid:10,mod_tp_dst=1000,output:dpdk1"
```



### 引用组表

```javascript
### 引用组表
ovs-ofctl del-flows s1
ovs-ofctl add-group s1 group_id=1,type=all,bucket=output:2,bucket=output:3,bucket=output:4 -O openflow11

ovs-ofctl add-flow s1 in_port=1,action=group:1 -O openflow11

### 查询组表
ovs-ofctl dump-groups s1 -o openflow11
ovs-ofctl dump-groups s1

```

### meter表

```javascript
### meter表，限速为10k，超过限制的流量丢弃。
ovs-ofctl add-meter s1 meter=1,kbps,band=type=drop,rate=10 -O OpenFlow13
### 匹配进端口为1的流量，经过meter表限速，然后转发到2端口
ovs-ofctl add-flow s1 priority=200,in_port=1,action=meter:1,output:2 -O OpenFlow13


```





# DPDK命令

### 巨页配置信息

dpdk-hugepages.py -c
dpdk-hugepages.py -p 2M --setup 1G
dpdk-hugepages.py -s

dpdk-devbind.py -b uio_pci_generic 0000:01:00.0
dpdk-devbind.py -b uio_pci_generic 0000:01:00.1



### 查询网卡信息

dpdk-devbind.py -s

 

### 绑卡，把网口绑定到用户态

modprobe vfio-pci

lsmod | grep vfio

/usr/bin/chmod a+x /dev/vfio

/usr/bin/chmod 0666 /dev/vfio/*

dpdk-devbind.py --bind=vfio-pci 16:00.0

dpdk-devbind.py --bind=vfio-pci 16:00.1



### 查询设备上CPU的核信息

$RTE_SDK/usertools/cpu_layout.py



## 大页设置

### 设置2M大页

修改/etc/default/grub，如果不存在就创建

vim /etc/default/grub

```plain
GRUB_TIMEOUT=5
GRUB_DISTRIBUTOR="$(sed 's, release .*$,,g' /etc/system-release)"
GRUB_DEFAULT=saved
GRUB_DISABLE_SUBMENU=true
GRUB_TERMINAL_OUTPUT="console"
GRUB_CMDLINE_LINUX="crashkernel=auto resume=/dev/mapper/cl-swap rd.lvm.lv=cl/root rd.lvm.lv=cl/swap rhgb quiet iommu=pt intel_iommu=on pci=assign-busses pci=realloc"
GRUB_CMDLINE_LINUX_DEFAULT="default_hugepagesz=2MB hugepagesz=2M hugepages=2048"
GRUB_DISABLE_RECOVERY="true"
GRUB_ENABLE_BLSCFG=true
```

使修改生效：

grub2-mkconfig -o /boot/grub2/grub.cfg



挂载：

mount -t hugetlbfs none /dev/hugepages



重启服务器：

reboot



同时配置2M和1G大页，可以参考wiki中kally总结的文档。



## 512字节报文rep口单队列ovs转发性能

[测试步骤]: http://wiki.dpu.tech/pages/viewpage.action?pageId=7919621

```javascript
dpdk-hugepages.py -c
rm -rf /dev/hugepages/*

dpdk-hugepages.py -p 2M --setup 2G
dpdk-hugepages.py -s
dpdk-devbind.py -b uio_pci_generic 0000:01:00.0
dpdk-devbind.py -b uio_pci_generic 0000:01:00.1

ovs-ctl start --system-id=random

ovs-vsctl --no-wait del-br br0

ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true

ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

ovs-vsctl add-port br0 dpdk-pf0 -- set interface dpdk-pf0 type=dpdk options:dpdk-devargs="0000:01:00.1,switch_mode=switchdev"

ovs-vsctl set interface dpdk-pf0 options:n_rxq=16
ovs-vsctl add-port br0 rep-eth0 -- set Interface rep-eth0 type=dpdk options:dpdk-devargs="0000:01:00.1,switch_mode=switchdev,representor=[2048]"
ovs-vsctl add-port br0 rep-eth1 -- set Interface rep-eth1 type=dpdk options:dpdk-devargs="0000:01:00.1,switch_mode=switchdev,representor=[2049]"

ovs-ofctl del-flows br0
ovs-ofctl add-flow br0 "table=0,in_port=rep-eth0,actions=output:rep-eth1"
ovs-ofctl add-flow br0 "table=0,in_port=rep-eth1,actions=output:rep-eth0"

以下为控制ovs日志的命令
ovs-appctl vlog/set dpdk:err
ovs-appctl vlog/set poll_loop:off
ovs-appctl vlog/disable-rate-limit dpdk
```

## VXLAN测试步骤

测试步骤http://wiki.dpu.tech/display/Knowledge/vxlan 



# Testpmd测试

```c++
https://ww.sdnlab.com/community/article/dpdk/898

```



# pktgen发包命令

参考wiki中kally写的文档

http://10.10.3.15:8090/pages/viewpage.action?pageId=7909793

perf top -p 3949 -a

# ethtool命令

```javascript
### 查看端口卸载开关
ethtool -k eth1

### 查看端口queue收发信息
ethtool -S eth1

现在我们来看一下网卡的硬中断合并配置。

### ethtool -c eth0
Coalesce parameters for eth0:
Adaptive RX: off  TX: off
......

rx-usecs: 1
rx-frames: 0
rx-usecs-irq: 0
rx-frames-irq: 0
......
我们来说一下上述结果的大致含义

Adaptive RX: 自适应中断合并，网卡驱动自己判断啥时候该合并啥时候不合并

rx-usecs：当过这么长时间过后，一个RX interrupt就会被产生

rx-frames：当累计接收到这么多个帧后，一个RX interrupt就会被产生

如果你想好了修改其中的某一个参数了的话，直接使用ethtool -C就可以，例如：

ethtool -C eth0 adaptive-rx on
不过需要注意的是，减少中断数量虽然能使得Linux整体吞吐更高，不过一些包的延迟也会增大，所以用的时候得适当注意。

### ethotool -s 配合 ip netns使用可以查看收发包
```

# devlink命令

```javascript
### devlink 
```

# lspci命令

```javascript
### lspci -s xx:xx.xx -vvv 
用来查看pcie设备的vpd数据，ID:03H代表的是VPD的CapabilityID



```



# GDB命令

```javascript
### x/<n/f/u> <addr>
eg：x/3uh 0x55555  表示从0x55555处以双字节为一个1个单位(h)、16进制方式(u)现实3个单位(3)的内存。

### watch var

### set 
set *(unsigned char *)p='h'

### jump <linespec> 
跳过某些程序段

### signal <signal>
在gdb的时候的某处产生一个信号量

### return <expression>
强制函数返回，忽略后面没执行的语句,expression会作为返回值。

### call <expr>
强制调用某个函数

### info命令
info register
info all-register
info register <register-name>
info break
info watchpoints
info signals
info handle
info line
info line test.c:func
    
### disassemble 
反汇编函数
```

# 内核调试方式

```javascript
### printk
查看printk打印级别： cat /proc/sys/kernel/printk
设置打印级别： echo 8 > /proc/sys/kernel/printk


### /proc虚拟文件系统
/proc/meminfo 可用内存信息

## 在代码中增加BUG_ON或者WARN_ON机制
DEBUG_LOCKS_WARN_ON(lock->magic != lock);如果异常会抛出栈回溯。

### strace


### sysctl
echo "1" > /proc/sys/net/ipv4/ip_forward
sysctl –w net.ipv4.ip_forward ="1"
sysctl的实现原理是： 所有的内核参数在/proc/sys中形成一个树状结构， sysctl系统调用的内核函数是
sys_sysctl， 匹配项目后， 最后的读写在do_sysctl_strategy中完成


### lspci -s xx:xx.x -vvn 查看是否支持sriov

```

# 红区

```javascript
scp gerrit_spider.py nebulamatrix@10.10.24.107:~/
sftp polo.li@10.10.24.15
```



# 一些名词

```javascript
 # Vital Product Data(VPD)，重要产品数据，是与一组特定硬件或软件相关的配置和信息数据的集合。
 例如部件号（part number），序列号(serial number)，以及设备指定的一些数据。并非系统连接的所有设备都提供VPD，但通常可从PCI和SCSI设备获得。并行ATA和USB设备也提供类似的数据，但不叫VPD。
 
# shadow RAM:影子ram内存
 
 
# VEPA（Virtual Ethernet Port Aggregator虚拟以太网端口汇聚器）
目标是要将虚拟机之间的交换从服务器内部移出到接入交换机上。通过将虚拟机交换移回物理网络，基于VEPA的方法使现有的网络工具和流程可以在虚拟化和非虚拟化环境以及监视程序技术中以相同的方式自由使用。基于VEPA产品可以开放互联，而且可以实现网络和服务器的紧耦合。 
 
# 虚拟以太桥接(VEB, Virtual Ethernet Bridge)
所谓VEB就是在一个物理终端工作站/服务器上支持多个虚拟机的本地交换，通常是由软件模拟一个虚拟交换机来实现。这种软件方案有很明显的缺点：虚拟交换机的功能过于简单，网络和主机管理界面模糊。

# 基于优先级的流控(priority based flow control)

| VSI  | virtual station interface          |
| ---- | ---------------------------------- |
| EVB  | edge virtual bridging 边缘虚拟网桥   |
| ER   | Edge Relay 边缘中继                 |
| TOR  | top of Rack 交换机                  |
| PD   | packet descriptor                  |

```

# 软硬件调试

```javascript
进入ECPU系统；
lspci 是一个用来显示系统中所有PCI总线设备或连接到该总线上的所有设备的工具。
lspci -nn 查看PCI设备

Host bridge:                 <==主板芯片

VGA compatible controller        <==显卡

Audio device                 <==音频设备

PCI bridge                  <==接口插槽

USB Controller                <==USB控制器

ISA bridge                            

IDE interface                        

SMBus                                      

Ethernet controller             <==网卡

 lspci -v查看是否已经绑定驱动

或者ll /sys/bus/pci/drivers/uio_pci_generic

若没有绑定驱动：则执行以下步骤；如果绑定了驱动，则跳过以下步骤；

modprobe uio_pci_generic
echo uio_pci_generic > /sys/bus/pci/devices/0000:01:00.0/driver_override
echo 0000:01:00.0 > /sys/bus/pci/drivers/uio_pci_generic/bind

（5）查看固件版本：fwup -d 0000:01:00.0 –fwversion

sudo su 进入root目录然后查看文件名称
执行升级程序：
fwup -d 0000:01:00.1 -m /root/bootis_top_325M_041100.mcs

HOST冷重启
进入ECPU， lscpi -vvvvv| less，查看05:00.0设备是否已经绑定驱动
若没有绑定驱动：则执行以下步骤；如果绑定了驱动，则跳过以下步骤；

modprobe uio_pci_generic
echo uio_pci_generic > /sys/bus/pci/devices/0000:01:00.0/driver_override
echo 0000:01:00.0 > /sys/bus/pci/drivers/uio_pci_generic/bind

查看升级后的固件版本：fwup -d 0000:01:00.0 –fwversion
固件升级过程中的异常场景处理
1、升级过程异常掉电

重启后，ECPU侧PF会丢失。

恢复手段：重启，用vivado+ jtag 烧写需要升级的固件版本，烧写完拔掉JTAG，重启

2、软件执行过程中状态异常导致升级程序退出

恢复手段：不要重启。 直接用fwup工具选择一个固件版本烧写。

./dpdk-devbind.py -u 3b:00.0 网卡去绑定大页

`4X10G`
 ./nbsp fwup-fpga -d 0000:05:00.0 -m nic_4x10ge_top_2208121400.mcs
 ./x4nbsp fwup-fpga -d 0000:3b:00.0 -m nic_4x10ge_top_2208121400.mcs
10.10.29.47  root 123456

cat /proc/interrupt

./pci_debug -s 05:00.0 [-b 2 选择bar空间，如果是mailbox bar就写2]
	d 12B000 20  读
	c 12B100 66  写
Cherish-earth
    
cd nm-kernel-driver/drivers/net/ethernet/nbl/
[sudo apt install linux-headers-5.13.0-39-generic]
sudo apt remove linux-headers-5.13.0-39-generic 
make -C /usr/src/linux-headers-`uname -r` M=$PWD modules
make -C /usr/src/linux-headers-5.4.0-122-generic M=$PWD modules
5.4.0-122-generic


通过lspci找到需要驱动的设备，比如0000:7b:00.0，并获取vendor id和device id:
Linux~: /home # lspci -n -s 0000:7b:00.0
7b:00.0 0880: 19e5:a122 (rev 21)  (vendor id = 19e5 device id = a1222)


获取设备所在的iommu group
 Linux~xp: /home # readlink /sys/bus/pci/devices/0000\:7b\:00.0/iommu_group
 ../../../kernel/iommu_groups/200 (/sys/kernel/iommu_groups/200/devices/0000\:7b\:00.0)
可见设备所在iommu group是200


```

# GDB

```CQL

##############################################################################
# 启动 GDB
##############################################################################

gdb object                # 正常启动，加载可执行
gdb object core           # 对可执行 + core 文件进行调试
gdb object pid            # 对正在执行的进程进行调试
gdb                       # 正常启动，启动后需要 file 命令手动加载
gdb -tui                  # 启用 gdb 的文本界面（或 ctrl-x ctrl-a 更换 CLI/TUI）


##############################################################################
# 帮助信息
##############################################################################

help                      # 列出命令分类
help running              # 查看某个类别的帮助信息
help run                  # 查看命令 run 的帮助
help info                 # 列出查看程序运行状态相关的命令
help info line            # 列出具体的一个运行状态命令的帮助
help show                 # 列出 GDB 状态相关的命令
help show commands        # 列出 show 命令的帮助


##############################################################################
# 断点
##############################################################################

break main                # 对函数 main 设置一个断点，可简写为 b main
break 101                 # 对源代码的行号设置断点，可简写为 b 101
break basic.c:101         # 对源代码和行号设置断点
break basic.c:foo         # 对源代码和函数名设置断点
break *0x00400448         # 对内存地址 0x00400448 设置断点
info breakpoints          # 列出当前的所有断点信息，可简写为 info break
delete 1                  # 按编号删除一个断点
delete                    # 删除所有断点
clear                     # 删除在当前行的断点
clear function            # 删除函数断点
clear line                # 删除行号断点
clear basic.c:101         # 删除文件名和行号的断点
clear basic.c:main        # 删除文件名和函数名的断点
clear *0x00400448         # 删除内存地址的断点
disable 2                 # 禁用某断点，但是不删除
enable 2                  # 允许某个之前被禁用的断点，让它生效
rbreak {regexpr}          # 匹配正则的函数前断点，如 ex_* 将断点 ex_ 开头的函数
tbreak function|line      # 临时断点
hbreak function|line      # 硬件断点
ignore {id} {count}       # 忽略某断点 N-1 次
condition {id} {expr}     # 条件断点，只有在条件生效时才发生
condition 2 i == 20       # 2号断点只有在 i == 20 条件为真时才生效
watch {expr}              # 对变量设置监视点
info watchpoints          # 显示所有观察点
catch exec                # 断点在exec事件，即子进程的入口地址


##############################################################################
# 运行程序
##############################################################################

run                       # 运行程序
run {args}                # 以某参数运行程序
run < file                # 以某文件为标准输入运行程序
run < <(cmd)              # 以某命令的输出作为标准输入运行程序
run <<< $(cmd)            # 以某命令的输出作为标准输入运行程序
set args {args} ...       # 设置运行的参数
show args                 # 显示当前的运行参数
cont                      # 继续运行，可简写为 c
step                      # 单步进入，碰到函数会进去
step {count}              # 单步多少次
next                      # 单步跳过，碰到函数不会进入
next {count}              # 单步多少次
CTRL+C                    # 发送 SIGINT 信号，中止当前运行的程序
attach {process-id}       # 链接上当前正在运行的进程，开始调试
detach                    # 断开进程链接
finish                    # 结束当前函数的运行
until                     # 持续执行直到代码行号大于当前行号（跳出循环）
until {line}              # 持续执行直到执行到某行
kill                      # 杀死当前运行的函数


##############################################################################
# 栈帧
##############################################################################

bt                        # 打印 backtrace 
frame                     # 显示当前运行的栈帧
up                        # 向上移动栈帧（向着 main 函数）
down                      # 向下移动栈帧（远离 main 函数）
info locals               # 打印帧内的相关变量
info args                 # 打印函数的参数


##############################################################################
# 代码浏览
##############################################################################

list 101                  # 显示第 101 行周围 10行代码
list 1,10                 # 显示 1 到 10 行代码
list main                 # 显示函数周围代码
list basic.c:main         # 显示另外一个源代码文件的函数周围代码
list -                    # 重复之前 10 行代码
list *0x22e4              # 显示特定地址的代码
cd dir                    # 切换当前目录
pwd                       # 显示当前目录
search {regexpr}          # 向前进行正则搜索
reverse-search {regexp}   # 向后进行正则搜索
dir {dirname}             # 增加源代码搜索路径
dir                       # 复位源代码搜索路径（清空）
show directories          # 显示源代码路径


##############################################################################
# 浏览数据
##############################################################################

print {expression}        # 打印表达式，并且增加到打印历史
print /x {expression}     # 十六进制输出，print 可以简写为 p
print array[i]@count      # 打印数组范围
print $                   # 打印之前的变量
print *$->next            # 打印 list
print $1                  # 输出打印历史里第一条
print ::gx                # 将变量可视范围（scope）设置为全局
print 'basic.c'::gx       # 打印某源代码里的全局变量，(gdb 4.6)
print /x &main            # 打印函数地址
x *0x11223344             # 显示给定地址的内存数据
x /nfu {address}          # 打印内存数据，n是多少个，f是格式，u是单位大小
x /10xb *0x11223344       # 按十六进制打印内存地址 0x11223344 处的十个字节
x/x &gx                   # 按十六进制打印变量 gx，x和斜杆后参数可以连写
x/4wx &main               # 按十六进制打印位于 main 函数开头的四个 long 
x/gf &gd1                 # 打印 double 类型
help x                    # 查看关于 x 命令的帮助
info locals               # 打印本地局部变量
info functions {regexp}   # 打印函数名称
info variables {regexp}   # 打印全局变量名称
ptype name                # 查看类型定义，比如 ptype FILE，查看 FILE 结构体定义
whatis {expression}       # 查看表达式的类型
set var = {expression}    # 变量赋值
display {expression}      # 在单步指令后查看某表达式的值
undisplay                 # 删除单步后对某些值的监控
info display              # 显示监视的表达式
show values               # 查看记录到打印历史中的变量的值 (gdb 4.0)
info history              # 查看打印历史的帮助 (gdb 3.5)


##############################################################################
# 目标文件操作
##############################################################################

file {object}             # 加载新的可执行文件供调试
file                      # 放弃可执行和符号表信息
symbol-file {object}      # 仅加载符号表
exec-file {object}        # 指定用于调试的可执行文件（非符号表）
core-file {core}          # 加载 core 用于分析


##############################################################################
# 信号控制
##############################################################################

info signals              # 打印信号设置
handle {signo} {actions}  # 设置信号的调试行为
handle INT print          # 信号发生时打印信息
handle INT noprint        # 信号发生时不打印信息
handle INT stop           # 信号发生时中止被调试程序
handle INT nostop         # 信号发生时不中止被调试程序
handle INT pass           # 调试器接获信号，不让程序知道
handle INT nopass         # 调试器不接获信号
signal signo              # 继续并将信号转移给程序
signal 0                  # 继续但不把信号给程序


##############################################################################
# 线程调试
##############################################################################

info threads              # 查看当前线程和 id
thread {id}               # 切换当前调试线程为指定 id 的线程
break {line} thread all   # 所有线程在指定行号处设置断点
thread apply {id..} cmd   # 指定多个线程共同执行 gdb 命令
thread apply all cmd      # 所有线程共同执行 gdb 命令
set schedule-locking ?    # 调试一个线程时，其他线程是否执行，off|on|step
set non-stop on/off       # 调试一个线程时，其他线程是否运行
set pagination on/off     # 调试一个线程时，分页是否停止
set target-async on/off   # 同步或者异步调试，是否等待线程中止的信息


##############################################################################
# 进程调试
##############################################################################

info inferiors                       # 查看当前进程和 id
inferior {id}                        # 切换某个进程
kill inferior {id...}                # 杀死某个进程
set detach-on-fork on/off            # 设置当进程调用fork时gdb是否同时调试父子进程
set follow-fork-mode parent/child    # 设置当进程调用fork时是否进入子进程


##############################################################################
# 汇编调试
##############################################################################

info registers            # 打印普通寄存器
info all-registers        # 打印所有寄存器
print/x $pc               # 打印单个寄存器
stepi                     # 指令级别单步进入，可以简写为 si
nexti                     # 指令级别单步跳过，可以简写为 ni
display/i $pc             # 监控寄存器（每条单步完以后会自动打印值）
x/x &gx                   # 十六进制打印变量
info line 22              # 打印行号为 22 的内存地址信息
info line *0x2c4e         # 打印给定内存地址对应的源代码和行号信息
disassemble {addr}        # 对地址进行反汇编，比如 disassemble 0x2c4e


##############################################################################
# 历史信息
##############################################################################

show commands             # 显示历史命令 (gdb 4.0)
info editing              # 显示历史命令 (gdb 3.5)
ESC-CTRL-J                # 切换到 Vi 命令行编辑模式
set history expansion on  # 允许类 c-shell 的历史
break class::member       # 在类成员处设置断点
list class:member         # 显示类成员代码
ptype class               # 查看类包含的成员
print *this               # 查看 this 指针


##############################################################################
# 其他命令
##############################################################################

define command ... end    # 定义用户命令
<return>                  # 直接按回车执行上一条指令
shell {command} [args]    # 执行 shell 命令
source {file}             # 从文件加载 gdb 命令
quit                      # 退出 gdb


##############################################################################
# GDB 前端
##############################################################################

gdb-tui                   使用 gdb -tui 启动（或 ctrl-x ctrl-a 更换 CLI/TUI）
cgdb                      http://cgdb.github.io/
emacs                     http://gnu.org/software/emacs
gdbgui                    https://github.com/cs01/gdbgui

GDB 图形化前端评测        http://www.skywind.me/blog/archives/2036


##############################################################################
# References
##############################################################################

https://sourceware.org/gdb/current/onlinedocs/gdb/
https://kapeli.com/cheat_sheets/GDB.docset/Contents/Resources/Documents/index
http://www.yolinux.com/TUTORIALS/GDB-Commands.html
https://gist.github.com/rkubik/b96c23bd8ed58333de37f2b8cd052c30
http://security.cs.pub.ro/hexcellents/wiki/kb/toolset/gdb


# vim: set ts=4 sw=4 tw=0 noet ft=gdb:
```

# Git

```C

##############################################################################
# 配置
##############################################################################
git config --global "Your Name"
git config --global "Email Address"
git config --global credential.helper store    保存密码(每次要输密码/重复输密码)


##############################################################################
# 初始化
##############################################################################
git init


##############################################################################
# 提交修改
##############################################################################
git add <file>
git add -u 提交work directory中所有已track的文件至staging area
git commit -m "descriptions"
git commit --amend 对最近一次的提交做内容修改
git commit --amend --author "user_name <user_email>" 修改最近提交用户名和邮箱


##############################################################################
# 查看状态、比对
##############################################################################
git status
git status -s 文件状态缩略信息, 常见 A:新增; M:文件变更; ?:未track; D:删除
git diff <file>
git diff HEAD -- <file>                 查看工作区和版本库里面最新版本的区别
git diff --check <file>                 检查是否有空白错误(regex:' \{1,\}$')
git diff --cached <file>                查看已add的内容(绿M)
git diff branch1 branch2 --stat         查看两个分支差异
git diff branch1 branch2 <file...>      查看分支文件具体差异

##############################################################################
# 查看历史版本、历史操作
##############################################################################
git log
git reflog
git log -n                  最近n条的提交历史
git log <branch_name> -n    分支branch_name最近n条的提交历史
git log --stat              历次commit的文件变化
git log --shortstat         对比--stat只显示最后的总文件和行数变化统计(n file changed, n insertions(+), n deletion(-))
git log --name-status       显示新增、修改、删除的文件清单
git log lhs_hash..rhs_hash  对比两次commit的变化(增删的主语为lhs, 如git log HEAD~2..HEAD == git log HEAD -3)
git log -p                  历次commit的内容增删
git log -p -W               历次commit的内容增删, 同时显示变更内容的上下文
git log origin/EI-1024 -1 --stat -p -W 查看远端分支EI-1024前一次修改的详细内容
git log origin/master..dev --stat -p -W 查看本地dev分支比远端master分支变化(修改)的详细内容

git log <branch_name> --oneline   对提交历史单行排列
git log <branch_name> --graph     对提交历史图形化排列
git log <branch_name> --decorate  对提交历史关联相关引用, 如tag, 本地远程分支等
git log <branch_name> --oneline --graph --decorate 拼接一下, 树形化显示历史
git log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen%ai(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit 同上, 建议alais保存

git log --pretty=format 常用的选项(摘自progit_v2.1.9)
%H 提交对象（commit）的完整哈希字串
%h 提交对象的简短哈希字串
%T 树对象（tree）的完整哈希字串
%t 树对象的简短哈希字串
%P 父对象（parent）的完整哈希字串
%p 父对象的简短哈希字串
%an 作者（author）的名字
%ae 作者的电子邮件地址
%ad 作者修订日期（可以用 --date= 选项定制格式）
%ar 作者修订日期，按多久以前的方式显示
%cn 提交者（committer）的名字
%ce 提交者的电子邮件地址
%cd 提交日期
%cr 提交日期，按多久以前的方式显示
%s 提交说明

git log --since --after     显示时间之后的提交
git log --until --before    显示时间之前的提交
git --author                显示指定作者的提交
git --committer             显示指定committer的提交(注:committer不一定是author)
git log -S [keyword]        仅显示添加或移除了某个关键字的提交(某些场景比单独git log -p | grep [keyword] 好用很多)
git log origin/b3.3/master --author=yx-ren --since="2019-10-01" --before="2019-11-01" 查看某作者在某发布版本最近一个月的提交, 常见于线上背锅
git log origin/b3.0/master --author=some_leave --since="1 month ago" 查看某刚离职同事过去一个月的提交, 常见于背锅
git log --since=1.weeks     过去一周的提交(写周报的时候可以看看我这一周干了啥)
git log --since=1.days      过去一天的提交(下班的时候可以看看我这一天干了啥)
git log --since="1 weeks 2 days 3 hours 40 minutes 50 seconds ago" 过去1周2天3小时40分50秒之内的提交


##############################################################################
# 版本回退、前进
##############################################################################
git reset --hard HEAD^      回退到上1版本
git reset --hard HEAD~5     回退到上5个版本
git reset --hard id         回退到指定版本


##############################################################################
# 撤销修改
##############################################################################
git checkout -- <file>      撤销修改：误修改工作区文件，未git add/commit
git restore <file>          撤销修改：误修改工作区文件，未git add/commit
git reset HEAD <file>       撤销git add：误将文件加入暂存区（git add），未git commit
git reset --hard HEAD^      撤销git commit：误将文件提交（一旦提交，只能通过版本回退进行撤销）


##############################################################################
# 删除与恢复
##############################################################################
git rm/add <file>
git commit -m "remove <file>"   删除版本库中的<file>：删除工作区文件后，继续删除版本库中相应的文件
git checkout -- <file>          根据版本库中的<file>恢复工作区<file>
git restore <file>              对于 checkout -- <file> 的新写法 (2.23 引入)

##############################################################################
# 清理工作区未track也未ignore的文件或文件夹(如各种临时.swp, .patch文件等)
##############################################################################
git clean -i    #交互式清理, 不常用
git clean -n    #查看清理文件列表(不包括文件夹), 不执行实际清理动作
git clean -n -d #查看清理文件列表(包括文件夹), 不执行实际清理动作
git clean -f    #清理所有未track文件
git clean -df   #清理所有未track文件和文件夹, 常用, 但使用前确保新增加的文件或文件夹已add, 否则新创建的文件或者文件夹也会被强制删除

##############################################################################
# 关联GitHub远程仓库（本地到远程）
##############################################################################
git remote add origin <remote address>    在本地工作区目录下按照 GitHub 提示进行关联
git remote rm origin                      解除错误关联
git push -u origin master                 第一次将本地仓库推送至远程仓库（每次在本地提交后进行操作）
git push origin master                    以后每次将本地仓库推送至远程仓库（每次在本地提交后进行操作）
<remote address>:
    git@github.com:<username>/<repository>.git
    https://github.com/<username>/<repository>.git


##############################################################################
# 克隆GitHub远程仓库（远程到本地）
##############################################################################
git clone <remote address>    git协议速度更快但通常公司内网不允许，https协议速度慢


##############################################################################
# 分支管理：创建、切换、查看、合并、删除
##############################################################################
git branch <branch name>            创建<branch name>分支
git checkout <branch name>          切换至<branch name>分支
git switch <branch name>            切换至<branch name>分支 (2.23 引入)
git checkout -b <branch name>       创建并切换至<branch name>分支
git switch -c <branch name>         创建并切换至<branch name>分支
git branch                          查看已有分支（* 表示当前分支）
git merge <branch name>             合并<branch name>到当前分支（通常在master分支下操作）
git merge --no-commit <branch name> 合并<branch name>到当前分支，但不提交
git branch -d <branch name>         删除分支
git branch -m oldbranchname newname 重命名分支


##############################################################################
# 解决合并冲突
##############################################################################
合并时报错“分支发生冲突”，首先vim相应文件，修改冲突位置，然后按照git add/commit重新提交，最后删除多余分支即可。
git log --graph --pretty=oneline --abbrev-commit
git log --graph


##############################################################################
# 分支管理：合并后删除分支也在 log 中保留分支记录
##############################################################################
git merge --no-ff -m "descriptions" <branch name>


##############################################################################
# 开发流程：
##############################################################################
master分支              发布稳定版本
dev分支                 发布开发版本
<developer name>分支    个人开发分支（个人开发完成将该分支并入dev，同时保留该分支，继续开发）


##############################################################################
# Bug分支管理（建立单独分支进行bug修复）
##############################################################################
软件开发中，bug就像家常便饭一样。有了bug就需要修复，在Git中，由于分支是如此的强大，所以，每个bug都可以通过一个新的临时分支来修复，修复后，合并分支，然后将临时分支删除。
git stash                   保存当前工作现场（在dev未完成开发，但master有bug需要修复）
git stash pop               回到dev分支后恢复工作现场（list中的现场会同时被删除）
git stash list              查看当前存储的工作现场
git stash apply stash@{#}   回到指定工作现场（list中的现场不会被删除，需要用git stash drop）
git stash drop stash@{#}    删除指定工作现场
git cherry-pick <id>        在master修复好bug后，在dev复制一遍bug修复流程


##############################################################################
# Feature分支管理（建立单独分支添加新功能）
##############################################################################
软件开发中，总有无穷无尽的新的功能要不断添加进来。添加一个新功能时，你肯定不希望因为一些实验性质的代码，把主分支搞乱了，所以，每添加一个新功能，最好新建一个feature分支，在上面开发，完成后，合并，最后，删除该feature分支。
git branch -D <branch name>    强制删除分支（丢弃未合并分支）


##############################################################################
# 协作与分支推送
##############################################################################
User 1:
git remote [-v]                        查看远程库信息（-v 查看详细信息）
git remote update origin --prune       更新分支列表(更新远程分支列表)
git remote update origin -p            更新分支列表(更新远程分支列表)
git push origin [master/dev/...]       推送指定分支到远程
User 2:
git clone <remote address>             克隆到本地（只能克隆master）
git checkout -b dev origin/dev         本地新建分支并关联远程
git add/commit/push                    添加、提交、推送更新
User 1:
git add/commit/push                    推送时报错（与user 2推送的更新冲突）
git pull <remote> <branch>
git branch --set-upstream-to=origin/<branch> <branch>    本地与远程关联
git pull                               拉取远程文件（并解决冲突）
git commit/push                        重新提交并推送


##############################################################################
# 标签管理（常用于版本管理）：查看、创建、操作
##############################################################################
git tag                                                     查看标签
git show <tag name>                                         查看指定标签
git log --pretty=oneline --abbrev-commit --decorate=full    在log中显示标签
git tag <tag name>                                          为上次commit位置打标签
git tag <tag name> <commit id>                              为指定commit位置打标签
git tag -a <tag name> -m "descriptions" <commit id>         为指定commit打标并添加描述
git tag -d <tag name>                                       删除本地标签
git push origin <tag name>                                  推送指定标签到远程
git push origin --tags                                      推送所有本地标签到远程
git push origin :refs/tags/<tag name>                       删除远程标签（先删除本地标签）

##############################################################################
# rebase(换基)
##############################################################################
# rebase 在日常中常用功能主要是两个, 多人协同开发定期rebase master以及压缩某分支多个commit
git rebase master 常见于多人开发, 每个开发人员从master checkout出自己的分支, 开发一段时间后提交至master之前最好rebase一下, 防止冲突,
              就算真有冲突在本地解决好过强制提交, 开发流程中尽量保证master的干净整洁

举个例子:
master分支上有三个提交C1, C2, C3
某一时刻usr1在C3的master分支上checkout出新的分支, 用于开发服务端支持ipv6新特性, 并提交了C4, C5
git checkout -b ipv6_support
......
git commit -m C4
......
git commit -m C5
此时提交状态如下所示
      (origin/master branch)
             |
C1 <- C2 <- C3
             \
              \
               \
                C4 <- C5
                       |
                (ipv6_support branch)

某同事usr2修改了master上的内存泄漏错误, 并提交了C6, C7, C8三个commit, 然后直接推送origin/master(假设这个期间无其他人推新内容到master)
此时提交状态如下所示
                    (origin/usr2/fix_mem_leak branch)
                               |
C1 <- C2 <- C3 <- C6 <- C7 <- C8
             \                 |
              \         (origin/master branch)
               \
                C4 <- C5
                       |
                (ipv6_support branch)

如果此时usr1希望将ipv6的新特性提交至master, 那么在其直接push origin master时会提示master需要合并分支ipv6_support
虽然C4, C5的改动内容完全独立于C6, C7, C8的改动
但git仍会抓取C5和C8的提交并产生一个新的C9 commit(因两者分支的base不同), 如下图所示
C1 <- C2 <- C3 <- C6 <- C7 <- C8
             \                 \
              \                 \
               \                 \
                C4 <- C5 <------ C9

如果是为了保证master提交记录的"干净完整"
或者是某分支不着急提交, 仍需要更多的测试与开发, 但又不想分支开发周期结束后"偏离"当初checkout的master分支太久远(容易造成更多的冲突)
可以考虑(定期)利用rebase来进行变基
即上面提到过的多人协同开发, 定期rebase master是个好习惯
git checkout ipv6_support
git rebase master
结果提交状态如下所示
            (origin/master origin/usr2/fix_mem_leak branch)
                               |
C1 <- C2 <- C3 <- C6 <- C7 <- C8
                                \
                                 \
                                  \
                                   C4' <- C5'
                                           |
                                    (ipv6_support branch)
这种rebase在功能上类似将某分支所有的改动做成多个patch并依次打在指定的新base上
此时再提交master就不会产生抓取效果, 会将C4'和C5'直接提交至master, 即can be fast-forwarded, 同时也保证了master提交记录的整洁性
(注: 虽然C4'和C5'的内容和C4, C5完全一致, 但两者base不同, commit hash code也完全不同)

git rebase --noto <branch_lhs> <branch_rhs> #重放, 用于变基在分支branch_lhs中而不在branch_rhs中的commit
#某项目状态分支如下所示, 其中Cn的数字代表提交时间顺
# T1 某员工urs1从C2(master分支)checkout出一个新的分支用于开发某基础公共组件功能
# T2 员工usr1开发完毕提交C3, 然后继续在该分支上(或checkout -b server)开发服务端相关功能, 并提交C4
# T3 master分支有更新, 其他同事usr2提交了C5, C6并推送到了origin master
# T4 员工usr1从server分支切回到C3公共基础的提交, 并创建新分支client, 用于开发客户端功能, 并提交C8, C9
# T5 员工usr1从client分支切回到server分支继续开发服务端功能, 并提交C10
            (master branch)
                   |
C1 <- C2 <- C5 <- C6
         \
          \
           \
            C3 <- C4 <- C10
               \         |
                \ (server branch)
                 \
                  C8 <- C9
                         |
                  (client branch)

# 此时该员工希望将客户端相关的功能合并到主分支并发布，但暂时并不想合并 server 中的修改，因为它们还需要经
# 过更全面的测试。 这时可以使用 git rebase 命令的 --onto 选项，选中在 client 分支里但不在
# server 分支里的修改（即 C8 和 C9），将它们在 master 分支上重放：

git rebase --noto client server
# 得到如下图所示的提交状态
# 注:其中C3', C8', C9'与C3, C8, C9的提交内容完全一样, 但是hash id是完全不同的
            (master branch)(client branch)
                   |            |
C1 <- C2 <- C5 <- C6 <- C8' <- C9'
         \
          \
           \
            C3 <- C4 <- C10
               \         |
                \ (server branch)
                 \
               [#####disable######]
               [  C8 <- C9        ]
               [         |        ]
               [  (client branch) ]

#can be fast-forwarded
git checkout master
git merge client
# 提交后分支状态如下
                                (client branch)
                                       |
C1 <- C2 <- C5 <- C6 <- C3' <- C8' <- C9'
         \                             |
          \                     (master branch)
           \
            C3 <- C4 <- C10
                         |
                  (server branch)

git rebase -i HEAD~n 压缩当前分支的n个commit并合并为1个commit, 常见第一行为pick, 剩下的n-1行为squash

git rebase --abort # rebase过程中发生错误, 可以利用该命令终止整个rebase过程
git rebase --continue # rebase过程中发生冲突, 在解决冲突后可以利用该命令进行后续过程

##############################################################################
# 打patch(补丁)
##############################################################################
# 生成diff patch文件(git可以识别diff文件)
git <branch> log -n -p > diff.patch # 生成某分支过去n个commit的文件diff信息至单个diff文件
git diff <--cached> diff.patch # 针对当前缓存区的内容生成diff文件

# 利用apply打patch
git apply --check diff.patch    #检查是否可以正常应用, 无回显证明无冲突
git apply --stat diff.patch     #查看应用diff文件后的文件变化
git apply diff.patch            #打patch, 仅仅改变文件信息, 无commit信息, 仍然需要add, commit

# 利用--format-patch生成patch, 带commit信息
git format-patch <branch> -n 　 #生成分支<branch>最近的n次commit的patch
git format-patch <r1>..<r2>     #生成两个commit间的修改的patch（包含两个commit. <r1>和<r2>都是具体的commit号)
git format-patch -1 <r1>        #生成单个commit的patch
git format-patch <r1>           #生成某commit以来的修改patch（不包含该commit）
git format-patch --root <r1>　　#生成从根到r1提交的所有patch

# 利用am打patch
git apply --check 0001-update-bash.sh.patch #检查patch是否冲突可用
git apply --stat 0001-update-bash.sh.patch  #检查patch文件变更情况, 无回显证明无冲突
git am 0001-update-bash.sh.patch            #将该patch打上到当前分支, 带commit信息
git am ./*.patch                            #将当前路径下的所有patch按照先后顺序打上
git am --abort                              #终止整个打patch的过程, 类似rebase --abort
git am --resolved                           #解决冲突后, 可以执行该命令进行后续的patch, 类似rebase --continue

##############################################################################

##############################################################################
# bundle(打包)
##############################################################################
# 该命令会将git工程打包, 默认情况下会打包所有commit记录和track的文件
# 不同于简单粗暴tar.gz打包整个文件夹, bundle只打包那些push过的记录
# 如某git工程下存在.build构建后的目录, 而.gitignore又忽略了该文件夹
# 如果利用tar.gz打包则会将那些忽略的文件文件夹一并打包, 可能会造成压缩包极大的臃肿
# 而又不想仅仅为了打个包就删除整个build目录(如重新build时间成本太大)
# 那么就可以使用bundle进行打包, 该命令只打包track过的文件
# 并且像url那样直接调用git clone来重建
git bundle create awesome-cheatsheets.bundle HEAD master #打包重建master分支的所有数据
git clone awesome-cheatsheets.bundle # 重建工程

# bundle也可以打包指定的区间, 至于提交区间有多种表示方式
git bundle create awesome-cheatsheets.bundle HEAD~10
git bundle create awesome-cheatsheets.bundle HEAD~10..HEAD
git bundle create awesome-cheatsheets.bundle lhs_commit_md5..rhs_commit_md5
git bundle create awesome-cheatsheets.bundle origin/master..master
git bundle create awesome-cheatsheets.bundle master ^origin/master


##############################################################################
# 使用GitHub
##############################################################################
fork --> clone --> add/commit/push --> pull request


##############################################################################
# 其他配置
##############################################################################
git config --global color.ui true    显示颜色


##############################################################################
# 配置.gitignore文件
##############################################################################
/<dir name>/                    忽略文件夹
*.zip                           忽略.zip文件
/<dir name>/<file name>         忽略指定文件


##############################################################################
# 文件.gitignore生效后
##############################################################################
git add -f <file>               强制添加
git check-ignore -v <file>      查看生效规则


##############################################################################
# 配置别名
##############################################################################
git config [--global] alias.<alias> '<original command>'    为所有工作区/当前工作区配置别名
.git/config             当前工作区的配置文件
~/.gitconfig            当前用户的配置文件


##############################################################################
# References
##############################################################################
https://www.liaoxuefeng.com/wiki/896043488029600
https://git-scm.com/book/en/v2
```

# VIM

```javascript

##############################################################################
# 光标移动
##############################################################################

h                   光标左移，同 <Left> 键
j                   光标下移，同 <Down> 键
k                   光标上移，同 <Up> 键
l                   光标右移，同 <Right> 键
CTRL-F              下一页
CTRL-B              上一页
CTRL-U              上移半屏
CTRL-D              下移半屏
0                   跳到行首（是数字零，不是字母O），效用等同于 <Home> 键
^                   跳到从行首开始第一个非空白字符
$                   跳到行尾，效用等同于 <End> 键
gg                  跳到第一行，效用等同于 CTRL+<Home>
G                   跳到最后一行，效用等同于 CTRL+<End>
nG                  跳到第n行，比如 10G 是移动到第十行
:n                  跳到第n行，比如 :10<回车> 是移动到第十行
10%                 移动到文件 10% 处
15|                 移动到当前行的 15列
w                   跳到下一个单词开头 (word: 标点或空格分隔的单词)
W                   跳到下一个单词开头 (WORD: 空格分隔的单词)
e                   跳到下一个单词尾部 (word: 标点或空格分隔的单词)
E                   跳到下一个单词尾部 (WORD: 空格分隔的单词)
b                   上一个单词头 (word: 标点或空格分隔的单词)
B                   上一个单词头 (WORD: 空格分隔的单词)
ge                  上一个单词尾
)                   向前移动一个句子（句号分隔）
(                   向后移动一个句子（句号分隔）
}                   向前移动一个段落（空行分隔）
{                   向后移动一个段落（空行分隔）
<enter>             移动到下一行首个非空字符
+                   移动到下一行首个非空字符（同回车键）
-                   移动到上一行首个非空字符
H                   移动到屏幕上部
M                   移动到屏幕中部
L                   移动到屏幕下部
fx                  跳转到下一个为 x 的字符，2f/ 可以找到第二个斜杆
Fx                  跳转到上一个为 x 的字符
tx                  跳转到下一个为 x 的字符前
Tx                  跳转到上一个为 x 的字符前
;                   跳到下一个 f/t 搜索的结果
,                   跳到上一个 f/t 搜索的结果
<S-Left>            按住 SHIFT 按左键，向左移动一个单词
<S-Right>           按住 SHIFT 按右键，向右移动一个单词
<S-Up>              按住 SHIFT 按上键，向上翻页
<S-Down>            按住 SHIFT 按下键，向下翻页
gm                  移动到行中
gj                  光标下移一行（忽略自动换行）
gk                  光标上移一行（忽略自动换行）


##############################################################################
# 插入模式：进入退出
##############################################################################

i                   在光标处进入插入模式
I                   在行首进入插入模式
a                   在光标后进入插入模式
A                   在行尾进入插入模式
o                   在下一行插入新行并进入插入模式
O                   在上一行插入新行并进入插入模式
gi                  进入到上一次插入模式的位置
<ESC>               退出插入模式
CTRL-[              退出插入模式（同 ESC 等价，但更顺手）


##############################################################################
# INSERT MODE - 由 i, I, a, A, o, O 等命令进入插入模式后
##############################################################################

<Up>                光标向上移动
<Down>              光标向下移动
<Left>              光标向左移动
<Right>             光标向右移动
<S-Left>            按住 SHIFT 按左键，向左移动一个单词
<S-Right>           按住 SHIFT 按右键，向右移动一个单词
<S-Up>              按住 SHIFT 按上键，向上翻页
<S-Down>            按住 SHIFT 按下键，向下翻页
<PageUp>            上翻页
<PageDown>          下翻页
<Delete>            删除光标处字符
<BS>                Backspace 向后删除字符
<Home>              光标跳转行首
<End>               光标跳转行尾
CTRL-W              向前删除单词
CTRL-O              临时退出插入模式，执行单条命令又返回插入模式
CTRL-\ CTRL-O       临时退出插入模式（光标保持），执行单条命令又返回插入模式
CTRL-R 0            插入寄存器（内部 0号剪贴板）内容，CTRL-R 后可跟寄存器名
CTRL-R "            插入匿名寄存器内容，相当于插入模式下 p粘贴
CTRL-R =            插入表达式计算结果，等号后面跟表达式
CTRL-R :            插入上一次命令行命令
CTRL-R /            插入上一次搜索的关键字
CTRL-F              自动缩进
CTRL-U              删除当前行所有字符
CTRL-V {char}       插入非数字的字面量
CTRL-V {number}     插入三个数字代表的 ascii/unicode 字符
CTRL-V 065          插入 10进制 ascii 字符（两数字） 065 即 A字符
CTRL-V x41          插入 16进制 ascii 字符（三数字） x41 即 A字符
CTRL-V o101         插入  8进制 ascii 字符（三数字） o101 即 A字符
CTRL-V u1234        插入 16进制 unicode 字符（四数字）
CTRL-V U12345678    插入 16进制 unicode 字符（八数字）
CTRL-K {ch1} {ch2}  插入 digraph（见 :h digraph），快速输入日文或符号等
CTRL-D              文字向前缩进
CTRL-T              文字向后缩进


##############################################################################
# 文本编辑
##############################################################################

r                   替换当前字符
R                   进入替换模式，直至 ESC 离开
s                   替换字符（删除光标处字符，并进入插入模式，前可接数量）
S                   替换行（删除当前行，并进入插入模式，前可接数量）
cc                  改写当前行（删除当前行并进入插入模式），同 S
cw                  改写光标开始处的当前单词
ciw                 改写光标所处的单词
caw                 改写光标所处的单词，并且包括前后空格（如果有的话）
c0                  改写到行首
c^                  改写到行首（第一个非零字符）
c$                  改写到行末
C                   改写到行尾（同c$）
ci"                 改写双引号中的内容
ci'                 改写单引号中的内容
cib                 改写小括号中的内容
cab                 改写小括号中的内容（包含小括号本身）
ci)                 改写小括号中的内容
ci]                 改写中括号中内容
ciB                 改写大括号中内容
caB                 改写大括号中的内容（包含大括号本身）
ci}                 改写大括号中内容
cit                 改写 xml tag 中的内容
cis                 改写当前句子
c2w                 改写下两个单词
ct(                 改写到小括号前
c/apple             改写到光标后的第一个apple前
x                   删除当前字符，前面可以接数字，3x代表删除三个字符
X                   向前删除字符
dd                  删除当前行
d0                  删除到行首
d^                  删除到行首（第一个非零字符）
d$                  删除到行末
D                   删除到行末（同 d$）
dw                  删除当前单词
diw                 删除光标所处的单词
daw                 删除光标所处的单词，并包含前后空格（如果有的话）
di"                 删除双引号中的内容
di'                 删除单引号中的内容
dib                 删除小括号中的内容
di)                 删除小括号中的内容
dab                 删除小括号内的内容（包含小括号本身）
di]                 删除中括号中内容
diB                 删除大括号中内容
di}                 删除大括号中内容
daB                 删除大括号内的内容（包含大括号本身）
dit                 删除 xml tag 中的内容
dis                 删除当前句子
dip                 删除当前段落(前后有空白行的称为一个段落)
dap                 删除当前段落(包括前后空白行)
d2w                 删除下两个单词
dt(                 删除到小括号前
d/apple             删除到光标后的第一个apple前
dgg                 删除到文件头部
dG                  删除到文件尾部
d}                  删除下一段
d{                  删除上一段
u                   撤销
U                   撤销整行操作
CTRL-R              撤销上一次 u 命令
J                   链接多行为一行
.                   重复上一次操作
~                   替换大小写
g~iw                替换当前单词的大小写
gUiw                将单词转成大写
guiw                将当前单词转成小写
guu                 全行转为小写
gUU                 全行转为大写
<<                  减少缩进
>>                  增加缩进
==                  自动缩进
CTRL-A              增加数字
CTRL-X              减少数字


##############################################################################
# 复制粘贴
##############################################################################

p                   粘贴到光标后
P                   粘贴到光标前
v                   开始标记
y                   复制标记内容
V                   开始按行标记
CTRL-V              开始列标记
y$                  复制当前位置到本行结束的内容
yy                  复制当前行
Y                   复制当前行，同 yy
yiw                 复制当前单词
3yy                 复制光标下三行内容
v0                  选中当前位置到行首
v$                  选中当前位置到行末
viw                 选中当前单词
vib                 选中小括号内的东西
vi)                 选中小括号内的东西
vi]                 选中中括号内的东西
viB                 选中大括号内的东西
vi}                 选中大括号内的东西
vis                 选中句子中的东西
vip                 选中当前段落(前后有空白行的称为一个段落)
vap                 选中当前段落(包括前后空白行)
vab                 选中小括号内的东西（包含小括号本身）
va)                 选中小括号内的东西（包含小括号本身）
va]                 选中中括号内的东西（包含中括号本身）
vaB                 选中大括号内的东西（包含大括号本身）
va}                 选中大括号内的东西（包含大括号本身）
gv                  重新选择上一次选中的文字
:set paste          允许粘贴模式（避免粘贴时自动缩进影响格式）
:set nopaste        禁止粘贴模式
"?yy                复制当前行到寄存器 ? ，问号代表 0-9 的寄存器名称
"?d3j               删除光标下三行内容，并放到寄存器 ? ，问号代表 0-9 的寄存器名称
"?p                 将寄存器 ? 的内容粘贴到光标后
"?P                 将寄存器 ? 的内容粘贴到光标前
:registers          显示所有寄存器内容
:[range]y           复制范围，比如 :20,30y 是复制20到30行，:10y 是复制第十行
:[range]d           删除范围，比如 :20,30d 是删除20到30行，:10d 是删除第十行
ddp                 交换两行内容：先删除当前行复制到寄存器，并粘贴
"_[command]         使用[command]删除内容，并且不进行复制（不会污染寄存器）
"*[command]         使用[command]复制内容到系统剪贴板（需要vim版本有clipboard支持）


##############################################################################
# 文本对象 - c,d,v,y 等命令后接文本对象，一般为：<范围 i/a><类型>
##############################################################################

$                   到行末
0                   到行首
^                   到行首非空字符
tx                  光标位置到字符 x 之前
fx                  光标位置到字符 x 之处
iw                  整个单词（不包括分隔符）
aw                  整个单词（包括分隔符）
iW                  整个 WORD（不包括分隔符）
aW                  整个 WORD（包括分隔符）
is                  整个句子（不包括分隔符）
as                  整个句子（包括分隔符）
ip                  整个段落（不包括前后空白行）
ap                  整个段落（包括前后空白行）
ib                  小括号内
ab                  小括号内（包含小括号本身）
iB                  大括号内
aB                  大括号内（包含大括号本身）
i)                  小括号内
a)                  小括号内（包含小括号本身）
i]                  中括号内
a]                  中括号内（包含中括号本身）
i}                  大括号内
a}                  大括号内（包含大括号本身）
i'                  单引号内
a'                  单引号内（包含单引号本身）
i"                  双引号内
a"                  双引号内（包含双引号本身）
2i)                 往外两层小括号内
2a)                 往外两层小括号内（包含小括号本身）
2f)                 到第二个小括号处
2t)                 到第二个小括号前


##############################################################################
# 查找替换
##############################################################################

/pattern            从光标处向文件尾搜索 pattern
?pattern            从光标处向文件头搜索 pattern
n                   向同一方向执行上一次搜索
N                   向相反方向执行上一次搜索
*                   向前搜索光标下的单词
#                   向后搜索光标下的单词
:s/p1/p2/g          将当前行中全替换p1为p2
:%s/p1/p2/g         将当前文件中全替换p1为p2
:%s/p1/p2/gc        将当前文件中全替换p1为p2，并且每处询问你是否替换
:10,20s/p1/p2/g     将第10到20行中所有p1替换为p2
:., ns/p1/p2/g      将当前行到n行中所有p1替换为p2
:., +10s/p1/p2/g    将当前行到相对当前行加10行的区间中所有p1替换为p2
:., $s/p1/p2/g      将当前行到最后一行中所有p1替换为p2
:0,.s/p1/p2/g       将第一行到当前行中所有p1替换为p2
:%s/1\\2\/3/123/g   将“1\2/3” 替换为 “123”（特殊字符使用反斜杠标注）
:%s/\r//g           删除 DOS 换行符 ^M


##############################################################################
# VISUAL MODE - 由 v, V, CTRL-V 进入的可视模式
##############################################################################

>                   增加缩进
<                   减少缩进
d                   删除高亮选中的文字
x                   删除高亮选中的文字
c                   改写文字，即删除高亮选中的文字并进入插入模式
s                   改写文字，即删除高亮选中的文字并进入插入模式
y                   拷贝文字
~                   转换大小写
o                   跳转到标记区的另外一端
O                   跳转到标记块的另外一端
u                   标记区转换为小写
U                   标记区转换为大写
g CTRL-G            显示所选择区域的统计信息
<Esc>               退出可视模式


##############################################################################
# 位置跳转
##############################################################################

CTRL-O              跳转到上一个位置
CTRL-I              跳转到下一个位置
CTRL-^              跳转到 alternate file (当前窗口的上一个文件）
CTRL-]              跳转到当前光标文字下的超链接
CTRL-T              返回到跳转之前的位置
%                   跳转到 {} () [] 的匹配
gd                  跳转到局部定义（光标下的单词的定义）
gD                  跳转到全局定义（光标下的单词的定义）
gf                  打开名称为光标下文件名的文件
[[                  跳转到上一个顶层函数（比如C语言以大括号分隔）
]]                  跳转到下一个顶层函数（比如C语言以大括号分隔）
[m                  跳转到上一个成员函数
]m                  跳转到下一个成员函数
[{                  跳转到上一处未匹配的 {
]}                  跳转到下一处未匹配的 }
[(                  跳转到上一处未匹配的 (
])                  跳转到下一处未匹配的 )
[c                  上一个不同处（diff时）
]c                  下一个不同处（diff时）
[/                  跳转到 C注释开头
]/                  跳转到 C注释结尾
``                  回到上次跳转的位置
''                  回到上次跳转的位置
`.                  回到上次编辑的位置
'.                  回到上次编辑的位置


##############################################################################
# 文件操作
##############################################################################

:w                  保存文件
:w <filename>       按名称保存文件
:e <filename>       打开文件并编辑
:saveas <filename>  另存为文件
:r <filename>       读取文件并将内容插入到光标后
:r !dir             将 dir 命令的输出捕获并插入到光标后
:close              关闭文件
:q                  退出
:q!                 强制退出
:wa                 保存所有文件
:cd <path>          切换 Vim 当前路径
:pwd                显示 Vim 当前路径
:new                打开一个新的窗口编辑新文件
:enew               在当前窗口创建新文件
:vnew               在左右切分的新窗口中编辑新文件
:tabnew             在新的标签页中编辑新文件


##############################################################################
# 已打开文件操作
##############################################################################

:ls                 查案缓存列表
:bn                 切换到下一个缓存
:bp                 切换到上一个缓存
:bd                 删除缓存
:b 1                切换到1号缓存
:b abc              切换到文件名为 abc 开头的缓存
:badd <filename>    将文件添加到缓存列表
:set hidden         设置隐藏模式（未保存的缓存可以被切换走，或者关闭）
:set nohidden       关闭隐藏模式（未保存的缓存不能被切换走，或者关闭）
n CTRL-^            切换缓存，先输入数字的缓存编号，再按 CTRL + 6


##############################################################################
# 窗口操作
##############################################################################

:sp <filename>      上下切分窗口并在新窗口打开文件 filename
:vs <filename>      左右切分窗口并在新窗口打开文件 filename
CTRL-W s            上下切分窗口
CTRL-W v            左右切分窗口
CTRL-W w            循环切换到下一个窗口
CTRL-W W            循环切换到上一个窗口
CTRL-W p            跳到上一个访问过的窗口
CTRL-W c            关闭当前窗口
CTRL-W o            关闭其他窗口
CTRL-W h            跳到左边的窗口
CTRL-W j            跳到下边的窗口
CTRL-W k            跳到上边的窗口
CTRL-W l            跳到右边的窗口
CTRL-W +            增加当前窗口的行高，前面可以加数字
CTRL-W -            减少当前窗口的行高，前面可以加数字
CTRL-W <            减少当前窗口的列宽，前面可以加数字
CTRL-W >            增加当前窗口的列宽，前面可以加数字
CTRL-W =            让所有窗口宽高相同
CTRL-W H            将当前窗口移动到最左边
CTRL-W J            将当前窗口移动到最下边
CTRL-W K            将当前窗口移动到最上边
CTRL-W L            将当前窗口移动到最右边
CTRL-W x            交换窗口
CTRL-W f            在新窗口中打开名为光标下文件名的文件
CTRL-W gf           在新标签页中打开名为光标下文件名的文件
CTRL-W R            旋转窗口
CTRL-W T            将当前窗口移到新的标签页中
CTRL-W P            跳转到预览窗口
CTRL-W z            关闭预览窗口
CTRL-W _            纵向最大化当前窗口
CTRL-W |            横向最大化当前窗口


##############################################################################
# 标签页
##############################################################################

:tabs               显示所有标签页
:tabe <filename>    在新标签页中打开文件 filename
:tabn               下一个标签页
:tabp               上一个标签页
:tabc               关闭当前标签页
:tabo               关闭其他标签页
:tabn n             切换到第n个标签页，比如 :tabn 3 切换到第三个标签页
:tabm n             标签移动
:tabfirst           切换到第一个标签页
:tablast            切换到最后一个标签页
:tab help           在标签页打开帮助
:tab drop <file>    如果文件已被其他标签页和窗口打开则跳过去，否则新标签打开
:tab split          在新的标签页中打开当前窗口里的文件
:tab ball           将缓存中所有文件用标签页打开
:set showtabline=?  设置为 0 就不显示标签页标签，1会按需显示，2会永久显示
ngt                 切换到第n个标签页，比如 2gt 将会切换到第二个标签页
gt                  下一个标签页
gT                  上一个标签页


##############################################################################
# 书签
##############################################################################

:marks              显示所有书签
ma                  保存当前位置到书签 a ，书签名小写字母为文件内，大写全局
'a                  跳转到书签 a所在的行
`a                  跳转到书签 a所在位置
`.                  跳转到上一次编辑的行
'A                  跳转到全文书签 A
['                  跳转到上一个书签
]'                  跳转到下一个书签
'<                  跳到上次可视模式选择区域的开始
'>                  跳到上次可视模式选择区域的结束
:delm a             删除缓冲区标签a
:delm A             删除文件标签A
:delm!              删除所有缓冲区标签(小写字母), 不能删除文件标签和数字标签
:delm A-Z           删除所有文件标签(大写字母)
:delm 0-9           删除所有数字标签(.viminfo)
:delm A-Z0-9        删除所有文件标签和数字标签

 
##############################################################################
# 常用设置
##############################################################################

:set nocompatible   设置不兼容原始 vi 模式（必须设置在最开头）
:set bs=?           设置BS键模式，现代编辑器为 :set bs=eol,start,indent
:set sw=4           设置缩进宽度为 4
:set ts=4           设置制表符宽度为 4
:set noet           设置不展开 tab 成空格
:set et             设置展开 tab 成空格
:set winaltkeys=no  设置 GVim 下正常捕获 ALT 键
:set nowrap         关闭自动换行
:set ttimeout       允许终端按键检测超时（终端下功能键为一串ESC开头的扫描码）
:set ttm=100        设置终端按键检测超时为100毫秒
:set term=?         设置终端类型，比如常见的 xterm
:set ignorecase     设置搜索忽略大小写(可缩写为 :set ic)
:set noignorecase   设置搜索不忽略大小写(可缩写为 :set noic)
:set smartcase      智能大小写，默认忽略大小写，除非搜索内容里包含大写字母
:set list           设置显示制表符和换行符
:set number         设置显示行号，禁止显示行号可以用 :set nonumber
:set relativenumber 设置显示相对行号（其他行与当前行的距离）
:set paste          进入粘贴模式（粘贴时禁用缩进等影响格式的东西）
:set nopaste        结束粘贴模式
:set spell          允许拼写检查
:set hlsearch       设置高亮查找
:set ruler          总是显示光标位置
:set incsearch      查找输入时动态增量显示查找结果
:set insertmode     Vim 始终处于插入模式下，使用 ctrl-o 临时执行命令
:set all            列出所有选项设置情况
:syntax on          允许语法高亮
:syntax off         禁止语法高亮


##############################################################################
# 帮助信息
##############################################################################

:h tutor            入门文档
:h quickref         快速帮助
:h index            查询 Vim 所有键盘命令定义
:h summary          帮助你更好的使用内置帮助系统
:h CTRL-H           查询普通模式下 CTRL-H 是干什么的
:h i_CTRL-H         查询插入模式下 CTRL-H 是干什么的
:h i_<Up>           查询插入模式下方向键上是干什么的
:h pattern.txt      正则表达式帮助
:h eval             脚本编写帮助
:h function-list    查看 VimScript 的函数列表 
:h windows.txt      窗口使用帮助
:h tabpage.txt      标签页使用帮助
:h +timers          显示对 +timers 特性的帮助
:h :!               查看如何运行外部命令
:h tips             查看 Vim 内置的常用技巧文档
:h set-termcap      查看如何设置按键扫描码
:viusage            NORMAL 模式帮助
:exusage            EX 命令帮助
:version            显示当前 Vim 的版本号和特性


##############################################################################
# 外部命令
##############################################################################

:!ls                运行外部命令 ls，并等待返回
:r !ls              将外部命令 ls 的输出捕获，并插入到光标后
:w !sudo tee %      sudo以后保存当前文件
:call system('ls')  调用 ls 命令，但是不显示返回内容
:!start notepad     Windows 下启动 notepad，最前面可以加 silent
:sil !start cmd     Windows 下当前目录打开 cmd
:%!prog             运行文字过滤程序，如整理 json格式 :%!python -m json.tool


##############################################################################
# Quickfix 窗口
##############################################################################

:copen              打开 quickfix 窗口（查看编译，grep等信息）
:copen 10           打开 quickfix 窗口，并且设置高度为 10
:cclose             关闭 quickfix 窗口
:cfirst             跳到 quickfix 中第一个错误信息
:clast              跳到 quickfix 中最后一条错误信息
:cc [nr]            查看错误 [nr]
:cnext              跳到 quickfix 中下一个错误信息
:cprev              跳到 quickfix 中上一个错误信息


##############################################################################
# 拼写检查
##############################################################################

:set spell          打开拼写检查
:set nospell        关闭拼写检查
]s                  下一处错误拼写的单词
[s                  上一处错误拼写的单词
zg                  加入单词到拼写词表中
zug                 撤销上一次加入的单词
z=                  拼写建议


##############################################################################
# 代码折叠
##############################################################################

za                  切换折叠
zA                  递归切换折叠
zc                  折叠光标下代码
zC                  折叠光标下所有代码
zd                  删除光标下折叠
zD                  递归删除所有折叠
zE                  删除所有折叠
zf                  创建代码折叠
zF                  指定行数创建折叠
zi                  切换折叠
zm                  所有代码折叠一层
zr                  所有代码打开一层
zM                  折叠所有代码，设置 foldlevel=0，设置 foldenable
zR                  打开所有代码，设置 foldlevel 为最大值
zn                  折叠 none，重置 foldenable 并打开所有代码
zN                  折叠 normal，重置 foldenable 并恢复所有折叠
zo                  打开一层代码
zO                  打开光标下所有代码折叠


##############################################################################
# 宏录制
##############################################################################

qa                  开始录制名字为 a 的宏
q                   结束录制宏
@a                  播放名字为 a 的宏
@@                  播放上一个宏
@:                  重复上一个ex命令（即冒号命令）


##############################################################################
# 其他命令
##############################################################################

CTRL-X CTRL-F       插入模式下文件路径补全
CTRL-X CTRL-O       插入下 Omnifunc 补全
CTRL-X CTRL-N       插入模式下关键字补全
CTRL-X CTRL-E       插入模式下向上滚屏
CTRL-X CTRL-Y       插入模式下向下滚屏
CTRL-E              向上滚屏
CTRL-Y              向下滚屏
CTRL-G              显示正在编辑的文件名，以及大小和位置信息
g CTRL-G            显示文件的：大小，字符数，单词数和行数，可视模式下也可用
zz                  调整光标所在行到屏幕中央
zt                  调整光标所在行到屏幕上部
zb                  调整光标所在行到屏幕下部
ga                  显示光标下字符的 ascii 码或者 unicode 编码
g8                  显示光标下字符的 utf-8 编码字节序
gi                  回到上次进入插入的地方，并切换到插入模式
K                   查询光标下单词的帮助
ZZ                  保存文件（如果有改动的话），并关闭窗口
ZQ                  不保存文件关闭窗口
CTRL-PgUp           上个标签页，GVim OK，部分终端软件需设置对应键盘码
CTRL-PgDown         下个标签页，GVim OK，部分终端软件需设置对应键盘码
CTRL-R CTRL-W       命令模式下插入光标下单词
CTRL-INSERT         复制到系统剪贴板（GVIM）
SHIFT-INSERT        粘贴系统剪贴板的内容（GVIM）
:set ff=unix        设置换行为 unix
:set ff=dos         设置换行为 dos
:set ff?            查看换行设置
:set nohl           清除搜索高亮
:set termcap        查看会从终端接收什么以及会发送给终端什么命令
:set guicursor=     解决 SecureCRT/PenguiNet 中 NeoVim 局部奇怪字符问题
:set t_RS= t_SH=    解决 SecureCRT/PenguiNet 中 Vim8.0 终端功能奇怪字符
:set fo+=a          开启文本段的实时自动格式化
:earlier 15m        回退到15分钟前的文件内容
:.!date             在当前窗口插入时间
:%!xxd              开始二进制编辑
:%!xxd -r           保存二进制编辑
:r !curl -sL {URL}  读取 url 内容添加到光标后
:g/^\s*$/d          删除空行
:g/green/d          删除所有包含 green 的行
:v/green/d          删除所有不包含 green 的行
:g/gladiolli/#      搜索单词打印结果，并在结果前加上行号
:g/ab.*cd.*efg/#    搜索包含 ab,cd 和 efg 的行，打印结果以及行号
:v/./,/./-j         压缩空行
:Man bash           在 Vim 中查看 man，先调用 :runtime! ftplugin/man.vim 激活
/fred\|joe          搜索 fred 或者 joe
/\<\d\d\d\d\>       精确搜索四个数字
/^\n\{3}            搜索连续三个空行


##############################################################################
# Plugin - https://github.com/tpope/vim-commentary
##############################################################################

gcc                 注释当前行
gc{motion}          注释 {motion} 所标注的区域，比如 gcap 注释整段
gci{                注释大括号内的内容
gc                  在 Visual Mode 下面按 gc 注释选中区域
:7,17Commentary     注释 7 到 17 行


##############################################################################
# Plugin - https://github.com/junegunn/vim-easy-align
##############################################################################

:EasyAlign =        以第一个匹配的=为中心对齐
:EasyAlign *=       匹配并且对齐所有=


##############################################################################
# Plugin - https://github.com/tpope/vim-unimpaired
##############################################################################

[space              向上插入空行
]space              向下插入空行
[e                  替换当前行和上一行
]e                  替换当前行和下一行
[x                  XML 编码
]x                  XML 解码
[u                  URL 编码
]u                  URL 解码
[y                  C 字符串编码
]y                  C 字符串解码
[q                  上一个 quickfix 错误
]q                  下一个 quickfix 错误
[Q                  第一个 quickfix 错误
]Q                  最后一个 quickfix 错误
[f                  切换同目录里上一个文件
]f                  切换同目录里下一个文件
[os                 设置 :set spell
]os                 设置 :set nospell
=os                 设置 :set invspell
[on                 显示行号
]on                 关闭行号
[ol                 显示回车和制表符 :set list
]ol                 不显示回车和制表符 :set nolist
[b                  缓存切换到上一个文件，即 :bp
]b                  缓存切换到下一个文件，即 :bn
[B                  缓存切换到第一个文件，即 :bfirst
]B                  缓存切换到最后一个文件，即 :blast


##############################################################################
# Plugin - https://github.com/skywind3000/asyncrun.vim
##############################################################################

:AsyncRun ls        异步运行命令 ls 结果输出到 quickfix 使用 :copen 查看
:AsyncRun -raw ls   异步运行命令 ls 结果不匹配 errorformat


##############################################################################
# Plugin - https://github.com/gaving/vim-textobj-argument
##############################################################################

cia                 改写函数参数
caa                 改写函数参数（包括逗号分隔）
dia                 删除函数参数
daa                 删除函数参数（包括逗号分隔）
via                 选取函数参数
vaa                 选取函数参数（包括逗号分隔）
yia                 复制函数参数
yaa                 复制函数参数（包括逗号分隔）

```



# Shell

```javascript

##############################################################################
# 常用快捷键（默认使用 Emacs 键位）
##############################################################################

CTRL+A              # 移动到行首，同 <Home>
CTRL+B              # 向后移动，同 <Left>
CTRL+C              # 结束当前命令
CTRL+D              # 删除光标前的字符，同 <Delete> ，或者没有内容时，退出会话
CTRL+E              # 移动到行末，同 <End>
CTRL+F              # 向前移动，同 <Right>
CTRL+G              # 退出当前编辑（比如正在 CTRL+R 搜索历史时）
CTRL+H              # 删除光标左边的字符，同 <Backspace>
CTRL+K              # 删除光标位置到行末的内容
CTRL+L              # 清屏并重新显示
CTRL+N              # 移动到命令历史的下一行，同 <Down>
CTRL+O              # 类似回车，但是会显示下一行历史
CTRL+P              # 移动到命令历史的上一行，同 <Up>
CTRL+R              # 历史命令反向搜索，使用 CTRL+G 退出搜索
CTRL+S              # 历史命令正向搜索，使用 CTRL+G 退出搜索
CTRL+T              # 交换前后两个字符
CTRL+U              # 删除字符到行首
CTRL+V              # 输入字符字面量，先按 CTRL+V 再按任意键
CTRL+W              # 删除光标左边的一个单词
CTRL+X              # 列出可能的补全
CTRL+Y              # 粘贴前面 CTRL+u/k/w 删除过的内容
CTRL+Z              # 暂停前台进程返回 bash，需要时可用 fg 将其切换回前台
CTRL+_              # 撤销（undo），有的终端将 CTRL+_ 映射为 CTRL+/ 或 CTRL+7

ALT+b               # 向后（左边）移动一个单词
ALT+d               # 删除光标后（右边）一个单词
ALT+f               # 向前（右边）移动一个单词
ALT+t               # 交换字符
ALT+BACKSPACE       # 删除光标前面一个单词，类似 CTRL+W，但不影响剪贴板

CTRL+X CTRL+X       # 连续按两次 CTRL+X，光标在当前位置和行首来回跳转 
CTRL+X CTRL+E       # 用你指定的编辑器，编辑当前命令


##############################################################################
# BASH 基本操作
##############################################################################

exit                # 退出当前登陆
env                 # 显示环境变量
echo $SHELL         # 显示你在使用什么 SHELL

bash                # 使用 bash，用 exit 返回
which bash          # 搜索 $PATH，查找哪个程序对应命令 bash
whereis bash        # 搜索可执行，头文件和帮助信息的位置，使用系统内建数据库
whatis bash         # 查看某个命令的解释，一句话告诉你这是干什么的

clear               # 清初屏幕内容
reset               # 重置终端（当你不小心 cat 了一个二进制，终端状态乱掉时使用）


##############################################################################
# 目录操作
##############################################################################

cd                  # 返回自己 $HOME 目录
cd {dirname}        # 进入目录
pwd                 # 显示当前所在目录
mkdir {dirname}     # 创建目录
mkdir -p {dirname}  # 递归创建目录
pushd {dirname}     # 目录压栈并进入新目录
popd                # 弹出并进入栈顶的目录
dirs -v             # 列出当前目录栈
cd -                # 回到之前的目录
cd -{N}             # 切换到目录栈中的第 N个目录，比如 cd -2 将切换到第二个


##############################################################################
# 文件操作
##############################################################################

ls                  # 显示当前目录内容，后面可接目录名：ls {dir} 显示指定目录
ls -l               # 列表方式显示目录内容，包括文件日期，大小，权限等信息
ls -1               # 列表方式显示目录内容，只显示文件名称，减号后面是数字 1
ls -a               # 显示所有文件和目录，包括隐藏文件（.开头的文件/目录名）
ln -s {fn} {link}   # 给指定文件创建一个软链接
cp {src} {dest}     # 拷贝文件，cp -r dir1 dir2 可以递归拷贝（目录）
rm {fn}             # 删除文件，rm -r 递归删除目录，rm -f 强制删除
mv {src} {dest}     # 移动文件，如果 dest 是目录，则移动，是文件名则覆盖
touch {fn}          # 创建或者更新一下制定文件
cat {fn}            # 输出文件原始内容
any_cmd > {fn}      # 执行任意命令并将标准输出重定向到指定文件
more {fn}           # 逐屏显示某文件内容，空格翻页，q 退出
less {fn}           # 更高级点的 more，更多操作，q 退出
head {fn}           # 显示文件头部数行，可用 head -3 abc.txt 显示头三行
tail {fn}           # 显示文件尾部数行，可用 tail -3 abc.txt 显示尾部三行
tail -f {fn}        # 持续显示文件尾部数据，可用于监控日志
nano {fn}           # 使用 nano 编辑器编辑文件
vim {fn}            # 使用 vim 编辑文件
diff {f1} {f2}      # 比较两个文件的内容
wc {fn}             # 统计文件有多少行，多少个单词
chmod 644 {fn}      # 修改文件权限为 644，可以接 -R 对目录循环改权限
chgrp group {fn}    # 修改文件所属的用户组
chown user1 {fn}    # 修改文件所有人为 user1, chown user1:group1 fn 可以修改组
file {fn}           # 检测文件的类型和编码
basename {fn}       # 查看文件的名字（不包括路径）
dirname {fn}        # 查看文件的路径（不包括名字）
grep {pat} {fn}     # 在文件中查找出现过 pat 的内容
grep -r {pat} .     # 在当前目录下递归查找所有出现过 pat 的文件内容
stat {fn}           # 显示文件的详细信息


##############################################################################
# 用户管理
##############################################################################

whoami              # 显示我的用户名
who                 # 显示已登陆用户信息，w / who / users 内容略有不同
w                   # 显示已登陆用户信息，w / who / users 内容略有不同
users               # 显示已登陆用户信息，w / who / users 内容略有不同
passwd              # 修改密码，passwd {user} 可以用于 root 修改别人密码
finger {user}       # 显示某用户信息，包括 id, 名字, 登陆状态等
adduser {user}      # 添加用户
deluser {user}      # 删除用户
w                   # 查看谁在线
su                  # 切换到 root 用户
su -                # 切换到 root 用户并登陆（执行登陆脚本）
su {user}           # 切换到某用户
su -{user}          # 切换到某用户并登陆（执行登陆脚本）
id {user}           # 查看用户的 uid，gid 以及所属其他用户组
id -u {user}        # 打印用户 uid
id -g {user}        # 打印用户 gid
write {user}        # 向某用户发送一句消息
last                # 显示最近用户登陆列表
last {user}         # 显示登陆记录
lastb               # 显示失败登陆记录
lastlog             # 显示所有用户的最近登陆记录
sudo {command}      # 以 root 权限执行某命令


##############################################################################
# 进程管理
##############################################################################

ps                        # 查看当前会话进程
ps ax                     # 查看所有进程，类似 ps -e
ps aux                    # 查看所有进程详细信息，类似 ps -ef
ps auxww                  # 查看所有进程，并且显示进程的完整启动命令
ps -u {user}              # 查看某用户进程
ps axjf                   # 列出进程树
ps xjf -u {user}          # 列出某用户的进程树
ps -eo pid,user,command   # 按用户指定的格式查看进程
ps aux | grep httpd       # 查看名为 httpd 的所有进程
ps --ppid {pid}           # 查看父进程为 pid 的所有进程
pstree                    # 树形列出所有进程，pstree 默认一般不带，需安装
pstree {user}             # 进程树列出某用户的进程
pstree -u                 # 树形列出所有进程以及所属用户
pgrep {procname}          # 搜索名字匹配的进程的 pid，比如 pgrep apache2

kill {pid}                # 结束进程
kill -9 {pid}             # 强制结束进程，9/SIGKILL 是强制不可捕获结束信号
kill -KILL {pid}          # 强制执行进程，kill -9 的另外一种写法
kill -l                   # 查看所有信号
kill -l TERM              # 查看 TERM 信号的编号
killall {procname}        # 按名称结束所有进程
pkill {procname}          # 按名称结束进程，除名称外还可以有其他参数

top                       # 查看最活跃的进程
top -u {user}             # 查看某用户最活跃的进程

any_command &             # 在后台运行某命令，也可用 CTRL+Z 将当前进程挂到后台
jobs                      # 查看所有后台进程（jobs）
bg                        # 查看后台进程，并切换过去
fg                        # 切换后台进程到前台
fg {job}                  # 切换特定后台进程到前台

trap cmd sig1 sig2        # 在脚本中设置信号处理命令
trap "" sig1 sig2         # 在脚本中屏蔽某信号
trap - sig1 sig2          # 恢复默认信号处理行为

nohup {command}           # 长期运行某程序，在你退出登陆都保持它运行
nohup {command} &         # 在后台长期运行某程序
disown {PID|JID}          # 将进程从后台任务列表（jobs）移除

wait                      # 等待所有后台进程任务结束


##############################################################################
# 常用命令：SSH / 系统信息 / 网络
##############################################################################

ssh user@host             # 以用户 user 登陆到远程主机 host
ssh -p {port} user@host   # 指定端口登陆主机
ssh-copy-id user@host     # 拷贝你的 ssh key 到远程主机，避免重复输入密码
scp {fn} user@host:path   # 拷贝文件到远程主机
scp user@host:path dest   # 从远程主机拷贝文件回来
scp -P {port} ...         # 指定端口远程拷贝文件

uname -a                  # 查看内核版本等信息
man {help}                # 查看帮助
man -k {keyword}          # 查看哪些帮助文档里包含了该关键字
info {help}               # 查看 info pages，比 man 更强的帮助系统
uptime                    # 查看系统启动时间
date                      # 显示日期
cal                       # 显示日历
vmstat                    # 显示内存和 CPU 使用情况
vmstat 10                 # 每 10 秒打印一行内存和 CPU情况，CTRL+C 退出
free                      # 显示内存和交换区使用情况
df                        # 显示磁盘使用情况
du                        # 显示当前目录占用，du . --max-depth=2 可以指定深度
uname                     # 显示系统版本号
hostname                  # 显示主机名称
showkey -a                # 查看终端发送的按键编码

ping {host}               # ping 远程主机并显示结果，CTRL+C 退出
ping -c N {host}          # ping 远程主机 N 次
traceroute {host}         # 侦测路由连通情况
mtr {host}                # 高级版本 traceroute
host {domain}             # DNS 查询，{domain} 前面可加 -a 查看详细信息
whois {domain}            # 取得域名 whois 信息
dig {domain}              # 取得域名 dns 信息
route -n                  # 查看路由表
netstat -a                # 列出所有端口
netstat -an               # 查看所有连接信息，不解析域名
netstat -anp              # 查看所有连接信息，包含进程信息（需要 sudo）
netstat -l                # 查看所有监听的端口
netstat -t                # 查看所有 TCP 链接
netstat -lntu             # 显示所有正在监听的 TCP 和 UDP 信息
netstat -lntup            # 显示所有正在监听的 socket 及进程信息
netstat -i                # 显示网卡信息
netstat -rn               # 显示当前系统路由表，同 route -n
ss -an                    # 比 netstat -an 更快速更详细
ss -s                     # 统计 TCP 的 established, wait 等

wget {url}                # 下载文件，可加 --no-check-certificate 忽略 ssl 验证
wget -qO- {url}           # 下载文件并输出到标准输出（不保存）
curl -sL {url}            # 同 wget -qO- {url} 没有 wget 的时候使用

sz {file}                 # 发送文件到终端，zmodem 协议
rz                        # 接收终端发送过来的文件


##############################################################################
# 变量操作
##############################################################################

varname=value             # 定义变量
varname=value command     # 定义子进程变量并执行子进程
echo $varname             # 查看变量内容
echo $$                   # 查看当前 shell 的进程号
echo $!                   # 查看最近调用的后台任务进程号
echo $?                   # 查看最近一条命令的返回码
export VARNAME=value      # 设置环境变量（将会影响到子进程）

array[0]=valA             # 定义数组
array[1]=valB
array[2]=valC
array=([0]=valA [1]=valB [2]=valC)   # 另一种方式
array=(valA valB valC)               # 另一种方式

${array[i]}               # 取得数组中的元素
${#array[@]}              # 取得数组的长度
${#array[i]}              # 取得数组中某个变量的长度

declare -a                # 查看所有数组
declare -f                # 查看所有函数
declare -F                # 查看所有函数，仅显示函数名
declare -i                # 查看所有整数
declare -r                # 查看所有只读变量
declare -x                # 查看所有被导出成环境变量的东西
declare -p varname        # 输出变量是怎么定义的（类型+值）

${varname:-word}          # 如果变量不为空则返回变量，否则返回 word
${varname:=word}          # 如果变量不为空则返回变量，否则赋值成 word 并返回
${varname:?message}       # 如果变量不为空则返回变量，否则打印错误信息并退出
${varname:+word}          # 如果变量不为空则返回 word，否则返回 null
${varname:offset:len}     # 取得字符串的子字符串

${variable#pattern}       # 如果变量头部匹配 pattern，则删除最小匹配部分返回剩下的
${variable##pattern}      # 如果变量头部匹配 pattern，则删除最大匹配部分返回剩下的
${variable%pattern}       # 如果变量尾部匹配 pattern，则删除最小匹配部分返回剩下的
${variable%%pattern}      # 如果变量尾部匹配 pattern，则删除最大匹配部分返回剩下的
${variable/pattern/str}   # 将变量中第一个匹配 pattern 的替换成 str，并返回
${variable//pattern/str}  # 将变量中所有匹配 pattern 的地方替换成 str 并返回

${#varname}               # 返回字符串长度

*(patternlist)            # 零次或者多次匹配
+(patternlist)            # 一次或者多次匹配
?(patternlist)            # 零次或者一次匹配
@(patternlist)            # 单词匹配
!(patternlist)            # 不匹配

array=($text)             # 按空格分隔 text 成数组，并赋值给变量
IFS="/" array=($text)     # 按斜杆分隔字符串 text 成数组，并赋值给变量
text="${array[*]}"        # 用空格链接数组并赋值给变量
text=$(IFS=/; echo "${array[*]}")  # 用斜杠链接数组并赋值给变量

A=( foo bar "a  b c" 42 ) # 数组定义
B=("${A[@]:1:2}")         # 数组切片：B=( bar "a  b c" )
C=("${A[@]:1}")           # 数组切片：C=( bar "a  b c" 42 )
echo "${B[@]}"            # bar a  b c
echo "${B[1]}"            # a  b c
echo "${C[@]}"            # bar a  b c 42
echo "${C[@]: -2:2}"      # a  b c 42  减号前的空格是必须的

$(UNIX command)           # 运行命令，并将标准输出内容捕获并返回
varname=$(id -u user)     # 将用户名为 user 的 uid 赋值给 varname 变量

num=$(expr 1 + 2)         # 兼容 posix sh 的计算，使用 expr 命令计算结果
num=$(expr $num + 1)      # 数字自增
expr 2 \* \( 2 + 3 \)     # 兼容 posix sh 的复杂计算，输出 10

num=$((1 + 2))            # 计算 1+2 赋值给 num，使用 bash 独有的 $((..)) 计算
num=$(($num + 1))         # 变量递增
num=$((num + 1))          # 变量递增，双括号内的 $ 可以省略
num=$((1 + (2 + 3) * 2))  # 复杂计算


##############################################################################
# 事件指示符
##############################################################################

!!                  # 上一条命令
!^                  # 上一条命令的第一个单词
!:n                 # 上一条命令的第n个单词
!:n-$               # 上一条命令的第n个单词到最后一个单词
!$                  # 上一条命令的最后一个单词
!-n:$               # 上n条命令的最后一个单词
!string             # 最近一条包含string的命令
!^string1^string2   # 最近一条包含string1的命令, 快速替换string1为string2
!#                  # 本条命令之前所有的输入内容
!#:n                # 本条命令之前的第n个单词, 快速备份cp /etc/passwd !#:1.bak


##############################################################################
# 函数
##############################################################################

# 定义一个新函数
function myfunc() {
    # $1 代表第一个参数，$N 代表第 N 个参数
    # $# 代表参数个数
    # $0 代表被调用者自身的名字
    # $@ 代表所有参数，类型是个数组，想传递所有参数给其他命令用 cmd "$@" 
    # $* 空格链接起来的所有参数，类型是字符串
    {shell commands ...}
}

myfunc                    # 调用函数 myfunc 
myfunc arg1 arg2 arg3     # 带参数的函数调用
myfunc "$@"               # 将所有参数传递给函数
myfunc "${array[@]}"      # 将一个数组当作多个参数传递给函数
shift                     # 参数左移

unset -f myfunc           # 删除函数
declare -f                # 列出函数定义


##############################################################################
# 条件判断（兼容 posix sh 的条件判断）：man test
##############################################################################

statement1 && statement2  # and 操作符
statement1 || statement2  # or 操作符

exp1 -a exp2              # exp1 和 exp2 同时为真时返回真（POSIX XSI扩展）
exp1 -o exp2              # exp1 和 exp2 有一个为真就返回真（POSIX XSI扩展）
( expression )            # 如果 expression 为真时返回真，输入注意括号前反斜杆
! expression              # 如果 expression 为假那返回真

str1 = str2               # 判断字符串相等，如 [ "$x" = "$y" ] && echo yes
str1 != str2              # 判断字符串不等，如 [ "$x" != "$y" ] && echo yes
str1 < str2               # 字符串小于，如 [ "$x" \< "$y" ] && echo yes
str2 > str2               # 字符串大于，注意 < 或 > 是字面量，输入时要加反斜杆
-n str1                   # 判断字符串不为空（长度大于零）
-z str1                   # 判断字符串为空（长度等于零）

-a file                   # 判断文件存在，如 [ -a /tmp/abc ] && echo "exists"
-d file                   # 判断文件存在，且该文件是一个目录
-e file                   # 判断文件存在，和 -a 等价
-f file                   # 判断文件存在，且该文件是一个普通文件（非目录等）
-r file                   # 判断文件存在，且可读
-s file                   # 判断文件存在，且尺寸大于0
-w file                   # 判断文件存在，且可写
-x file                   # 判断文件存在，且执行
-N file                   # 文件上次修改过后还没有读取过
-O file                   # 文件存在且属于当前用户
-G file                   # 文件存在且匹配你的用户组
file1 -nt file2           # 文件1 比 文件2 新
file1 -ot file2           # 文件1 比 文件2 旧

num1 -eq num2             # 数字判断：num1 == num2
num1 -ne num2             # 数字判断：num1 != num2
num1 -lt num2             # 数字判断：num1 < num2
num1 -le num2             # 数字判断：num1 <= num2
num1 -gt num2             # 数字判断：num1 > num2
num1 -ge num2             # 数字判断：num1 >= num2


##############################################################################
# 分支控制：if 和经典 test，兼容 posix sh 的条件判断语句
##############################################################################

test {expression}         # 判断条件为真的话 test 程序返回0 否则非零
[ expression ]            # 判断条件为真的话返回0 否则非零

test "abc" = "def"        # 查看返回值 echo $? 显示 1，因为条件为假
test "abc" != "def"       # 查看返回值 echo $? 显示 0，因为条件为真

test -a /tmp; echo $?     # 调用 test 判断 /tmp 是否存在，并打印 test 的返回值
[ -a /tmp ]; echo $?      # 和上面完全等价，/tmp 肯定是存在的，所以输出是 0

test cond && cmd1         # 判断条件为真时执行 cmd1
[ cond ] && cmd1          # 和上面完全等价
[ cond ] && cmd1 || cmd2  # 条件为真执行 cmd1 否则执行 cmd2

# 判断 /etc/passwd 文件是否存在
# 经典的 if 语句就是判断后面的命令返回值为0的话，认为条件为真，否则为假
if test -e /etc/passwd; then
    echo "alright it exists ... "
else
    echo "it doesn't exist ... "
fi

# 和上面完全等价，[ 是个和 test 一样的可执行程序，但最后一个参数必须为 ]
# 这个名字为 "[" 的可执行程序一般就在 /bin 或 /usr/bin 下面，比 test 优雅些
if [ -e /etc/passwd ]; then   
    echo "alright it exists ... "
else
    echo "it doesn't exist ... "
fi

# 和上面两个完全等价，其实到 bash 时代 [ 已经是内部命令了，用 enable 可以看到
[ -e /etc/passwd ] && echo "alright it exists" || echo "it doesn't exist"

# 判断变量的值
if [ "$varname" = "foo" ]; then
    echo "this is foo"
elif [ "$varname" = "bar" ]; then
    echo "this is bar"
else
    echo "neither"
fi

# 复杂条件判断，注意 || 和 && 是完全兼容 POSIX 的推荐写法
if [ $x -gt 10 ] && [ $x -lt 20 ]; then
    echo "yes, between 10 and 20"
fi

# 可以用 && 命令连接符来做和上面完全等价的事情
[ $x -gt 10 ] && [ $x -lt 20 ] && echo "yes, between 10 and 20"

# 小括号和 -a -o 是 POSIX XSI 扩展写法，小括号是字面量，输入时前面要加反斜杆
if [ \( $x -gt 10 \) -a \( $x -lt 20 \) ]; then
    echo "yes, between 10 and 20"
fi

# 同样可以用 && 命令连接符来做和上面完全等价的事情
[ \( $x -gt 10 \) -a \( $x -lt 20 \) ] && echo "yes, between 10 and 20"


# 判断程序存在的话就执行
[ -x /bin/ls ] && /bin/ls -l

# 如果不考虑兼容 posix sh 和 dash 这些的话，可用 bash 独有的 ((..)) 和 [[..]]:
https://www.ibm.com/developerworks/library/l-bash-test/index.html


##############################################################################
# 流程控制：while / for / case / until 
##############################################################################

# while 循环
while condition; do
    statements
done

i=1
while [ $i -le 10 ]; do
    echo $i; 
    i=$(expr $i + 1)
done

# for 循环：上面的 while 语句等价
for i in {1..10}; do
    echo $i
done

for name [in list]; do
    statements
done

# for 列举某目录下面的所有文件
for f in /home/*; do 
    echo $f
done

# bash 独有的 (( .. )) 语句，更接近 C 语言，但是不兼容 posix sh
for (( initialisation ; ending condition ; update )); do
    statements
done

# 和上面的写法等价
for ((i = 0; i < 10; i++)); do echo $i; done

# case 判断
case expression in 
    pattern1 )
        statements ;;
    pattern2 )
        statements ;;
    * )
        otherwise ;;
esac

# until 语句
until condition; do
    statements
done

# select 语句
select name [in list]; do
  statements that can use $name
done


##############################################################################
# 命令处理
##############################################################################

command ls                         # 忽略 alias 直接执行程序或者内建命令 ls
builtin cd                         # 忽略 alias 直接运行内建的 cd 命令
enable                             # 列出所有 bash 内置命令，或禁止某命令
help {builtin_command}             # 查看内置命令的帮助（仅限 bash 内置命令）

eval $script                       # 对 script 变量中的字符串求值（执行）


##############################################################################
# 输出/输入 重定向
##############################################################################

cmd1 | cmd2                        # 管道，cmd1 的标准输出接到 cmd2 的标准输入
< file                             # 将文件内容重定向为命令的标准输入
> file                             # 将命令的标准输出重定向到文件，会覆盖文件
>> file                            # 将命令的标准输出重定向到文件，追加不覆盖
>| file                            # 强制输出到文件，即便设置过：set -o noclobber
n>| file                           # 强制将文件描述符 n的输出重定向到文件
<> file                            # 同时使用该文件作为标准输入和标准输出
n<> file                           # 同时使用文件作为文件描述符 n 的输出和输入
n> file                            # 重定向文件描述符 n 的输出到文件
n< file                            # 重定向文件描述符 n 的输入为文件内容
n>&                                # 将标准输出 dup/合并 到文件描述符 n
n<&                                # 将标准输入 dump/合并 定向为描述符 n
n>&m                               # 文件描述符 n 被作为描述符 m 的副本，输出用
n<&m                               # 文件描述符 n 被作为描述符 m 的副本，输入用
&>file                             # 将标准输出和标准错误重定向到文件
<&-                                # 关闭标准输入
>&-                                # 关闭标准输出
n>&-                               # 关闭作为输出的文件描述符 n
n<&-                               # 关闭作为输入的文件描述符 n
diff <(cmd1) <(cmd2)               # 比较两个命令的输出


##############################################################################
# 文本处理 - cut
##############################################################################

cut -c 1-16                        # 截取每行头16个字符
cut -c 1-16 file                   # 截取指定文件中每行头 16个字符
cut -c3-                           # 截取每行从第三个字符开始到行末的内容
cut -d':' -f5                      # 截取用冒号分隔的第五列内容
cut -d';' -f2,10                   # 截取用分号分隔的第二和第十列内容
cut -d' ' -f3-7                    # 截取空格分隔的三到七列
echo "hello" | cut -c1-3           # 显示 hel
echo "hello sir" | cut -d' ' -f2   # 显示 sir
ps | tr -s " " | cut -d " " -f 2,3,4  # cut 搭配 tr 压缩字符


##############################################################################
# 文本处理 - awk / sed 
##############################################################################

awk '{print $5}' file              # 打印文件中以空格分隔的第五列
awk -F ',' '{print $5}' file       # 打印文件中以逗号分隔的第五列
awk '/str/ {print $2}' file        # 打印文件中包含 str 的所有行的第二列
awk -F ',' '{print $NF}' file      # 打印逗号分隔的文件中的每行最后一列 
awk '{s+=$1} END {print s}' file   # 计算所有第一列的合
awk 'NR%3==1' file                 # 从第一行开始，每隔三行打印一行

sed 's/find/replace/' file         # 替换文件中首次出现的字符串并输出结果 
sed '10s/find/replace/' file       # 替换文件第 10 行内容
sed '10,20s/find/replace/' file    # 替换文件中 10-20 行内容
sed -r 's/regex/replace/g' file    # 替换文件中所有出现的字符串
sed -i 's/find/replace/g' file     # 替换文件中所有出现的字符并且覆盖文件
sed -i '/find/i\newline' file      # 在文件的匹配文本前插入行
sed -i '/find/a\newline' file      # 在文件的匹配文本后插入行
sed '/line/s/find/replace/' file   # 先搜索行特征再执行替换
sed -e 's/f/r/' -e 's/f/r' file    # 执行多次替换
sed 's#find#replace#' file         # 使用 # 替换 / 来避免 pattern 中有斜杆
sed -i -r 's/^\s+//g' file         # 删除文件每行头部空格
sed '/^$/d' file                   # 删除文件空行并打印
sed -i 's/\s\+$//' file            # 删除文件每行末尾多余空格
sed -n '2p' file                   # 打印文件第二行
sed -n '2,5p' file                 # 打印文件第二到第五行


##############################################################################
# 排序 - sort
##############################################################################

sort file                          # 排序文件
sort -r file                       # 反向排序（降序）
sort -n file                       # 使用数字而不是字符串进行比较
sort -t: -k 3n /etc/passwd         # 按 passwd 文件的第三列进行排序
sort -u file                       # 去重排序


##############################################################################
# 快速跳转 - https://github.com/rupa/z
##############################################################################

source /path/to/z.sh               # .bashrc 中初始化 z.sh
z                                  # 列出所有历史路径以及他们的权重
z foo                              # 跳到历史路径中匹配 foo 的权重最大的目录
z foo bar                          # 跳到历史路径中匹配 foo 和 bar 权重最大的目录
z -l foo                           # 列出所有历史路径中匹配 foo 的目录及权重
z -r foo                           # 按照最高访问次数优先进行匹配跳转
z -t foo                           # 按照最近访问优先进行匹配跳转


##############################################################################
# 键盘绑定
##############################################################################

bind '"\eh":"\C-b"'                # 绑定 ALT+h 为光标左移，同 CTRL+b / <Left>
bind '"\el":"\C-f"'                # 绑定 ALT+l 为光标右移，同 CTRL+f / <Right>
bind '"\ej":"\C-n"'                # 绑定 ALT+j 为下条历史，同 CTRL+n / <Down>
bind '"\ek":"\C-p"'                # 绑定 ALT+k 为上条历史，同 CTRL+p / <Up>
bind '"\eH":"\eb"'                 # 绑定 ALT+H 为光标左移一个单词，同 ALT-b 
bind '"\eL":"\ef"'                 # 绑定 ALT+L 为光标右移一个单词，同 ALT-f 
bind '"\eJ":"\C-a"'                # 绑定 ALT+J 为移动到行首，同 CTRL+a / <Home>
bind '"\eK":"\C-e"'                # 绑定 ALT+K 为移动到行末，同 CTRL+e / <End>
bind '"\e;":"ls -l\n"'             # 绑定 ALT+; 为执行 ls -l 命令


##############################################################################
# 网络管理：ip / ifconfig / nmap ...
##############################################################################

ip a                               # 显示所有网络地址，同 ip address
ip a show eth1                     # 显示网卡 IP 地址
ip a add 172.16.1.23/24 dev eth1   # 添加网卡 IP 地址
ip a del 172.16.1.23/24 dev eth1   # 删除网卡 IP 地址
ip link show dev eth0              # 显示网卡设备属性
ip link set eth1 up                # 激活网卡
ip link set eth1 down              # 关闭网卡
ip link set eth1 address {mac}     # 修改 MAC 地址
ip neighbour                       # 查看 ARP 缓存
ip route                           # 查看路由表
ip route add 10.1.0.0/24 via 10.0.0.253 dev eth0    # 添加静态路由
ip route del 10.1.0.0/24           # 删除静态路由

ifconfig                           # 显示所有网卡和接口信息
ifconfig -a                        # 显示所有网卡（包括开机没启动的）信息
ifconfig eth0                      # 指定设备显示信息
ifconfig eth0 up                   # 激活网卡
ifconfig eth0 down                 # 关闭网卡
ifconfig eth0 192.168.120.56       # 给网卡配置 IP 地址
ifconfig eth0 10.0.0.8 netmask 255.255.255.0 up     # 配置 IP 并启动
ifconfig eth0 hw ether 00:aa:bb:cc:dd:ee            # 修改 MAC 地址

nmap 10.0.0.12                     # 扫描主机 1-1000 端口
nmap -p 1024-65535 10.0.0.12       # 扫描给定端口
nmap 10.0.0.0/24                   # 给定网段扫描局域网内所有主机
nmap -O -sV 10.0.0.12              # 探测主机服务和操作系统版本


##############################################################################
# 有趣的命令
##############################################################################

man hier                           # 查看文件系统的结构和含义
man test                           # 查看 posix sh 的条件判断帮助
man ascii                          # 显示 ascii 表
getconf LONG_BIT                   # 查看系统是 32 位还是 64 位
bind -P                            # 列出所有 bash 的快捷键
mount | column -t                  # 漂亮的列出当前加载的文件系统
curl ip.cn                         # 取得外网 ip 地址和服务商信息
disown -a && exit                  # 关闭所有后台任务并退出
cat /etc/issue                     # 查看 Linux 发行版信息
lsof -i port:80                    # 哪个程序在使用 80 端口？
showkey -a                         # 取得按键的 ASCII 码
svn diff | view -                  # 使用 Vim 来显示带色彩的 diff 输出
mv filename.{old,new}              # 快速文件改名
time read                          # 使用 CTRL-D 停止，最简单的计时功能
cp file.txt{,.bak}                 # 快速备份文件
sudo touch /forcefsck              # 强制在下次重启时扫描磁盘
find ~ -mmin 60 -type f            # 查找 $HOME 目录中，60 分钟内修改过的文件
curl wttr.in/~beijing              # 查看北京的天气预报
echo ${SSH_CLIENT%% *}             # 取得你是从什么 IP 链接到当前主机上的
echo $[RANDOM%X+1]                 # 取得 1 到 X 之间的随机数
bind -x '"\C-l":ls -l'             # 设置 CTRL+l 为执行 ls -l 命令
find / -type f -size +5M           # 查找大于 5M 的文件
chmod --reference f1 f2            # 将 f2 的权限设置成 f1 一模一样的
curl -L cheat.sh                   # 速查表大全


##############################################################################
# 常用技巧
##############################################################################

# 列出最常使用的命令
history | awk '{a[$2]++}END{for(i in a){print a[i] " " i}}' | sort -rn | head

# 列出所有网络状态：ESTABLISHED / TIME_WAIT / FIN_WAIT1 / FIN_WAIT2 
netstat -n | awk '/^tcp/ {++tt[$NF]} END {for (a in tt) print a, tt[a]}'

# 通过 SSH 来 mount 文件系统
sshfs name@server:/path/to/folder /path/to/mount/point

# 显示前十个运行的进程并按内存使用量排序
ps aux | sort -nk +4 | tail

# 在右上角显示时钟
while sleep 1;do tput sc;tput cup 0 $(($(tput cols)-29));date;tput rc;done&

# 从网络上的压缩文件中解出一个文件来，并避免保存中间文件
wget -qO - "http://www.tarball.com/tarball.gz" | tar zxvf -

# 性能测试：测试处理器性能
python -c "import test.pystone;print(test.pystone.pystones())"

# 性能测试：测试内存带宽
dd if=/dev/zero of=/dev/null bs=1M count=32768

# Linux 下挂载一个 iso 文件
mount /path/to/file.iso /mnt/cdrom -oloop

# 通过主机 A 直接 ssh 到主机 B
ssh -t hostA ssh hostB

# 下载一个网站的所有图片
wget -r -l1 --no-parent -nH -nd -P/tmp -A".gif,.jpg" http://example.com/images

# 快速创建项目目录
mkdir -p work/{project1,project2}/{src,bin,bak}

# 按日期范围查找文件
find . -type f -newermt "2010-01-01" ! -newermt "2010-06-01"

# 显示当前正在使用网络的进程
lsof -P -i -n | cut -f 1 -d " "| uniq | tail -n +2

# Vim 中保存一个没有权限的文件
:w !sudo tee > /dev/null %

# 在 .bashrc / .bash_profile 中加载另外一个文件（比如你保存在 github 上的配置）
source ~/github/profiles/my_bash_init.sh

# 反向代理：将外网主机（202.115.8.1）端口（8443）转发到内网主机 192.168.1.2:443
ssh -CqTnN -R 0.0.0.0:8443:192.168.1.2:443  user@202.115.8.1

# 正向代理：将本地主机的 8443 端口，通过 192.168.1.3 转发到 192.168.1.2:443 
ssh -CqTnN -L 0.0.0.0:8443:192.168.1.2:443  user@192.168.1.3

# socks5 代理：把本地 1080 端口的 socks5 的代理请求通过远程主机转发出去
ssh -CqTnN -D localhost:1080  user@202.115.8.1

# 终端下正确设置 ALT 键和 BackSpace 键
http://www.skywind.me/blog/archives/2021


##############################################################################
# 有用的函数
##############################################################################

# 自动解压：判断文件后缀名并调用相应解压命令
function q-extract() {
    if [ -f $1 ] ; then
        case $1 in
        *.tar.bz2)   tar -xvjf $1    ;;
        *.tar.gz)    tar -xvzf $1    ;;
        *.tar.xz)    tar -xvJf $1    ;;
        *.bz2)       bunzip2 $1     ;;
        *.rar)       rar x $1       ;;
        *.gz)        gunzip $1      ;;
        *.tar)       tar -xvf $1     ;;
        *.tbz2)      tar -xvjf $1    ;;
        *.tgz)       tar -xvzf $1    ;;
        *.zip)       unzip $1       ;;
        *.Z)         uncompress $1  ;;
        *.7z)        7z x $1        ;;
        *)           echo "don't know how to extract '$1'..." ;;
        esac
    else
        echo "'$1' is not a valid file!"
    fi
}

# 自动压缩：判断后缀名并调用相应压缩程序
function q-compress() {
    if [ -n "$1" ] ; then
        FILE=$1
        case $FILE in
        *.tar) shift && tar -cf $FILE $* ;;
        *.tar.bz2) shift && tar -cjf $FILE $* ;;
        *.tar.xz) shift && tar -cJf $FILE $* ;;
        *.tar.gz) shift && tar -czf $FILE $* ;;
        *.tgz) shift && tar -czf $FILE $* ;;
        *.zip) shift && zip $FILE $* ;;
        *.rar) shift && rar $FILE $* ;;
        esac
    else
        echo "usage: q-compress <foo.tar.gz> ./foo ./bar"
    fi
}

# 漂亮的带语法高亮的 color cat ，需要先 pip install pygments
function ccat() {
    local style="monokai"
    if [ $# -eq 0 ]; then
        pygmentize -P style=$style -P tabsize=4 -f terminal256 -g
    else
        for NAME in $@; do
            pygmentize -P style=$style -P tabsize=4 -f terminal256 -g "$NAME"
        done
    fi
}


##############################################################################
# 好玩的配置
##############################################################################

# 放到你的 ~/.bashrc 配置文件中，给 man 增加漂亮的色彩高亮
export LESS_TERMCAP_mb=$'\E[1m\E[32m'
export LESS_TERMCAP_mh=$'\E[2m'
export LESS_TERMCAP_mr=$'\E[7m'
export LESS_TERMCAP_md=$'\E[1m\E[36m'
export LESS_TERMCAP_ZW=""
export LESS_TERMCAP_us=$'\E[4m\E[1m\E[37m'
export LESS_TERMCAP_me=$'\E(B\E[m'
export LESS_TERMCAP_ue=$'\E[24m\E(B\E[m'
export LESS_TERMCAP_ZO=""
export LESS_TERMCAP_ZN=""
export LESS_TERMCAP_se=$'\E[27m\E(B\E[m'
export LESS_TERMCAP_ZV=""
export LESS_TERMCAP_so=$'\E[1m\E[33m\E[44m'

# ALT+hjkl/HJKL 快速移动光标，将下面内容添加到 ~/.inputrc 中可作用所有工具，
# 包括 bash/zsh/python/lua 等使用 readline 的工具，帮助见：info rluserman
"\eh": backward-char
"\el": forward-char
"\ej": next-history
"\ek": previous-history
"\eH": backward-word
"\eL": forward-word
"\eJ": beginning-of-line
"\eK": end-of-line


##############################################################################
# References
##############################################################################

https://github.com/Idnan/bash-guide
http://www.linuxstall.com/linux-command-line-tips-that-every-linux-user-should-know/
https://ss64.com/bash/syntax-keyboard.html
http://wiki.bash-hackers.org/commands/classictest
https://www.ibm.com/developerworks/library/l-bash-test/index.html
https://www.cyberciti.biz/faq/bash-loop-over-file/
https://linuxconfig.org/bash-scripting-tutorial
https://github.com/LeCoupa/awesome-cheatsheets/blob/master/languages/bash.sh
https://devhints.io/bash
https://github.com/jlevy/the-art-of-command-line
https://yq.aliyun.com/articles/68541

```



# Lua

```javascript

---------------------------------------------------------------------------------
--[[
	Lua 特性：
		轻量级：源码2.5万行左右C代码， 方便嵌入进宿主语言(C/C++)
		可扩展：提供了易于使用的扩展接口和机制， 使用宿主语言提供的功能
		高效性：运行最快的脚本语言之一
		可移植：跨平台
	入门书籍《lua程序设计》
		推荐：云风翻译的《Lua 5.3参考手册》	
		http://cloudwu.github.io/lua53doc/manual.html
	源码： 
		http://www.lua.org/ftp/
--]]
---------------------------------------------------------------------------------


---------------------------------------------------------------------------------
--[[
	变量: 作为动态类型语言，变量本身没有类型， 赋值决定某一时刻变量的类型。私有静态
	变量带local, 公有静态变量不带local。
		数据类型：
			nil            	为空，无效值，在条件判断中表示false
			boolean			包含两个值：false和true
			number			表示双精度类型的实浮点数
			string			字符串由一对双引号或单引号来表示
			function		由 C 或 Lua 编写的函数
			table			Lua 中的表（table）其实是一个"关联数组"（associative
							arrays），数组的索引可以是数字、字符串或表类型
			thread			协程
			userdata		存储在变量中的C数据结构
--]]
---------------------------------------------------------------------------------
print(type(signal))						--nil

signal = true				
print(type(signal))						--boolean

signal = 1454
print(type(signal))						--number

signal = "UnionTech"
print(type(signal))						--string			

signal = function() 
	print(type(signal))
end 	
print(type(signal))						--function

signal = {}								
print(type(signal))						--table

signal = coroutine.create(function()
	print(type(signal))
end)
print(type(signal))						--coroutine



---------------------------------------------------------------------------------
--[[
	流程控制：if...elseif...else、 while、 for
--]]
---------------------------------------------------------------------------------
--if...else
ty_signal = type(signal)
if ty_signal == "coroutine" then
    print("signal type is coroutine")
elseif ty_signal == "table" then
    print("signal type is table")
else
    print("signal type is other")
end

--while
ut_companys = {"beijing company", "shanghai company", "nanjing company", "wuxi company", "guangzhou company", "yunfu company", "wuhan company", "chengdu company", "xian company"}
count = 0
while count <= #ut_companys 
do
    count = count + 1
    print("ut_companys[", count, "] is ", ut_companys[count])
end

--for
for i=#ut_companys, 1, -2 do        --以2为步长反向遍历
    print("num: ", i, "company: ", ut_companys[i])
end


---------------------------------------------------------------------------------
--[[
	table： 表作为Lua唯一自带的数据结构， 使用简单方便， 兼具数组和Map作为容器的
	功能，通过表可以很容易组成常见的数据结构， 如栈、队列、链表、集合，用for循环
	很容易迭代遍历表数据。
--]]
---------------------------------------------------------------------------------
--table当数组用，下标从1开始
for i, c in ipairs(ut_companys) do
	print(string.format("1 UnionTech company: %d		%s", i, c))
end

table.sort(ut_companys)
for i=#ut_companys, 1, -1 do
	print(string.format("2 UnionTech company: %d		%s", i, ut_companys[i]))
end

--table当hash map用
ut_cptypes = {}

ut_cptypes["adapter"] = {"beijing company", "wuhan company", "guangzhou company"}
ut_cptypes["developer"] = {"beijing company", "wuhan company", "nanjing company", "chengdu company", "xian company", "guangzhou company"}
ut_cptypes["general"] = {"beijing company"}

for ty, cps in pairs(ut_cptypes) do
	for i, cp in ipairs(cps) do
		print(string.format("3 UnionTech companys: type:%s  identifier:%s	company:%s", ty, i, cp))
	end
end


---------------------------------------------------------------------------------
--[[
	函数：在Lua中函数也是第一类型值， 可赋值给变量， 也可以在函数体内定义并使用函数，或者
	是直接使用匿名匿名函数。
--]]
---------------------------------------------------------------------------------
--多重返回值
ut_types = {"adapter", "developer", "general"}
function company_types(cp, cptypes)
	local adpt, dvlp, genl = nil, nil, nil
	for i, ty in ipairs(ut_types) do
		for _, _cp in ipairs(cptypes[ty]) do
			if _cp == cp then
				if i == 1 then
					adpt = true
				elseif i == 2 then
					dvlp = true
				elseif i == 3 then
					genl = true
				end
				break
			end
		end
	end
	return adpt, dvlp, genl
end

cp = "wuhan company"
types = {company_types(cp, ut_cptypes)}

for i, ty in ipairs(types) do
	if ty then
		print(string.format("%s  is %s", cp, ut_types[i]))
	end
end 

--变参
function printf(str, ...)
	print(string.format(str, ...))
end

function add_companys(...)
	local newcps = {...}
	local num = #newcps
	for _, cp in ipairs(newcps) do
		table.insert(ut_companys, cp)
	end
	return ut_companys, num
end

_, _ = add_companys("changsha company", "zhengzhou company", "hefei company")
for i=1, #ut_companys do
	--print(string.format("4 UnionTech company: %d		%s", i, ut_companys[i]))
	printf("4 UnionTech company: %d		%s", i, ut_companys[i])
end

--闭包
function all_companys(cps)
	local companys, n = {}, 0
	for _, v in ipairs(cps) do
		table.insert(companys, v)
	end
	return function()
		n = n + 1
		if n > #companys then
			return ""
		else
			return companys[n]
		end
	end
end

get_company = all_companys(ut_companys)
while true
do
	cp = get_company()
	if cp == "" then
		break
	else	
		printf("get company: %s", cp)
	end
end


---------------------------------------------------------------------------------
--[[
	协程(coroutine)：Lua协同程序(coroutine)与线程比较类似：拥有独立的堆栈，独立的局
	部变量，独立的指令指针，同时又与其它协同程序共享全局变量和其它大部分东西。
--]]
---------------------------------------------------------------------------------
function foo (a)
    print("foo 函数输出", a)
    return coroutine.yield(2 * a) -- 返回  2*a 的值
end
 
co = coroutine.create(function (a , b)
    print("第一次协同程序执行输出", a, b) -- co-body 1 10
    local r = foo(a + 1)
     
    print("第二次协同程序执行输出", r)
    local r, s = coroutine.yield(a + b, a - b)  -- a，b的值为第一次调用协同程序时传入
     
    print("第三次协同程序执行输出", r, s)
    return b, "结束协同程序"                   -- b的值为第二次调用协同程序时传入
end)
       
print("main", coroutine.resume(co, 1, 10)) -- true, 4
print("main", coroutine.resume(co, "r")) -- true 11 -9
print("main", coroutine.resume(co, "x", "y")) -- true 10 end
print("main", coroutine.resume(co, "x", "y")) -- cannot resume dead coroutine
--resume将主协程数据传入次协程， yield将次协程中数据传回主协程


---------------------------------------------------------------------------------
--[[
	元表(Metatable)：本质上来说就是存放元方法的表结构， 通过元表实现对表中数据和行为
	的改变。
	Lua 查找一个表元素时的规则，其实就是如下 3 个步骤:
		1.在表中查找，如果找到，返回该元素，找不到则继续
		2.判断该表是否有元表，如果没有元表，返回 nil，有元表则继续。
		3.判断元表有没有 __index 方法，如果 __index 方法为 nil，则返回 nil；如果
		__index 方法是一个表，则重复 1、2、3；如果 __index 方法是一个函数，则返
		回该函数的返回值
	
--]]
---------------------------------------------------------------------------------
father = {
	colourofskin = "yellow",
	weight = 70,
	work = "programming",
	otherwork = function() 
		print "do housework"
	end
}
father.__index = father

son = {
	weight = 50,
	like = "basketball"
}

setmetatable(son, father)
printf("weight:%d 	like:%s  	work:%s		colourofskin:%s ", son.weight, son.like, son.work, son.colourofskin)
son.otherwork()


---------------------------------------------------------------------------------
--[[
    面向对象：因为lua本身不是面向对象的语言， 在lua中， 通过table和function来模拟一个对象， 
    用metatable来模拟面向对象中的继承，但是在使用的时候需要考虑lua作为脚本语言， 变量的类型随
    所赋值类型而改变。
--]]
---------------------------------------------------------------------------------
--父类
rect = {
    area = 0,
    length = 0, 
    width = 0,
}

function rect:getArea()
    if self.area == 0 then
        self.area = self.length * self.width
    end
    
    return self.area
end

function rect:getLength()
    return self.length
end

function rect:new(leng, wid)
    self.length = leng
    self.width = wid
    return self    
end

--子类
cuboid = {
    volume = 0,
    height = 0,
}

function cuboid:getVolume()
    if self.volume == 0 then
        self.volume = self.height * self:getArea()
    end
    return self.volume
end

function cuboid:new(_rect, _height)
    setmetatable(self, _rect)
    _rect.__index = _rect
    self.height = _height
    return self
end

rect1 = rect:new(5, 10)
print("rect1 rectangle:", rect1:getArea())

cuboid1 = cuboid:new(rect1, 2)
print("cuboid1 volume: ", cuboid1:getVolume())
print("cuboid1 rectangle: ", cuboid1:getArea())             --子类调用父类方法getArea
print("cuboid1 length function: ", cuboid1:getLength())     --子类调用父类方法getLength
print("cuboid1 length variable: ", cuboid1.length)          --子类使用父类变量length

--重写子类接口getArea， lua中没有重载
function cuboid:getArea()                                   
    return 2 * (self.height * self.length + self.height * self.width + self.length * self.width)
end

cuboid2 = cuboid:new(rect1, 2)
print("cuboid2 function: getArea: ", cuboid2:getArea())                     --调用子类重写的方法getArea
print("cuboid2 base function: getArea: ", getmetatable(cuboid2):getArea())  --显示调用父类方法getArea


---------------------------------------------------------------------------------
--[[
	模块与C包: 模块类似封装库， 有利于代码复用， 降低耦合， 提供被调用的API。
	----------------------------------------------------------------------
	-- 文件名为 module.lua, 定义一个名为 module 的模块
	module = {}
	module.constant = "这是一个常量"
	function module.func1()
		io.write("这是一个公有函数！\n")
	end
	
	local function func2()
		print("这是一个私有函数！")
	end
	
	function module.func3()
		func2()
	end
 
	return module
	
	在其他模块中调用module模块：
	local m = require("module")
	print(m.constant)
	----------------------------------------------------------------------
	与Lua中写包不同，C包在使用以前必须首先加载并连接，在大多数系统中最容易的实现方式
	是通过动态连接库机制。Lua在一个叫loadlib的函数内提供了所有的动态连接的功能。
	
	----------------------------------------------------------------------
--]]
---------------------------------------------------------------------------------


---------------------------------------------------------------------------------
--[[
	lua标准库： 标准库中接口可直接使用不需要require
	常用标准库：
		math		数学计算
		table		表结构数据处理
		string		字符串处理
		os			系统库函数
		io			文件读写
		coroutine	协程库
		debug		调式器
--]]
---------------------------------------------------------------------------------


---------------------------------------------------------------------------------
--[[
	lua虚拟机：脚本语言没有像编译型语言那样直接编译为机器能识别的机器代码，这意味着
	解释性脚本语言与编译型语言的区别：由于每个脚本语言都有自己的一套字节码，与具体的
	硬件平台无关，所以无需修改脚本代码，就能运行在各个平台上。硬件、软件平台的差异都
	由语言自身的虚拟机解决。由于脚本语言的字节码需要由虚拟机执行，而不像机器代码那样
	能够直接执行，所以运行速度比编译型语言差不少。有了虚拟机这个中间层，同样的代码可
	以不经修改就运行在不同的操作系统、硬件平台上。Java、Python都是基于虚拟机的编程语
	言，Lua同样也是这样。
--]]
---------------------------------------------------------------------------------




--可在命令行lua lua.lua运行本脚本
```



# End

