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

# 一些名词

```javascript
 # Vital Product Data(VPD)，重要产品数据，是与一组特定硬件或软件相关的配置和信息数据的集合。
 例如部件号（part number），序列号(serial number)，以及设备指定的一些数据。并非系统连接的所有设备都提供VPD，但通常可从PCI和SCSI设备获得。并行ATA和USB设备也提供类似的数据，但不叫VPD。
 
# shadow RAM:影子ram内存
 
 
# VEPA（Virtual Ethernet Port Aggregator虚拟以太网端口汇聚器）
目标是要将虚拟机之间的交换从服务器内部移出到接入交换机上。通过将虚拟机交换移回物理网络，基于VEPA的方法使现有的网络工具和流程可以在虚拟化和非虚拟化环境以及监视程序技术中以相同的方式自由使用。基于VEPA产品可以开放互联，而且可以实现网络和服务器的紧耦合。 
 
# 虚拟以太桥接(VEB, Virtual Ethernet Bridge)
所谓VEB就是在一个物理终端工作站/服务器上支持多个虚拟机的本地交换，通常是由软件模拟一个虚拟交换机来实现。这种软件方案有很明显的缺点：虚拟交换机的功能过于简单，网络和主机管理界面模糊。



```

