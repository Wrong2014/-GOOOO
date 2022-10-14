# Python脚本汇总

## 爬取jenkis review意见

```python
import requests
import re
import json
import xlwt

url= 'http://gerrit.dpu.tech/changes/?O=81&S=%d&n=25&q=status%3Amerge%20-is%3Awip'
project_name='dpdk'
commit_url='http://gerrit.dpu.tech/c/dpdk/+/'
comment_url_prefix='http://gerrit.dpu.tech/changes/dpdk~'
continue_f=1
interl_val=25
lines=0


def write_excel(comment,sheet):
    global lines
    sheet.write(lines,0,comment)
    lines=lines+1


def request(url,sheet):
    headers = {
        'User-Agent': 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:97.0) Gecko/20100101 Firefox/97.0',
        'Cookie': 'GerritAccount=aSIeprqPhGO4mi3AXZwH3fh3EfmUaFjRZW'
    }
    data = requests.get(url, headers=headers).text
    adjust_data=re.compile('\)\]\}\'')
    data=re.sub(adjust_data,"",data)
    data_json=json.loads(data)
    for obj in data_json:
        if (obj["project"] == project_name ):
            #print(obj["owner"]["name"])
            submission_id=obj['submission_id']
            #print(submission_id)
            comment_url=comment_url_prefix+submission_id+'/comments'
            #print(comment_url)
            comment = requests.get(comment_url, headers=headers).text
            comment_data=re.compile('\)\]\}\'')
            data1=re.sub(comment_data,"",comment)
            comment_json=json.loads(data1)
            for comment in comment_json:
                path=comment
                #print(path)
                message=comment_json.get(path)
                for i in message:
                    #print(i.get('author'))
                    sub_message = i.get('message')
                    if (sub_message.lower() != 'done' and sub_message.lower() != 'ack' and  sub_message.lower() != 'ok'):
                        print(sub_message)
                        write_excel(sub_message,sheet)
def main():
    id=0
    workbook=xlwt.Workbook(encoding='utf-8')
    worksheet=workbook.add_sheet('wx')
    while(continue_f):
        url='http://gerrit.dpu.tech/changes/?O=81&S='+str(id)+'&n=25&q=status%3Amerge%20-is%3Awip'
        request(url,worksheet)
        id=id+25
        if id >= 5000:
            break;
    workbook.save("wx1111.xls");
    

if __name__ == '__main__':
    main()
```

修改版：

```Python
import requests
import re
import json
import xlwt

url= 'http://gerrit.dpu.tech/changes/?O=81&S=0&n=25&q=status%3Amerged'
project_name='nm-kernel-driver'
commit_url='http://gerrit.dpu.tech/c/nm-kernel-driver/+/'
comment_url_prefix='http://gerrit.dpu.tech/changes/nm-kernel-driver~'
continue_f=1
interl_val=25
lines=0


def write_excel(author, comment,sheet):
    global lines
    sheet.write(lines,0,author)
    sheet.write(lines,1,comment)
    lines=lines+1


def request(url,sheet):
    headers = {
        'User-Agent': 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
        'Cookie': 'GerritAccount=aTseprszPn7JY814pFA4TkRjFlYxV8R2Xq'
    }

    data = requests.get(url, headers=headers).text
    adjust_data=re.compile('\)\]\}\'')
    data=re.sub(adjust_data,"",data)
    #print(data)
    data_json=json.loads(data)
    for obj in data_json:
        if (obj["project"] == project_name ):
            #print("aaaaaaaaaaa")
            submission_id=obj['submission_id']
            #print(submission_id)
            sub_id = submission_id.split('-')[0]
            #print(sub_id)
            #print("bbbbbbbbbb")
            comment_url=comment_url_prefix+sub_id+'/comments'
            #print(comment_url)
            comment = requests.get(comment_url, headers=headers).text
            #print(comment)
            comment_data=re.compile('\)\]\}\'')
            data1=re.sub(comment_data,"",comment)
            comment_json=json.loads(data1)
            for comment in comment_json:
                path=comment
                #print(path)
                message=comment_json.get(path)
                print(message)
                for i in message:
                    author1 = i.get('author')
                    author = author1.get('name')
                    print(author)
                    sub_message = i.get('message')
                    if (sub_message.lower() != 'done' and sub_message.lower() != 'ack' and  sub_message.lower() != 'ok'):
                        #print(sub_message)
                        write_excel(author,sub_message,sheet)
def main():
    id=0
    workbook=xlwt.Workbook(encoding='utf-8')
    worksheet=workbook.add_sheet('wx')
    while(continue_f):
        url='http://gerrit.dpu.tech/changes/?O=81&S='+str(id)+'&n=25&q=status%3Amerge%20-is%3Awip'
        request(url,worksheet)
        id=id+25
        if id >= 5000:
            break;
    workbook.save("wx1111.xls");


if __name__ == '__main__':
    main()






```

## 部署testpmd测试

```shell
root@Ubuntu20:~/bennie# cat vfio_bind.sh 
./dpdk-hugepages.py -p 2M --setup 2G

modprobe vfio
echo "vfio-pci" > /sys/bus/pci/devices/0000:af:00.0/driver_override
echo -n "0000:af:00.0" > /sys/bus/pci/drivers/vfio-pci/bind
echo "" > /sys/bus/pci/devices/0000:af:00.0/driver_override

echo "vfio-pci" > /sys/bus/pci/devices/0000:af:00.1/driver_override
echo -n "0000:af:00.1" > /sys/bus/pci/drivers/vfio-pci/bind
echo "" > /sys/bus/pci/devices/0000:af:00.1/driver_override


echo "vfio-pci" > /sys/bus/pci/devices/0000:af:00.2/driver_override
echo -n "0000:af:00.2" > /sys/bus/pci/drivers/vfio-pci/bind
echo "" > /sys/bus/pci/devices/0000:af:00.2/driver_override
echo "vfio-pci" > /sys/bus/pci/devices/0000:af:00.3/driver_override
echo -n "0000:af:00.3" > /sys/bus/pci/drivers/vfio-pci/bind
echo "" > /sys/bus/pci/devices/0000:af:00.3/driver_override


echo "vfio-pci" > /sys/bus/pci/devices/0000:08:00.0/driver_override
echo -n "0000:08:00.0" > /sys/bus/pci/drivers/vfio-pci/bind
echo "" > /sys/bus/pci/devices/0000:08:00.0/driver_override

```



## 抓取寄存器脚本

```shell
root@Ubuntu20:~# cat rep.sh (watch ./rep.sh)
#!/bin/bash
echo "VER=1.01"


pci_addr_base=$((0x`lspci -d 1f0f:1220 -v |grep -oP "(?<=Memory at )\S+"|head -n1`))

addr_greg=$(($pci_addr_base+ $((0x00000000))))
addr_eth0=$(($pci_addr_base+ $((0x000d0000))))
addr_eth1=$(($pci_addr_base+ $((0x000e0000)))) 
addr_eth2=$(($pci_addr_base+ $((0x000f0000))))
addr_eth3=$(($pci_addr_base+ $((0x00100000)))) 

addr_urmx=$(($pci_addr_base+$((0x00090000))))  
addr_store=$(($pci_addr_base+$((0x00010000))))  
addr_pa=$(($pci_addr_base+$((0x00060000))))  
addr_pro=$(($pci_addr_base+$((0x00020000))))  
addr_qm=$(($pci_addr_base+$((0x00030000))))
addr_ped=$(($pci_addr_base+$((0x00050000))))

addr_dmux=$(($pci_addr_base+$((0x000a0000))))
addr_uvn=$(($pci_addr_base+$((0x000c0000))))
addr_dvn=$(($pci_addr_base+$((0x000b0000))))
addr_memt=$(($pci_addr_base+$((0x00080000))))
addr_stat=$(($pci_addr_base+$((0x00040000))))
addr_bm=$(($pci_addr_base+$((0x00070000))))

addr_padpt=$(($pci_addr_base+$((0x00150000))))    
addr_pcompleter=$(($pci_addr_base+$((0x00130000))))  

tmp_addr=`printf "0x%08x" $(($addr_greg+ $((0x0000))))`;  prj[0]=$((`busybox devmem $tmp_addr `))

tmp_addr=`printf "0x%08x" $(($addr_greg+ $((0x0004))))`;  greg[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_greg+ $((0x0010))))`;  greg[1]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_greg+ $((0x0008))))`;  greg[2]=$((`busybox devmem $tmp_addr `))

#tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0080))))`;  eth_rx[0]=$((`busybox devmem $tmp_addr `))
#tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0080))))`;  eth_rx[1]=$((`busybox devmem $tmp_addr `))             
#tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0080))))`;  eth_rx[2]=$((`busybox devmem $tmp_addr `))
#tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0080))))`;  eth_rx[3]=$((`busybox devmem $tmp_addr `))

#eth0 cfg
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0080))))`;  eth_rx0[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0084))))`;  eth_rx0[1]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0088))))`;  eth_rx0[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x008c))))`;  eth_rx0[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0090))))`;  eth_rx0[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0094))))`;  eth_rx0[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0098))))`;  eth_rx0[6]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x009c))))`;  eth_rx0[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00a0))))`;  eth_rx0[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00a4))))`;  eth_rx0[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00a8))))`;  eth_rx0[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00ac))))`;  eth_rx0[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00b0))))`;  eth_rx0[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00b4))))`;  eth_rx0[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00b8))))`;  eth_rx0[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00bc))))`;  eth_rx0[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00c0))))`;  eth_rx0[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00c4))))`;  eth_rx0[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00c8))))`;  eth_rx0[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00cc))))`;  eth_rx0[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00d0))))`;  eth_rx0[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00d4))))`;  eth_rx0[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00d8))))`;  eth_rx0[22]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00dc))))`;  eth_rx0[23]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00e0))))`;  eth_rx0[24]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00e4))))`;  eth_rx0[25]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00e8))))`;  eth_rx0[26]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00ec))))`;  eth_rx0[27]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00f0))))`;  eth_rx0[28]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00f4))))`;  eth_rx0[29]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00f8))))`;  eth_rx0[30]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x00fc))))`;  eth_rx0[31]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0100))))`;  eth_rx0[32]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0104))))`;  eth_rx0[33]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0108))))`;  eth_rx0[34]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x010c))))`;  eth_rx0[35]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0110))))`;  eth_rx0[36]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0114))))`;  eth_rx0[37]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0118))))`;  eth_rx0[38]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x011c))))`;  eth_rx0[39]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0120))))`;  eth_rx0[40]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0124))))`;  eth_rx0[41]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0128))))`;  eth_rx0[42]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x012c))))`;  eth_rx0[43]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0130))))`;  eth_rx0[44]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0134))))`;  eth_rx0[45]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0138))))`;  eth_rx0[46]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x013c))))`;  eth_rx0[47]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0140))))`;  eth_rx0[48]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0144))))`;  eth_rx0[49]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0148))))`;  eth_rx0[50]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x014c))))`;  eth_rx0[51]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0150))))`;  eth_rx0[52]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0154))))`;  eth_rx0[53]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0158))))`;  eth_rx0[54]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x015c))))`;  eth_rx0[55]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0160))))`;  eth_rx0[56]=$((`busybox devmem $tmp_addr `))

#eth1 cfg
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0080))))`;  eth_rx1[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0084))))`;  eth_rx1[1]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0088))))`;  eth_rx1[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x008c))))`;  eth_rx1[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0090))))`;  eth_rx1[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0094))))`;  eth_rx1[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0098))))`;  eth_rx1[6]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x009c))))`;  eth_rx1[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00a0))))`;  eth_rx1[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00a4))))`;  eth_rx1[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00a8))))`;  eth_rx1[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00ac))))`;  eth_rx1[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00b0))))`;  eth_rx1[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00b4))))`;  eth_rx1[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00b8))))`;  eth_rx1[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00bc))))`;  eth_rx1[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00c0))))`;  eth_rx1[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00c4))))`;  eth_rx1[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00c8))))`;  eth_rx1[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00cc))))`;  eth_rx1[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00d0))))`;  eth_rx1[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00d4))))`;  eth_rx1[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00d8))))`;  eth_rx1[22]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00dc))))`;  eth_rx1[23]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00e0))))`;  eth_rx1[24]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00e4))))`;  eth_rx1[25]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00e8))))`;  eth_rx1[26]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00ec))))`;  eth_rx1[27]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00f0))))`;  eth_rx1[28]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00f4))))`;  eth_rx1[29]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00f8))))`;  eth_rx1[30]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x00fc))))`;  eth_rx1[31]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0100))))`;  eth_rx1[32]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0104))))`;  eth_rx1[33]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0108))))`;  eth_rx1[34]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x010c))))`;  eth_rx1[35]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0110))))`;  eth_rx1[36]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0114))))`;  eth_rx1[37]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0118))))`;  eth_rx1[38]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x011c))))`;  eth_rx1[39]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0120))))`;  eth_rx1[40]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0124))))`;  eth_rx1[41]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0128))))`;  eth_rx1[42]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x012c))))`;  eth_rx1[43]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0130))))`;  eth_rx1[44]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0134))))`;  eth_rx1[45]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0138))))`;  eth_rx1[46]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x013c))))`;  eth_rx1[47]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0140))))`;  eth_rx1[48]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0144))))`;  eth_rx1[49]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0148))))`;  eth_rx1[50]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x014c))))`;  eth_rx1[51]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0150))))`;  eth_rx1[52]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0154))))`;  eth_rx1[53]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0158))))`;  eth_rx1[54]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x015c))))`;  eth_rx1[55]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0160))))`;  eth_rx1[56]=$((`busybox devmem $tmp_addr `))

#eth2 cfg
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0080))))`;  eth_rx2[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0084))))`;  eth_rx2[1]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0088))))`;  eth_rx2[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x008c))))`;  eth_rx2[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0090))))`;  eth_rx2[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0094))))`;  eth_rx2[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0098))))`;  eth_rx2[6]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x009c))))`;  eth_rx2[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00a0))))`;  eth_rx2[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00a4))))`;  eth_rx2[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00a8))))`;  eth_rx2[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00ac))))`;  eth_rx2[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00b0))))`;  eth_rx2[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00b4))))`;  eth_rx2[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00b8))))`;  eth_rx2[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00bc))))`;  eth_rx2[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00c0))))`;  eth_rx2[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00c4))))`;  eth_rx2[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00c8))))`;  eth_rx2[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00cc))))`;  eth_rx2[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00d0))))`;  eth_rx2[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00d4))))`;  eth_rx2[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00d8))))`;  eth_rx2[22]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00dc))))`;  eth_rx2[23]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00e0))))`;  eth_rx2[24]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00e4))))`;  eth_rx2[25]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00e8))))`;  eth_rx2[26]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00ec))))`;  eth_rx2[27]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00f0))))`;  eth_rx2[28]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00f4))))`;  eth_rx2[29]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00f8))))`;  eth_rx2[30]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x00fc))))`;  eth_rx2[31]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0100))))`;  eth_rx2[32]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0104))))`;  eth_rx2[33]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0108))))`;  eth_rx2[34]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x010c))))`;  eth_rx2[35]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0110))))`;  eth_rx2[36]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0114))))`;  eth_rx2[37]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0118))))`;  eth_rx2[38]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x011c))))`;  eth_rx2[39]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0120))))`;  eth_rx2[40]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0124))))`;  eth_rx2[41]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0128))))`;  eth_rx2[42]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x012c))))`;  eth_rx2[43]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0130))))`;  eth_rx2[44]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0134))))`;  eth_rx2[45]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0138))))`;  eth_rx2[46]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x013c))))`;  eth_rx2[47]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0140))))`;  eth_rx2[48]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0144))))`;  eth_rx2[49]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0148))))`;  eth_rx2[50]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x014c))))`;  eth_rx2[51]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0150))))`;  eth_rx2[52]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0154))))`;  eth_rx2[53]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0158))))`;  eth_rx2[54]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x015c))))`;  eth_rx2[55]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0160))))`;  eth_rx2[56]=$((`busybox devmem $tmp_addr `))

#eth3 cfg
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0080))))`;  eth_rx3[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0084))))`;  eth_rx3[1]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0088))))`;  eth_rx3[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x008c))))`;  eth_rx3[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0090))))`;  eth_rx3[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0094))))`;  eth_rx3[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0098))))`;  eth_rx3[6]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x009c))))`;  eth_rx3[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00a0))))`;  eth_rx3[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00a4))))`;  eth_rx3[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00a8))))`;  eth_rx3[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00ac))))`;  eth_rx3[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00b0))))`;  eth_rx3[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00b4))))`;  eth_rx3[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00b8))))`;  eth_rx3[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00bc))))`;  eth_rx3[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00c0))))`;  eth_rx3[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00c4))))`;  eth_rx3[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00c8))))`;  eth_rx3[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00cc))))`;  eth_rx3[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00d0))))`;  eth_rx3[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00d4))))`;  eth_rx3[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00d8))))`;  eth_rx3[22]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00dc))))`;  eth_rx3[23]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00e0))))`;  eth_rx3[24]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00e4))))`;  eth_rx3[25]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00e8))))`;  eth_rx3[26]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00ec))))`;  eth_rx3[27]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00f0))))`;  eth_rx3[28]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00f4))))`;  eth_rx3[29]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00f8))))`;  eth_rx3[30]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x00fc))))`;  eth_rx3[31]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0100))))`;  eth_rx3[32]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0104))))`;  eth_rx3[33]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0108))))`;  eth_rx3[34]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x010c))))`;  eth_rx3[35]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0110))))`;  eth_rx3[36]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0114))))`;  eth_rx3[37]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0118))))`;  eth_rx3[38]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x011c))))`;  eth_rx3[39]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0120))))`;  eth_rx3[40]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0124))))`;  eth_rx3[41]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0128))))`;  eth_rx3[42]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x012c))))`;  eth_rx3[43]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0130))))`;  eth_rx3[44]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0134))))`;  eth_rx3[45]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0138))))`;  eth_rx3[46]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x013c))))`;  eth_rx3[47]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0140))))`;  eth_rx3[48]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0144))))`;  eth_rx3[49]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0148))))`;  eth_rx3[50]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x014c))))`;  eth_rx3[51]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0150))))`;  eth_rx3[52]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0154))))`;  eth_rx3[53]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0158))))`;  eth_rx3[54]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x015c))))`;  eth_rx3[55]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0160))))`;  eth_rx3[56]=$((`busybox devmem $tmp_addr `))


                                         
tmp_addr=`printf "0x%08x" $(($addr_eth0+ $((0x0010))))`;  link[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth1+ $((0x0010))))`;  link[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_eth2+ $((0x0010))))`;  link[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_eth3+ $((0x0010))))`;  link[3]=$((`busybox devmem $tmp_addr `))

#urmx
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0100))))`;  urmx0[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0104))))`;  urmx0[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0108))))`;  urmx0[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x010c))))`;  urmx0[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0110))))`;  urmx0[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0114))))`;  urmx0[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0118))))`;  urmx0[6]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x011c))))`;  urmx0[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0120))))`;  urmx0[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0124))))`;  urmx0[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0128))))`;  urmx0[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x012c))))`;  urmx0[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0130))))`;  urmx0[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0134))))`;  urmx0[13]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0138))))`;  urmx0[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x013c))))`;  urmx0[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0140))))`;  urmx0[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0144))))`;  urmx0[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0148))))`;  urmx0[18]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x014c))))`;  urmx0[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0150))))`;  urmx0[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0154))))`;  urmx0[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0158))))`;  urmx0[22]=$((`busybox devmem $tmp_addr `))

tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0200))))`;  urmx1[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0204))))`;  urmx1[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0208))))`;  urmx1[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x020c))))`;  urmx1[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0210))))`;  urmx1[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0214))))`;  urmx1[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0218))))`;  urmx1[6]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x021c))))`;  urmx1[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0220))))`;  urmx1[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0224))))`;  urmx1[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0228))))`;  urmx1[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x022c))))`;  urmx1[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0230))))`;  urmx1[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0234))))`;  urmx1[13]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0238))))`;  urmx1[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x023c))))`;  urmx1[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0240))))`;  urmx1[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0244))))`;  urmx1[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0248))))`;  urmx1[18]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x024c))))`;  urmx1[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0250))))`;  urmx1[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0254))))`;  urmx1[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0258))))`;  urmx1[22]=$((`busybox devmem $tmp_addr `))

tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0300))))`;  urmx2[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0304))))`;  urmx2[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0308))))`;  urmx2[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x030c))))`;  urmx2[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0310))))`;  urmx2[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0314))))`;  urmx2[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0318))))`;  urmx2[6]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x031c))))`;  urmx2[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0320))))`;  urmx2[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0324))))`;  urmx2[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0328))))`;  urmx2[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x032c))))`;  urmx2[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0330))))`;  urmx2[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0334))))`;  urmx2[13]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0338))))`;  urmx2[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x033c))))`;  urmx2[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0340))))`;  urmx2[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0344))))`;  urmx2[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0348))))`;  urmx2[18]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x034c))))`;  urmx2[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0350))))`;  urmx2[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0354))))`;  urmx2[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0358))))`;  urmx2[22]=$((`busybox devmem $tmp_addr `))

tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0400))))`;  urmx3[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0404))))`;  urmx3[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0408))))`;  urmx3[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x040c))))`;  urmx3[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0410))))`;  urmx3[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0414))))`;  urmx3[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0418))))`;  urmx3[6]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x041c))))`;  urmx3[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0420))))`;  urmx3[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0424))))`;  urmx3[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0428))))`;  urmx3[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x042c))))`;  urmx3[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0430))))`;  urmx3[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0434))))`;  urmx3[13]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0438))))`;  urmx3[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x043c))))`;  urmx3[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0440))))`;  urmx3[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0444))))`;  urmx3[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0448))))`;  urmx3[18]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x044c))))`;  urmx3[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0450))))`;  urmx3[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0454))))`;  urmx3[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_urmx+ $((0x0458))))`;  urmx3[22]=$((`busybox devmem $tmp_addr `))

tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x003c))))`;  store[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0040))))`;  store[1]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0044))))`;  store[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0048))))`;  store[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0050))))`;  store[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0054))))`;  store[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0058))))`;  store[6]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x005c))))`;  store[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0064))))`;  store[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0074))))`;  store[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x004c))))`;  store[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_store+ $((0x0060))))`;  store[11]=$((`busybox devmem $tmp_addr `))

store[12]=$((store[8] & 0xffff))
store[13]=$((store[8]>>16))
store[14]=$((store[9] & 0xffff))
store[15]=$((store[9]>>16))

tmp_addr=`printf "0x%08x" $(($addr_pa+ $((0x0100))))`;  pa[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_pa+ $((0x0104))))`;  pa[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_pa+ $((0x0114))))`;  pa[10]=$((`busybox devmem $tmp_addr `))
pa[0]=$((pa[8] & 0xff))
pa[1]=$(($((pa[8] & 0xff00))>>8))
pa[2]=$((pa[8]>>16))
pa[3]=$((pa[9] & 0xff))
pa[4]=$(($((pa[9] & 0xff00))>>8))
pa[5]=$((pa[9]>>16))
pa[6]=$((pa[10] & 0xffff))
pa[7]=$((pa[10]>>16))

tmp_addr=`printf "0x%08x" $(($addr_pro+ $((0x004c))))`;  pro[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_pro+ $((0x0050))))`;  pro[1]=$((`busybox devmem $tmp_addr `))

tmp_addr=`printf "0x%08x" $(($addr_qm+ $((0x0050))))`;  qm[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_qm+ $((0x0054))))`;  qm[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_qm+ $((0x0058))))`;  qm[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_qm+ $((0x005c))))`;  qm[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_qm+ $((0x0030))))`;  qm[12]=$((`busybox devmem $tmp_addr `))
qm[0]=$((qm[8] & 0xffff))
qm[1]=$((qm[8]>>16))
qm[2]=$((qm[9] & 0xffff))
qm[3]=$((qm[9]>>16))
qm[4]=$((qm[10] & 0xffff))
qm[5]=$((qm[10]>>16))
qm[6]=$((qm[11] & 0xffff))
qm[7]=$((qm[11]>>16))
qm[13]=$((qm[12]>>16))


tmp_addr=`printf "0x%08x" $(($addr_ped+ $((0x00a8))))`;  ped[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_ped+ $((0x00ac))))`;  ped[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_ped+ $((0x00b0))))`;  ped[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_ped+ $((0x00b4))))`;  ped[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_ped+ $((0x00b8))))`;  ped[4]=$((`busybox devmem $tmp_addr `))

tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x0140))))`;  uvn[0]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x0144))))`;  uvn[1]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x0158))))`;  uvn[2]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x015c))))`;  uvn[3]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x0160))))`;  uvn[4]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x3000))))`;  uvn[5]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x3004))))`;  uvn[6]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x3008))))`;  uvn[7]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x300c))))`;  uvn[8]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x0170))))`;  uvn[16]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_uvn+ $((0x0034))))`;  uvn[17]=$((`busybox devmem $tmp_addr  `))
uvn[9]=$((uvn[5] & 0xffff))
uvn[10]=$((uvn[5]>>16))
uvn[11]=$((uvn[6] & 0xffff))
uvn[12]=$((uvn[6]>>16))
uvn[13]=$((uvn[7] & 0xffff))
uvn[14]=$((uvn[7]>>16))
uvn[15]=$((uvn[8] & 0xffff))
uvn[18]=$((uvn[16]>>16))


tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x00c0))))`;  dvn[0]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x00c8))))`;  dvn[1]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x00d0))))`;  dvn[2]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x3000))))`;  dvn[3]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x3004))))`;  dvn[4]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x3008))))`;  dvn[5]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x300c))))`;  dvn[6]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x3010))))`;  dvn[7]=$((`busybox devmem $tmp_addr  `))
tmp_addr=`printf "0x%08x" $(($addr_dvn+ $((0x3014))))`;  dvn[8]=$((`busybox devmem $tmp_addr  `))


tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0100))))`;  dmux0[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0104))))`;  dmux0[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0108))))`;  dmux0[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x010c))))`;  dmux0[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0110))))`;  dmux0[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0114))))`;  dmux0[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0118))))`;  dmux0[6]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x011c))))`;  dmux0[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0120))))`;  dmux0[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0124))))`;  dmux0[9]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0128))))`;  dmux0[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x012c))))`;  dmux0[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0130))))`;  dmux0[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0134))))`;  dmux0[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0138))))`;  dmux0[14]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x013c))))`;  dmux0[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0140))))`;  dmux0[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0144))))`;  dmux0[17]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0148))))`;  dmux0[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x014c))))`;  dmux0[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0150))))`;  dmux0[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0154))))`;  dmux0[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0158))))`;  dmux0[22]=$((`busybox devmem $tmp_addr `)) 

tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0200))))`;  dmux1[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0204))))`;  dmux1[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0208))))`;  dmux1[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x020c))))`;  dmux1[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0210))))`;  dmux1[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0214))))`;  dmux1[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0218))))`;  dmux1[6]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x021c))))`;  dmux1[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0220))))`;  dmux1[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0224))))`;  dmux1[9]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0228))))`;  dmux1[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x022c))))`;  dmux1[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0230))))`;  dmux1[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0234))))`;  dmux1[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0238))))`;  dmux1[14]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x023c))))`;  dmux1[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0240))))`;  dmux1[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0244))))`;  dmux1[17]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0248))))`;  dmux1[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x024c))))`;  dmux1[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0250))))`;  dmux1[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0254))))`;  dmux1[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0258))))`;  dmux1[22]=$((`busybox devmem $tmp_addr `)) 

tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0300))))`;  dmux2[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0304))))`;  dmux2[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0308))))`;  dmux2[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x030c))))`;  dmux2[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0310))))`;  dmux2[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0314))))`;  dmux2[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0318))))`;  dmux2[6]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x031c))))`;  dmux2[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0320))))`;  dmux2[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0324))))`;  dmux2[9]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0328))))`;  dmux2[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x032c))))`;  dmux2[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0330))))`;  dmux2[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0334))))`;  dmux2[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0338))))`;  dmux2[14]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x033c))))`;  dmux2[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0340))))`;  dmux2[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0344))))`;  dmux2[17]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0348))))`;  dmux2[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x034c))))`;  dmux2[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0350))))`;  dmux2[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0354))))`;  dmux2[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0358))))`;  dmux2[22]=$((`busybox devmem $tmp_addr `)) 

tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0400))))`;  dmux3[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0404))))`;  dmux3[1]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0408))))`;  dmux3[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x040c))))`;  dmux3[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0410))))`;  dmux3[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0414))))`;  dmux3[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0418))))`;  dmux3[6]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x041c))))`;  dmux3[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0420))))`;  dmux3[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0424))))`;  dmux3[9]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0428))))`;  dmux3[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x042c))))`;  dmux3[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0430))))`;  dmux3[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0434))))`;  dmux3[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0438))))`;  dmux3[14]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x043c))))`;  dmux3[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0440))))`;  dmux3[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0444))))`;  dmux3[17]=$((`busybox devmem $tmp_addr `))             
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0448))))`;  dmux3[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x044c))))`;  dmux3[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0450))))`;  dmux3[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0454))))`;  dmux3[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_dmux+ $((0x0458))))`;  dmux3[22]=$((`busybox devmem $tmp_addr `))

tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0400))))`;  padpt[0]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0404))))`;  padpt[1]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0408))))`;  padpt[2]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x040c))))`;  padpt[3]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0410))))`;  padpt[4]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0414))))`;  padpt[5]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0418))))`;  padpt[6]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x04bc))))`;  padpt[7]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x04c0))))`;  padpt[8]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x04c4))))`;  padpt[9]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x04c8))))`;  padpt[10]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x04cc))))`;  padpt[11]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x08e4))))`;  padpt[12]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x08e8))))`;  padpt[13]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x08ec))))`;  padpt[14]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x08f0))))`;  padpt[15]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x090c))))`;  padpt[16]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0924))))`;  padpt[17]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0928))))`;  padpt[18]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0930))))`;  padpt[19]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0938))))`;  padpt[20]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x093c))))`;  padpt[21]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0950))))`;  padpt[22]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0954))))`;  padpt[23]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0958))))`;  padpt[24]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x095c))))`;  padpt[25]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0960))))`;  padpt[26]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0c04))))`;  padpt[27]=$((`busybox devmem $tmp_addr `))
tmp_addr=`printf "0x%08x" $(($addr_padpt+ $((0x0c84))))`;  padpt[28]=$((`busybox devmem $tmp_addr `))





                          

printf "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"
printf "+prj_4x10ge version=%8x init_flag=%8x interupt_flag=%8x eth0:%1x eth1:%1x eth2:%1x eth3:%1x                             \n" ${greg[0]} ${greg[1]} ${greg[2]} ${link[0]} ${link[1]} ${link[2]} ${link[3]}
if [ "$1" == "all" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++ETH0++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth0_rx:"     ${eth_rx0[0]} "good_pkt:"   ${eth_rx0[1]}          "bytes:" ${eth_rx0[2]}          "good_bytes:"        ${eth_rx0[3]}           "fcs:"         ${eth_rx0[4]}          "fram_err:"        ${eth_rx0[5]}          "bad_code:"        ${eth_rx0[6]} "small:"       ${eth_rx0[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "jabber:"     ${eth_rx0[8]} "large:"   ${eth_rx0[9]}          "oversize:" ${eth_rx0[10]}         "undersize:"        ${eth_rx0[11]}          "toolong:"         ${eth_rx0[12]}         "fragment:"        ${eth_rx0[13]}         "inrangeerr:"        ${eth_rx0[14]}  "bad_preamble:"       ${eth_rx0[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "bad_sfd:"     ${eth_rx0[16]} "64:"  ${eth_rx0[17]}         "65_127:" ${eth_rx0[18]}         "128_255:"        ${eth_rx0[19]}          "256_511:"         ${eth_rx0[20]}         "512_1023:"        ${eth_rx0[21]}         "1024_1518:"        ${eth_rx0[22]}   "1519_1522:"       ${eth_rx0[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1523_1548:"     ${eth_rx0[24]} "1549_2047:"  ${eth_rx0[25]}         "2048_4095:" ${eth_rx0[26]}         "4096_8191:"        ${eth_rx0[27]}          "8192_9215:"         ${eth_rx0[28]}         "unicast:"        ${eth_rx0[29]}         "multicast:"        ${eth_rx0[30]}  "broadcast:"       ${eth_rx0[31]} 
        printf "%12s %8x\n" "vlan:"     ${eth_rx0[32]}
        printf "+++++++++++++++++++++++++++++++++++++RX++ETH1++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth1_rx:"     ${eth_rx1[0]} "good_pkt:"   ${eth_rx1[1]}          "bytes:" ${eth_rx1[2]}          "good_bytes:"        ${eth_rx1[3]}           "fcs:"         ${eth_rx1[4]}          "fram_err:"        ${eth_rx1[5]}          "bad_code:"        ${eth_rx1[6]} "small:"       ${eth_rx1[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "jabber:"     ${eth_rx1[8]} "large:"   ${eth_rx1[9]}          "oversize:" ${eth_rx1[10]}         "undersize:"        ${eth_rx1[11]}          "toolong:"         ${eth_rx1[12]}         "fragment:"        ${eth_rx1[13]}         "inrangeerr:"        ${eth_rx1[14]}  "bad_preamble:"       ${eth_rx1[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "bad_sfd:"     ${eth_rx1[16]} "64:"  ${eth_rx1[17]}         "65_127:" ${eth_rx1[18]}         "128_255:"        ${eth_rx1[19]}          "256_511:"         ${eth_rx1[20]}         "512_1023:"        ${eth_rx1[21]}         "1024_1518:"        ${eth_rx1[22]}   "1519_1522:"       ${eth_rx1[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1523_1548:"     ${eth_rx1[24]} "1549_2047:"  ${eth_rx1[25]}         "2048_4095:" ${eth_rx1[26]}         "4096_8191:"        ${eth_rx1[27]}          "8192_9215:"         ${eth_rx1[28]}         "unicast:"        ${eth_rx1[29]}         "multicast:"        ${eth_rx1[30]}  "broadcast:"       ${eth_rx1[31]} 
        printf "%12s %8x\n" "vlan:"     ${eth_rx1[32]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++ETH2++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth2_rx:"     ${eth_rx2[0]} "good_pkt:"   ${eth_rx2[1]}          "bytes:" ${eth_rx2[2]}          "good_bytes:"        ${eth_rx2[3]}           "fcs:"         ${eth_rx2[4]}          "fram_err:"        ${eth_rx2[5]}          "bad_code:"        ${eth_rx2[6]} "small:"       ${eth_rx2[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "jabber:"     ${eth_rx2[8]} "large:"   ${eth_rx2[9]}          "oversize:" ${eth_rx2[10]}         "undersize:"        ${eth_rx2[11]}          "toolong:"         ${eth_rx2[12]}         "fragment:"        ${eth_rx2[13]}         "inrangeerr:"        ${eth_rx2[14]}  "bad_preamble:"       ${eth_rx2[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "bad_sfd:"     ${eth_rx2[16]} "64:"  ${eth_rx2[17]}         "65_127:" ${eth_rx2[18]}         "128_255:"        ${eth_rx2[19]}          "256_511:"         ${eth_rx2[20]}         "512_1023:"        ${eth_rx2[21]}         "1024_1518:"        ${eth_rx2[22]}   "1519_1522:"       ${eth_rx2[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1523_1548:"     ${eth_rx2[24]} "1549_2047:"  ${eth_rx2[25]}         "2048_4095:" ${eth_rx2[26]}         "4096_8191:"        ${eth_rx2[27]}          "8192_9215:"         ${eth_rx2[28]}         "unicast:"        ${eth_rx2[29]}         "multicast:"        ${eth_rx2[30]}  "broadcast:"       ${eth_rx2[31]} 
        printf "%12s %8x\n" "vlan:"     ${eth_rx2[32]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++ETH3++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth3_rx:"     ${eth_rx3[0]} "good_pkt:"   ${eth_rx3[1]}          "bytes:" ${eth_rx3[2]}          "good_bytes:"        ${eth_rx3[3]}           "fcs:"         ${eth_rx3[4]}          "fram_err:"        ${eth_rx3[5]}          "bad_code:"        ${eth_rx3[6]} "small:"       ${eth_rx3[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "jabber:"     ${eth_rx3[8]} "large:"   ${eth_rx3[9]}          "oversize:" ${eth_rx3[10]}         "undersize:"        ${eth_rx3[11]}          "toolong:"         ${eth_rx3[12]}         "fragment:"        ${eth_rx3[13]}         "inrangeerr:"        ${eth_rx3[14]}  "bad_preamble:"       ${eth_rx3[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "bad_sfd:"     ${eth_rx3[16]} "64:"  ${eth_rx3[17]}         "65_127:" ${eth_rx3[18]}         "128_255:"        ${eth_rx3[19]}          "256_511:"         ${eth_rx3[20]}         "512_1023:"        ${eth_rx3[21]}         "1024_1518:"        ${eth_rx3[22]}   "1519_1522:"       ${eth_rx3[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1523_1548:"     ${eth_rx3[24]} "1549_2047:"  ${eth_rx3[25]}         "2048_4095:" ${eth_rx3[26]}         "4096_8191:"        ${eth_rx3[27]}          "8192_9215:"         ${eth_rx3[28]}         "unicast:"        ${eth_rx3[29]}         "multicast:"        ${eth_rx3[30]}  "broadcast:"       ${eth_rx3[31]} 
        printf "%12s %8x\n" "vlan:"     ${eth_rx3[32]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++URMUX++ETH0+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${urmx0[0]} "h_byte:"   ${urmx0[1]}          "uc:" ${urmx0[2]}          "mc:"        ${urmx0[3]}           "bc:"         ${urmx0[4]}          "pkt:"        ${urmx0[5]}          "less_64:"        ${urmx0[6]} "64:"       ${urmx0[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${urmx0[8]} "128_255:"   ${urmx0[9]}          "256_511:" ${urmx0[10]}         "512_1023:"        ${urmx0[11]}          "1024_1518:"         ${urmx0[12]}         "1519_1522:"        ${urmx0[13]}         "1523_1548:"        ${urmx0[14]}  "1549_2047:"       ${urmx0[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${urmx0[16]} "4096_8191:"  ${urmx0[17]}         "8192_9215:" ${urmx0[18]}         "more_9216:"        ${urmx0[19]}          "overflow:"         ${urmx0[20]}         "crc:"        ${urmx0[21]}         "pause:"        ${urmx0[22]}
        printf "+++++++++++++++++++++++++++++++++++++RX++URMUX++ETH1+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${urmx1[0]} "h_byte:"   ${urmx1[1]}          "uc:" ${urmx1[2]}          "mc:"        ${urmx1[3]}           "bc:"         ${urmx1[4]}          "pkt:"        ${urmx1[5]}          "less_64:"        ${urmx1[6]} "64:"       ${urmx1[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${urmx1[8]} "128_255:"   ${urmx1[9]}          "256_511:" ${urmx1[10]}         "512_1023:"        ${urmx1[11]}          "1024_1518:"         ${urmx1[12]}         "1519_1522:"        ${urmx1[13]}         "1523_1548:"        ${urmx1[14]}  "1549_2047:"       ${urmx1[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${urmx1[16]} "4096_8191:"  ${urmx1[17]}         "8192_9215:" ${urmx1[18]}         "more_9216:"        ${urmx1[19]}          "overflow:"         ${urmx1[20]}         "crc:"        ${urmx1[21]}         "pause:"        ${urmx1[22]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++URMUX++ETH2+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${urmx2[0]} "h_byte:"   ${urmx2[1]}          "uc:" ${urmx2[2]}          "mc:"        ${urmx2[3]}           "bc:"         ${urmx2[4]}          "pkt:"        ${urmx2[5]}          "less_64:"        ${urmx2[6]} "64:"       ${urmx2[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${urmx2[8]} "128_255:"   ${urmx2[9]}          "256_511:" ${urmx2[10]}         "512_1023:"        ${urmx2[11]}          "1024_1518:"         ${urmx2[12]}         "1519_1522:"        ${urmx2[13]}         "1523_1548:"        ${urmx2[14]}  "1549_2047:"       ${urmx2[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${urmx2[16]} "4096_8191:"  ${urmx2[17]}         "8192_9215:" ${urmx2[18]}         "more_9216:"        ${urmx2[19]}          "overflow:"         ${urmx2[20]}         "crc:"        ${urmx2[21]}         "pause:"        ${urmx2[22]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++URMUX++ETH3+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${urmx3[0]} "h_byte:"   ${urmx3[1]}          "uc:" ${urmx3[2]}          "mc:"        ${urmx3[3]}           "bc:"         ${urmx3[4]}          "pkt:"        ${urmx3[5]}          "less_64:"        ${urmx3[6]} "64:"       ${urmx3[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${urmx3[8]} "128_255:"   ${urmx3[9]}          "256_511:" ${urmx3[10]}         "512_1023:"        ${urmx3[11]}          "1024_1518:"         ${urmx3[12]}         "1519_1522:"        ${urmx3[13]}         "1523_1548:"        ${urmx3[14]}  "1549_2047:"       ${urmx3[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${urmx3[16]} "4096_8191:"  ${urmx3[17]}         "8192_9215:" ${urmx3[18]}         "more_9216:"        ${urmx3[19]}          "overflow:"         ${urmx3[20]}         "crc:"        ${urmx3[21]}         "pause:"        ${urmx3[22]}  
        printf "+++++++++++++++++++++++++++++++++++++RX++STORE+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth0_pkt_in:"     ${store[0]} "eth1_pkt_in:"   ${store[1]}          "eth2_pkt_in:" ${store[2]}          "eth3_pkt_in:"        ${store[3]}           "eth0_pkt_o:"         ${store[4]}          "eth1_pkt_o:"        ${store[5]}          "eth2_pkt_o:"        ${store[6]} "eth3_pkt_o:"       ${store[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "pkt_cell:"     ${store[12]} "ptr_req:"   ${store[13]}          "dn_eop_err:" ${store[14]}         "up_eop_err:"        ${store[15]}
        printf "+++++++++++++++++++++++++++++++++++++RX++PA++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eop_r:"     ${pa[0]} "sop_r:"   ${pa[1]}          "info_r:" ${pa[2]}          "cpucap_type:"        ${pa[3]}           "rsv_type:"         ${pa[4]}          "drop_type:"        ${pa[5]}          "pa_pro_r:"        ${pa[6]} "pa_pro_w:"       ${pa[7]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++PRO+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x\n"  "in_info_r:"     ${pro[0]} "out_info_r:"     ${pro[1]}   
        printf "+++++++++++++++++++++++++++++++++++++RX++QM++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "port0_drop:"     ${qm[0]} "port1_drop:"   ${qm[1]}          "port2_drop:" ${qm[2]}          "port3_drop:"        ${qm[3]}           "port4_drop:"         ${qm[4]}          "port4_drop:"        ${qm[5]}          "port6_drop:"        ${qm[6]} "port7_drop:"       ${qm[7]} 
        printf "%13s %8x\n" "pntr_cfg_debug:" ${qm[13]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++PED+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x\n"  "uvn_info_wr:"     ${ped[4]}  
        printf "+++++++++++++++++++++++++++++++++++++RX++UVN+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "r_pre_fifo:"     ${uvn[0]} "fsm_debug:"   ${uvn[1]}          "eop_err:" ${uvn[2]}          "wback_pkt:"        ${uvn[3]}    "wback_desc:"        ${uvn[4]}   "pkt_drop:"  ${uvn[9]} "desc_err:"   ${uvn[10]}          "pkt_in:" ${uvn[11]}             
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x\n"  "pkt_out:"        ${uvn[12]}  "desc_rd:"     ${uvn[13]}  "desc_wd:"   ${uvn[14]}         "notify:"  ${uvn[15]} 
        printf "%12s %8x  %12s %8x\n"  "drop_cnt:"       ${uvn[18]}  "rd_dma_dly:"  ${uvn[17]}   
        printf "+++++++++++++++++++++++++++++++++++++TX++ETH0++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "eth0_tx:"     ${eth_rx0[33]} "good_pkt:"     ${eth_rx0[34]} "bytes:"     ${eth_rx0[35]} "good_bytes:"     ${eth_rx0[36]} "small:" ${eth_rx0[37]} "large:"     ${eth_rx0[38]} "fcs:"     ${eth_rx0[39]} "fram_err:"     ${eth_rx0[40]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "64:"     ${eth_rx0[41]} "65_127:"     ${eth_rx0[42]} "128_255:"     ${eth_rx0[43]} "256_511:"     ${eth_rx0[44]}  "512_1023:" ${eth_rx0[45]} "1024_1518:"     ${eth_rx0[46]} "1519_1522:"     ${eth_rx0[47]} "1523_1548:"     ${eth_rx0[48]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "1549_2047:"     ${eth_rx0[49]} "2048_4095:"     ${eth_rx0[50]}   "4096_8191:"     ${eth_rx0[51]} "8192_9215:"     ${eth_rx0[52]} "unicast:"  ${eth_rx0[53]} "multicast:"     ${eth_rx0[54]} "broadcast:"     ${eth_rx0[55]} "vlan:"     ${eth_rx0[56]} 
        printf "+++++++++++++++++++++++++++++++++++++TX++ETH1++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "eth1_tx:"     ${eth_rx1[33]} "good_pkt:"     ${eth_rx1[34]} "bytes:"     ${eth_rx1[35]} "good_bytes:"     ${eth_rx1[36]} "small:" ${eth_rx1[37]} "large:"     ${eth_rx1[38]} "fcs:"     ${eth_rx1[39]} "fram_err:"     ${eth_rx1[40]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "64:"     ${eth_rx1[41]} "65_127:"     ${eth_rx1[42]} "128_255:"     ${eth_rx1[43]} "256_511:"     ${eth_rx1[44]}  "512_1023:" ${eth_rx1[45]} "1024_1518:"     ${eth_rx1[46]} "1519_1522:"     ${eth_rx1[47]} "1523_1548:"     ${eth_rx1[48]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "1549_2047:"     ${eth_rx1[49]} "2048_4095:"     ${eth_rx1[50]}   "4096_8191:"     ${eth_rx1[51]} "8192_9215:"     ${eth_rx1[52]} "unicast:"  ${eth_rx1[53]} "multicast:"     ${eth_rx1[54]} "broadcast:"     ${eth_rx1[55]} "vlan:"     ${eth_rx1[56]} 
        printf "+++++++++++++++++++++++++++++++++++++TX++ETH2++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "eth2_tx:"     ${eth_rx2[33]} "good_pkt:"     ${eth_rx2[34]} "bytes:"     ${eth_rx2[35]} "good_bytes:"     ${eth_rx2[36]} "small:" ${eth_rx2[37]} "large:"     ${eth_rx2[38]} "fcs:"     ${eth_rx2[39]} "fram_err:"     ${eth_rx2[40]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "64:"     ${eth_rx2[41]} "65_127:"     ${eth_rx2[42]} "128_255:"     ${eth_rx2[43]} "256_511:"     ${eth_rx2[44]}  "512_1023:" ${eth_rx2[45]} "1024_1518:"     ${eth_rx2[46]} "1519_1522:"     ${eth_rx2[47]} "1523_1548:"     ${eth_rx2[48]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "1549_2047:"     ${eth_rx2[49]} "2048_4095:"     ${eth_rx2[50]}   "4096_8191:"     ${eth_rx2[51]} "8192_9215:"     ${eth_rx2[52]} "unicast:"  ${eth_rx2[53]} "multicast:"     ${eth_rx2[54]} "broadcast:"     ${eth_rx2[55]} "vlan:"     ${eth_rx2[56]} 
        printf "+++++++++++++++++++++++++++++++++++++TX++ETH3++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "eth3_tx:"     ${eth_rx3[33]} "good_pkt:"     ${eth_rx3[34]} "bytes:"     ${eth_rx3[35]} "good_bytes:"     ${eth_rx3[36]} "small:" ${eth_rx3[37]} "large:"     ${eth_rx3[38]} "fcs:"     ${eth_rx3[39]} "fram_err:"     ${eth_rx3[40]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "64:"     ${eth_rx3[41]} "65_127:"     ${eth_rx3[42]} "128_255:"     ${eth_rx3[43]} "256_511:"     ${eth_rx3[44]}  "512_1023:" ${eth_rx3[45]} "1024_1518:"     ${eth_rx3[46]} "1519_1522:"     ${eth_rx3[47]} "1523_1548:"     ${eth_rx3[48]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "1549_2047:"     ${eth_rx3[49]} "2048_4095:"     ${eth_rx3[50]}   "4096_8191:"     ${eth_rx3[51]} "8192_9215:"     ${eth_rx3[52]} "unicast:"  ${eth_rx3[53]} "multicast:"     ${eth_rx3[54]} "broadcast:"     ${eth_rx3[55]} "vlan:"     ${eth_rx3[56]} 
        printf "+++++++++++++++++++++++++++++++++++++TX++STORE+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x\n"  "dvn_in_pkt:"     ${store[10]} "dvn_out_pkt:"     ${store[11]}  
        printf "+++++++++++++++++++++++++++++++++++++TX++PED+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "eth0_inf_wr:"     ${ped[0]} "eth1_inf_wr:"   ${ped[1]}          "eth2_inf_wr:" ${ped[2]}          "eth3_inf_wr:"        ${ped[3]}
        printf "+++++++++++++++++++++++++++++++++++++TX++DVN+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s  %8x %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "rdpkt_inf_w:"     ${dvn[0]} "wrdesc_dma:"   ${dvn[1]}          "descpro_in:" ${dvn[2]}  "pkt_get:"        ${dvn[3]}           "pkt_out:"         ${dvn[4]}          "pkt_drop:"        ${dvn[5]}          "sw_notify:"        ${dvn[6]} "pkt_dsch:"       ${dvn[7]} 
        printf "%12s %8x\n" "hd_notify:"     ${dvn[8]}
        printf "+++++++++++++++++++++++++++++++++++++TX++DMUX++ETH0++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${dmux0[0]} "h_byte:"   ${dmux0[1]}          "uc:" ${dmux0[2]}          "mc:"        ${dmux0[3]}           "bc:"         ${dmux0[4]}          "pkt:"        ${dmux0[5]}          "less_64:"        ${dmux0[6]} "64:"       ${dmux0[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${dmux0[8]} "128_255:"   ${dmux0[9]}          "256_511:" ${dmux0[10]}         "512_1023:"        ${dmux0[11]}          "1024_1518:"         ${dmux0[12]}         "1519_1522:"        ${dmux0[13]}         "1523_1548:"        ${dmux0[14]}  "1549_2047:"       ${dmux0[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${dmux0[16]} "4096_8191:"  ${dmux0[17]}         "8192_9215:" ${dmux0[18]}         "more_9216:"        ${dmux0[19]}          "overflow:"         ${dmux0[20]}         "crc:"        ${dmux0[21]}         "pause:"        ${dmux0[22]}
        printf "+++++++++++++++++++++++++++++++++++++TX++DMUX++ETH1++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${dmux1[0]} "h_byte:"   ${dmux1[1]}          "uc:" ${dmux1[2]}          "mc:"        ${dmux1[3]}           "bc:"         ${dmux1[4]}          "pkt:"        ${dmux1[5]}          "less_64:"        ${dmux1[6]} "64:"       ${dmux1[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${dmux1[8]} "128_255:"   ${dmux1[9]}          "256_511:" ${dmux1[10]}         "512_1023:"        ${dmux1[11]}          "1024_1518:"         ${dmux1[12]}         "1519_1522:"        ${dmux1[13]}         "1523_1548:"        ${dmux1[14]}  "1549_2047:"       ${dmux1[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${dmux1[16]} "4096_8191:"  ${dmux1[17]}         "8192_9215:" ${dmux1[18]}         "more_9216:"        ${dmux1[19]}          "overflow:"         ${dmux1[20]}         "crc:"        ${dmux1[21]}         "pause:"        ${dmux1[22]}
        printf "+++++++++++++++++++++++++++++++++++++TX++DMUX++ETH2++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${dmux2[0]} "h_byte:"   ${dmux2[1]}          "uc:" ${dmux2[2]}          "mc:"        ${dmux2[3]}           "bc:"         ${dmux2[4]}          "pkt:"        ${dmux2[5]}          "less_64:"        ${dmux2[6]} "64:"       ${dmux2[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${dmux2[8]} "128_255:"   ${dmux2[9]}          "256_511:" ${dmux2[10]}         "512_1023:"        ${dmux2[11]}          "1024_1518:"         ${dmux2[12]}         "1519_1522:"        ${dmux2[13]}         "1523_1548:"        ${dmux2[14]}  "1549_2047:"       ${dmux2[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${dmux2[16]} "4096_8191:"  ${dmux2[17]}         "8192_9215:" ${dmux2[18]}         "more_9216:"        ${dmux2[19]}          "overflow:"         ${dmux2[20]}         "crc:"        ${dmux2[21]}         "pause:"        ${dmux2[22]}
        printf "+++++++++++++++++++++++++++++++++++++TX++DMUX++ETH3++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${dmux3[0]} "h_byte:"   ${dmux3[1]}          "uc:" ${dmux3[2]}          "mc:"        ${dmux3[3]}           "bc:"         ${dmux3[4]}          "pkt:"        ${dmux3[5]}          "less_64:"        ${dmux3[6]} "64:"       ${dmux3[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${dmux3[8]} "128_255:"   ${dmux3[9]}          "256_511:" ${dmux3[10]}         "512_1023:"        ${dmux3[11]}          "1024_1518:"         ${dmux3[12]}         "1519_1522:"        ${dmux3[13]}         "1523_1548:"        ${dmux3[14]}  "1549_2047:"       ${dmux3[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${dmux3[16]} "4096_8191:"  ${dmux3[17]}         "8192_9215:" ${dmux3[18]}         "more_9216:"        ${dmux3[19]}          "overflow:"         ${dmux3[20]}         "crc:"        ${dmux3[21]}         "pause:"        ${dmux3[22]}
        printf "+++++++++++++++++++++++++++++++++++++PADPT+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "rdif_ack:"     ${padpt[0]} "rdif_eob:"   ${padpt[1]}          "rdif_err:" ${padpt[2]}          "rdif_info:"        ${padpt[3]}           "rdif_reob:"         ${padpt[4]}          "rdif_rerr:"        ${padpt[5]}          "edif_inf_err:"        ${padpt[6]} "wdif_err:"       ${padpt[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "wdif_ack:"     ${padpt[8]} "wdif_eob:"   ${padpt[9]}          "wdif_info:" ${padpt[10]}         "wdif_inf_err:"        ${padpt[11]}          "sel_tag:"         ${padpt[12]}         "rx_tag:"        ${padpt[13]}         "err_tag:"        ${padpt[14]}  "aged_tag:"       ${padpt[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "tag_rls:"     ${padpt[16]} "aged_max_t:"  ${padpt[17]}         "aged_avr_t:" ${padpt[18]}         "req_debug:"        ${padpt[19]}          "rq_cnt:"         ${padpt[20]}         "rc_cnt:"        ${padpt[21]}         "rq_speed:"        ${padpt[22]}   "rc_speed:"       ${padpt[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "rq_nordy_spd:"     ${padpt[24]} "rq_vld_spd:"  ${padpt[25]}         "rc_vld_spd:" ${padpt[26]}         "mux_msix:"        ${padpt[27]}          "msix:"         ${padpt[28]} 
elif [ "$1" == "eth_rx" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++ETH0++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth0_rx:"     ${eth_rx0[0]} "good_pkt:"   ${eth_rx0[1]}          "bytes:" ${eth_rx0[2]}          "good_bytes:"        ${eth_rx0[3]}           "fcs:"         ${eth_rx0[4]}          "fram_err:"        ${eth_rx0[5]}          "bad_code:"        ${eth_rx0[6]} "small:"       ${eth_rx0[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "jabber:"     ${eth_rx0[8]} "large:"   ${eth_rx0[9]}          "oversize:" ${eth_rx0[10]}         "undersize:"        ${eth_rx0[11]}          "toolong:"         ${eth_rx0[12]}         "fragment:"        ${eth_rx0[13]}         "inrangeerr:"        ${eth_rx0[14]}  "bad_preamble:"       ${eth_rx0[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "bad_sfd:"     ${eth_rx0[16]} "64:"  ${eth_rx0[17]}         "65_127:" ${eth_rx0[18]}         "128_255:"        ${eth_rx0[19]}          "256_511:"         ${eth_rx0[20]}         "512_1023:"        ${eth_rx0[21]}         "1024_1518:"        ${eth_rx0[22]}   "1519_1522:"       ${eth_rx0[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1523_1548:"     ${eth_rx0[24]} "1549_2047:"  ${eth_rx0[25]}         "2048_4095:" ${eth_rx0[26]}         "4096_8191:"        ${eth_rx0[27]}          "8192_9215:"         ${eth_rx0[28]}         "unicast:"        ${eth_rx0[29]}         "multicast:"        ${eth_rx0[30]}  "broadcast:"       ${eth_rx0[31]} 
        printf "%12s %8x\n" "vlan:"     ${eth_rx0[32]}
        printf "+++++++++++++++++++++++++++++++++++++RX++ETH1++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth1_rx:"     ${eth_rx1[0]} "good_pkt:"   ${eth_rx1[1]}          "bytes:" ${eth_rx1[2]}          "good_bytes:"        ${eth_rx1[3]}           "fcs:"         ${eth_rx1[4]}          "fram_err:"        ${eth_rx1[5]}          "bad_code:"        ${eth_rx1[6]} "small:"       ${eth_rx1[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "jabber:"     ${eth_rx1[8]} "large:"   ${eth_rx1[9]}          "oversize:" ${eth_rx1[10]}         "undersize:"        ${eth_rx1[11]}          "toolong:"         ${eth_rx1[12]}         "fragment:"        ${eth_rx1[13]}         "inrangeerr:"        ${eth_rx1[14]}  "bad_preamble:"       ${eth_rx1[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "bad_sfd:"     ${eth_rx1[16]} "64:"  ${eth_rx1[17]}         "65_127:" ${eth_rx1[18]}         "128_255:"        ${eth_rx1[19]}          "256_511:"         ${eth_rx1[20]}         "512_1023:"        ${eth_rx1[21]}         "1024_1518:"        ${eth_rx1[22]}   "1519_1522:"       ${eth_rx1[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1523_1548:"     ${eth_rx1[24]} "1549_2047:"  ${eth_rx1[25]}         "2048_4095:" ${eth_rx1[26]}         "4096_8191:"        ${eth_rx1[27]}          "8192_9215:"         ${eth_rx1[28]}         "unicast:"        ${eth_rx1[29]}         "multicast:"        ${eth_rx1[30]}  "broadcast:"       ${eth_rx1[31]} 
        printf "%12s %8x\n" "vlan:"     ${eth_rx1[32]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++ETH2++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth2_rx:"     ${eth_rx2[0]} "good_pkt:"   ${eth_rx2[1]}          "bytes:" ${eth_rx2[2]}          "good_bytes:"        ${eth_rx2[3]}           "fcs:"         ${eth_rx2[4]}          "fram_err:"        ${eth_rx2[5]}          "bad_code:"        ${eth_rx2[6]} "small:"       ${eth_rx2[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "jabber:"     ${eth_rx2[8]} "large:"   ${eth_rx2[9]}          "oversize:" ${eth_rx2[10]}         "undersize:"        ${eth_rx2[11]}          "toolong:"         ${eth_rx2[12]}         "fragment:"        ${eth_rx2[13]}         "inrangeerr:"        ${eth_rx2[14]}  "bad_preamble:"       ${eth_rx2[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "bad_sfd:"     ${eth_rx2[16]} "64:"  ${eth_rx2[17]}         "65_127:" ${eth_rx2[18]}         "128_255:"        ${eth_rx2[19]}          "256_511:"         ${eth_rx2[20]}         "512_1023:"        ${eth_rx2[21]}         "1024_1518:"        ${eth_rx2[22]}   "1519_1522:"       ${eth_rx2[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1523_1548:"     ${eth_rx2[24]} "1549_2047:"  ${eth_rx2[25]}         "2048_4095:" ${eth_rx2[26]}         "4096_8191:"        ${eth_rx2[27]}          "8192_9215:"         ${eth_rx2[28]}         "unicast:"        ${eth_rx2[29]}         "multicast:"        ${eth_rx2[30]}  "broadcast:"       ${eth_rx2[31]} 
        printf "%12s %8x\n" "vlan:"     ${eth_rx2[32]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++ETH3++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth3_rx:"     ${eth_rx3[0]} "good_pkt:"   ${eth_rx3[1]}          "bytes:" ${eth_rx3[2]}          "good_bytes:"        ${eth_rx3[3]}           "fcs:"         ${eth_rx3[4]}          "fram_err:"        ${eth_rx3[5]}          "bad_code:"        ${eth_rx3[6]} "small:"       ${eth_rx3[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "jabber:"     ${eth_rx3[8]} "large:"   ${eth_rx3[9]}          "oversize:" ${eth_rx3[10]}         "undersize:"        ${eth_rx3[11]}          "toolong:"         ${eth_rx3[12]}         "fragment:"        ${eth_rx3[13]}         "inrangeerr:"        ${eth_rx3[14]}  "bad_preamble:"       ${eth_rx3[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "bad_sfd:"     ${eth_rx3[16]} "64:"  ${eth_rx3[17]}         "65_127:" ${eth_rx3[18]}         "128_255:"        ${eth_rx3[19]}          "256_511:"         ${eth_rx3[20]}         "512_1023:"        ${eth_rx3[21]}         "1024_1518:"        ${eth_rx3[22]}   "1519_1522:"       ${eth_rx3[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1523_1548:"     ${eth_rx3[24]} "1549_2047:"  ${eth_rx3[25]}         "2048_4095:" ${eth_rx3[26]}         "4096_8191:"        ${eth_rx3[27]}          "8192_9215:"         ${eth_rx3[28]}         "unicast:"        ${eth_rx3[29]}         "multicast:"        ${eth_rx3[30]}  "broadcast:"       ${eth_rx3[31]} 
        printf "%12s %8x\n" "vlan:"     ${eth_rx3[32]}
elif [ "$1" == "urmux" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++URMUX++ETH0+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${urmx0[0]} "h_byte:"   ${urmx0[1]}          "uc:" ${urmx0[2]}          "mc:"        ${urmx0[3]}           "bc:"         ${urmx0[4]}          "pkt:"        ${urmx0[5]}          "less_64:"        ${urmx0[6]} "64:"       ${urmx0[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${urmx0[8]} "128_255:"   ${urmx0[9]}          "256_511:" ${urmx0[10]}         "512_1023:"        ${urmx0[11]}          "1024_1518:"         ${urmx0[12]}         "1519_1522:"        ${urmx0[13]}         "1523_1548:"        ${urmx0[14]}  "1549_2047:"       ${urmx0[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${urmx0[16]} "4096_8191:"  ${urmx0[17]}         "8192_9215:" ${urmx0[18]}         "more_9216:"        ${urmx0[19]}          "overflow:"         ${urmx0[20]}         "crc:"        ${urmx0[21]}         "pause:"        ${urmx0[22]}
        printf "+++++++++++++++++++++++++++++++++++++RX++URMUX++ETH1+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${urmx1[0]} "h_byte:"   ${urmx1[1]}          "uc:" ${urmx1[2]}          "mc:"        ${urmx1[3]}           "bc:"         ${urmx1[4]}          "pkt:"        ${urmx1[5]}          "less_64:"        ${urmx1[6]} "64:"       ${urmx1[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${urmx1[8]} "128_255:"   ${urmx1[9]}          "256_511:" ${urmx1[10]}         "512_1023:"        ${urmx1[11]}          "1024_1518:"         ${urmx1[12]}         "1519_1522:"        ${urmx1[13]}         "1523_1548:"        ${urmx1[14]}  "1549_2047:"       ${urmx1[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${urmx1[16]} "4096_8191:"  ${urmx1[17]}         "8192_9215:" ${urmx1[18]}         "more_9216:"        ${urmx1[19]}          "overflow:"         ${urmx1[20]}         "crc:"        ${urmx1[21]}         "pause:"        ${urmx1[22]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++URMUX++ETH2+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${urmx2[0]} "h_byte:"   ${urmx2[1]}          "uc:" ${urmx2[2]}          "mc:"        ${urmx2[3]}           "bc:"         ${urmx2[4]}          "pkt:"        ${urmx2[5]}          "less_64:"        ${urmx2[6]} "64:"       ${urmx2[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${urmx2[8]} "128_255:"   ${urmx2[9]}          "256_511:" ${urmx2[10]}         "512_1023:"        ${urmx2[11]}          "1024_1518:"         ${urmx2[12]}         "1519_1522:"        ${urmx2[13]}         "1523_1548:"        ${urmx2[14]}  "1549_2047:"       ${urmx2[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${urmx2[16]} "4096_8191:"  ${urmx2[17]}         "8192_9215:" ${urmx2[18]}         "more_9216:"        ${urmx2[19]}          "overflow:"         ${urmx2[20]}         "crc:"        ${urmx2[21]}         "pause:"        ${urmx2[22]} 
        printf "+++++++++++++++++++++++++++++++++++++RX++URMUX++ETH3+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${urmx3[0]} "h_byte:"   ${urmx3[1]}          "uc:" ${urmx3[2]}          "mc:"        ${urmx3[3]}           "bc:"         ${urmx3[4]}          "pkt:"        ${urmx3[5]}          "less_64:"        ${urmx3[6]} "64:"       ${urmx3[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${urmx3[8]} "128_255:"   ${urmx3[9]}          "256_511:" ${urmx3[10]}         "512_1023:"        ${urmx3[11]}          "1024_1518:"         ${urmx3[12]}         "1519_1522:"        ${urmx3[13]}         "1523_1548:"        ${urmx3[14]}  "1549_2047:"       ${urmx3[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${urmx3[16]} "4096_8191:"  ${urmx3[17]}         "8192_9215:" ${urmx3[18]}         "more_9216:"        ${urmx3[19]}          "overflow:"         ${urmx3[20]}         "crc:"        ${urmx3[21]}         "pause:"        ${urmx3[22]}  
elif [ "$1" == "store" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++STORE+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eth0_pkt_in:"     ${store[0]} "eth1_pkt_in:"   ${store[1]}          "eth2_pkt_in:" ${store[2]}          "eth3_pkt_in:"        ${store[3]}           "eth0_pkt_o:"         ${store[4]}          "eth1_pkt_o:"        ${store[5]}          "eth2_pkt_o:"        ${store[6]} "eth3_pkt_o:"       ${store[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "pkt_cell:"     ${store[12]} "ptr_req:"   ${store[13]}          "dn_eop_err:" ${store[14]}         "up_eop_err:"        ${store[15]}
elif [ "$1" == "pa" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++PA++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "eop_r:"     ${pa[0]} "sop_r:"   ${pa[1]}          "info_r:" ${pa[2]}          "cpucap_type:"        ${pa[3]}           "rsv_type:"         ${pa[4]}          "drop_type:"        ${pa[5]}          "pa_pro_r:"        ${pa[6]} "pa_pro_w:"       ${pa[7]}
elif [ "$1" == "pro" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++PRO+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x\n"  "in_info_r:"     ${pro[0]} "out_info_r:"     ${pro[1]}  
elif [ "$1" == "qm" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++QM++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "port0_drop:"     ${qm[0]} "port1_drop:"   ${qm[1]}          "port2_drop:" ${qm[2]}          "port3_drop:"        ${qm[3]}           "port4_drop:"         ${qm[4]}          "port4_drop:"        ${qm[5]}          "port6_drop:"        ${qm[6]} "port7_drop:"       ${qm[7]} 
        printf "%13s %8x\n" "pntr_cfg_debug:" ${qm[13]} 
elif [ "$1" == "ped" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++PED+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x\n"  "uvn_info_wr:"     ${ped[4]}
elif [ "$1" == "uvn" ]
then
        printf "+++++++++++++++++++++++++++++++++++++RX++UVN+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "r_pre_fifo:"     ${uvn[0]} "fsm_debug:"   ${uvn[1]}          "eop_err:" ${uvn[2]}          "wback_pkt:"        ${uvn[3]}    "wback_desc:"        ${uvn[4]}   "pkt_drop:"  ${uvn[9]} "desc_err:"   ${uvn[10]}          "pkt_in:" ${uvn[11]}             
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x\n"  "pkt_out:"        ${uvn[12]}  "desc_rd:"     ${uvn[13]}  "desc_wd:"   ${uvn[14]}         "notify:"  ${uvn[15]} 
        printf "%12s %8x  %12s %8x\n"  "drop_cnt:"       ${uvn[18]}  "rd_dma_dly:"  ${uvn[17]}   
elif [ "$1" == "eth_tx" ]
then
        printf "+++++++++++++++++++++++++++++++++++++TX++ETH0++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "eth0_tx:"     ${eth_rx0[33]} "good_pkt:"     ${eth_rx0[34]} "bytes:"     ${eth_rx0[35]} "good_bytes:"     ${eth_rx0[36]} "small:" ${eth_rx0[37]} "large:"     ${eth_rx0[38]} "fcs:"     ${eth_rx0[39]} "fram_err:"     ${eth_rx0[40]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "64:"     ${eth_rx0[41]} "65_127:"     ${eth_rx0[42]} "128_255:"     ${eth_rx0[43]} "256_511:"     ${eth_rx0[44]}  "512_1023:" ${eth_rx0[45]} "1024_1518:"     ${eth_rx0[46]} "1519_1522:"     ${eth_rx0[47]} "1523_1548:"     ${eth_rx0[48]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "1549_2047:"     ${eth_rx0[49]} "2048_4095:"     ${eth_rx0[50]}   "4096_8191:"     ${eth_rx0[51]} "8192_9215:"     ${eth_rx0[52]} "unicast:"  ${eth_rx0[53]} "multicast:"     ${eth_rx0[54]} "broadcast:"     ${eth_rx0[55]} "vlan:"     ${eth_rx0[56]} 
        printf "+++++++++++++++++++++++++++++++++++++TX++ETH1++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "eth1_tx:"     ${eth_rx1[33]} "good_pkt:"     ${eth_rx1[34]} "bytes:"     ${eth_rx1[35]} "good_bytes:"     ${eth_rx1[36]} "small:" ${eth_rx1[37]} "large:"     ${eth_rx1[38]} "fcs:"     ${eth_rx1[39]} "fram_err:"     ${eth_rx1[40]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "64:"     ${eth_rx1[41]} "65_127:"     ${eth_rx1[42]} "128_255:"     ${eth_rx1[43]} "256_511:"     ${eth_rx1[44]}  "512_1023:" ${eth_rx1[45]} "1024_1518:"     ${eth_rx1[46]} "1519_1522:"     ${eth_rx1[47]} "1523_1548:"     ${eth_rx1[48]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "1549_2047:"     ${eth_rx1[49]} "2048_4095:"     ${eth_rx1[50]}   "4096_8191:"     ${eth_rx1[51]} "8192_9215:"     ${eth_rx1[52]} "unicast:"  ${eth_rx1[53]} "multicast:"     ${eth_rx1[54]} "broadcast:"     ${eth_rx1[55]} "vlan:"     ${eth_rx1[56]} 
        printf "+++++++++++++++++++++++++++++++++++++TX++ETH2++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "eth2_tx:"     ${eth_rx2[33]} "good_pkt:"     ${eth_rx2[34]} "bytes:"     ${eth_rx2[35]} "good_bytes:"     ${eth_rx2[36]} "small:" ${eth_rx2[37]} "large:"     ${eth_rx2[38]} "fcs:"     ${eth_rx2[39]} "fram_err:"     ${eth_rx2[40]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "64:"     ${eth_rx2[41]} "65_127:"     ${eth_rx2[42]} "128_255:"     ${eth_rx2[43]} "256_511:"     ${eth_rx2[44]}  "512_1023:" ${eth_rx2[45]} "1024_1518:"     ${eth_rx2[46]} "1519_1522:"     ${eth_rx2[47]} "1523_1548:"     ${eth_rx2[48]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "1549_2047:"     ${eth_rx2[49]} "2048_4095:"     ${eth_rx2[50]}   "4096_8191:"     ${eth_rx2[51]} "8192_9215:"     ${eth_rx2[52]} "unicast:"  ${eth_rx2[53]} "multicast:"     ${eth_rx2[54]} "broadcast:"     ${eth_rx2[55]} "vlan:"     ${eth_rx2[56]} 
        printf "+++++++++++++++++++++++++++++++++++++TX++ETH3++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "eth3_tx:"     ${eth_rx3[33]} "good_pkt:"     ${eth_rx3[34]} "bytes:"     ${eth_rx3[35]} "good_bytes:"     ${eth_rx3[36]} "small:" ${eth_rx3[37]} "large:"     ${eth_rx3[38]} "fcs:"     ${eth_rx3[39]} "fram_err:"     ${eth_rx3[40]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "64:"     ${eth_rx3[41]} "65_127:"     ${eth_rx3[42]} "128_255:"     ${eth_rx3[43]} "256_511:"     ${eth_rx3[44]}  "512_1023:" ${eth_rx3[45]} "1024_1518:"     ${eth_rx3[46]} "1519_1522:"     ${eth_rx3[47]} "1523_1548:"     ${eth_rx3[48]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n"  "1549_2047:"     ${eth_rx3[49]} "2048_4095:"     ${eth_rx3[50]}   "4096_8191:"     ${eth_rx3[51]} "8192_9215:"     ${eth_rx3[52]} "unicast:"  ${eth_rx3[53]} "multicast:"     ${eth_rx3[54]} "broadcast:"     ${eth_rx3[55]} "vlan:"     ${eth_rx3[56]} 
elif [ "$1" == "store_tx" ]
then
        printf "+++++++++++++++++++++++++++++++++++++TX++STORE+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x\n"  "dvn_in_pkt:"     ${store[10]} "dvn_out_pkt:"     ${store[11]}
elif [ "$1" == "ped_tx" ]
then
        printf "+++++++++++++++++++++++++++++++++++++TX++PED+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "eth0_inf_wr:"     ${ped[0]} "eth1_inf_wr:"   ${ped[1]}          "eth2_inf_wr:" ${ped[2]}          "eth3_inf_wr:"        ${ped[3]}
elif [ "$1" == "dvn" ]
then
        printf "+++++++++++++++++++++++++++++++++++++TX++DVN+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s  %8x %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "rdpkt_inf_w:"     ${dvn[0]} "wrdesc_dma:"   ${dvn[1]}          "descpro_in:" ${dvn[2]}  "pkt_get:"        ${dvn[3]}           "pkt_out:"         ${dvn[4]}          "pkt_drop:"        ${dvn[5]}          "sw_notify:"        ${dvn[6]} "pkt_dsch:"       ${dvn[7]} 
        printf "%12s %8x\n" "hd_notify:"     ${dvn[8]}
elif [ "$1" == "dmux" ]
then
        printf "+++++++++++++++++++++++++++++++++++++TX++DMUX++ETH0++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${dmux0[0]} "h_byte:"   ${dmux0[1]}          "uc:" ${dmux0[2]}          "mc:"        ${dmux0[3]}           "bc:"         ${dmux0[4]}          "pkt:"        ${dmux0[5]}          "less_64:"        ${dmux0[6]} "64:"       ${dmux0[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${dmux0[8]} "128_255:"   ${dmux0[9]}          "256_511:" ${dmux0[10]}         "512_1023:"        ${dmux0[11]}          "1024_1518:"         ${dmux0[12]}         "1519_1522:"        ${dmux0[13]}         "1523_1548:"        ${dmux0[14]}  "1549_2047:"       ${dmux0[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${dmux0[16]} "4096_8191:"  ${dmux0[17]}         "8192_9215:" ${dmux0[18]}         "more_9216:"        ${dmux0[19]}          "overflow:"         ${dmux0[20]}         "crc:"        ${dmux0[21]}         "pause:"        ${dmux0[22]}
        printf "+++++++++++++++++++++++++++++++++++++TX++DMUX++ETH1++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${dmux1[0]} "h_byte:"   ${dmux1[1]}          "uc:" ${dmux1[2]}          "mc:"        ${dmux1[3]}           "bc:"         ${dmux1[4]}          "pkt:"        ${dmux1[5]}          "less_64:"        ${dmux1[6]} "64:"       ${dmux1[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${dmux1[8]} "128_255:"   ${dmux1[9]}          "256_511:" ${dmux1[10]}         "512_1023:"        ${dmux1[11]}          "1024_1518:"         ${dmux1[12]}         "1519_1522:"        ${dmux1[13]}         "1523_1548:"        ${dmux1[14]}  "1549_2047:"       ${dmux1[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${dmux1[16]} "4096_8191:"  ${dmux1[17]}         "8192_9215:" ${dmux1[18]}         "more_9216:"        ${dmux1[19]}          "overflow:"         ${dmux1[20]}         "crc:"        ${dmux1[21]}         "pause:"        ${dmux1[22]}
        printf "+++++++++++++++++++++++++++++++++++++TX++DMUX++ETH2++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${dmux2[0]} "h_byte:"   ${dmux2[1]}          "uc:" ${dmux2[2]}          "mc:"        ${dmux2[3]}           "bc:"         ${dmux2[4]}          "pkt:"        ${dmux2[5]}          "less_64:"        ${dmux2[6]} "64:"       ${dmux2[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${dmux2[8]} "128_255:"   ${dmux2[9]}          "256_511:" ${dmux2[10]}         "512_1023:"        ${dmux2[11]}          "1024_1518:"         ${dmux2[12]}         "1519_1522:"        ${dmux2[13]}         "1523_1548:"        ${dmux2[14]}  "1549_2047:"       ${dmux2[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${dmux2[16]} "4096_8191:"  ${dmux2[17]}         "8192_9215:" ${dmux2[18]}         "more_9216:"        ${dmux2[19]}          "overflow:"         ${dmux2[20]}         "crc:"        ${dmux2[21]}         "pause:"        ${dmux2[22]}
        printf "+++++++++++++++++++++++++++++++++++++TX++DMUX++ETH3++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "1_byte:"     ${dmux3[0]} "h_byte:"   ${dmux3[1]}          "uc:" ${dmux3[2]}          "mc:"        ${dmux3[3]}           "bc:"         ${dmux3[4]}          "pkt:"        ${dmux3[5]}          "less_64:"        ${dmux3[6]} "64:"       ${dmux3[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "65_127:"     ${dmux3[8]} "128_255:"   ${dmux3[9]}          "256_511:" ${dmux3[10]}         "512_1023:"        ${dmux3[11]}          "1024_1518:"         ${dmux3[12]}         "1519_1522:"        ${dmux3[13]}         "1523_1548:"        ${dmux3[14]}  "1549_2047:"       ${dmux3[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "2048_4095:"     ${dmux3[16]} "4096_8191:"  ${dmux3[17]}         "8192_9215:" ${dmux3[18]}         "more_9216:"        ${dmux3[19]}          "overflow:"         ${dmux3[20]}         "crc:"        ${dmux3[21]}         "pause:"        ${dmux3[22]}
elif [ "$1" == "padpt" ]
then
        printf "+++++++++++++++++++++++++++++++++++++PADPT+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"    
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "rdif_ack:"     ${padpt[0]} "rdif_eob:"   ${padpt[1]}          "rdif_err:" ${padpt[2]}          "rdif_info:"        ${padpt[3]}           "rdif_reob:"         ${padpt[4]}          "rdif_rerr:"        ${padpt[5]}          "edif_inf_err:"        ${padpt[6]} "wdif_err:"       ${padpt[7]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "wdif_ack:"     ${padpt[8]} "wdif_eob:"   ${padpt[9]}          "wdif_info:" ${padpt[10]}         "wdif_inf_err:"        ${padpt[11]}          "sel_tag:"         ${padpt[12]}         "rx_tag:"        ${padpt[13]}         "err_tag:"        ${padpt[14]}  "aged_tag:"       ${padpt[15]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x  %13s %8x\n" "tag_rls:"     ${padpt[16]} "aged_max_t:"  ${padpt[17]}         "aged_avr_t:" ${padpt[18]}         "req_debug:"        ${padpt[19]}          "rq_cnt:"         ${padpt[20]}         "rc_cnt:"        ${padpt[21]}         "rq_speed:"        ${padpt[22]}   "rc_speed:"       ${padpt[23]} 
        printf "%12s %8x  %12s %8x  %12s %8x  %12s %8x  %12s %8x\n" "rq_nordy_spd:"     ${padpt[24]} "rq_vld_spd:"  ${padpt[25]}         "rc_vld_spd:" ${padpt[26]}         "mux_msix:"        ${padpt[27]}          "msix:"         ${padpt[28]}  
else
        printf "+++++++4x10g+module name+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"
        printf "module name : all eth_rx urmux store pa pro qm ped uvn eth_tx store_tx ped_tx dvn dmux padpt\n"
fi
printf "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ \n"
```

