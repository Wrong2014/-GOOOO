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

