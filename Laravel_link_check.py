#!/usr/bin/env python3
# _*_ coding:utf-8 _*_

import aiohttp
import asyncio
from aiohttp import ClientSession
from aiohttp import TCPConnector
from urllib.parse import urlparse
import argparse
import re
import time


timeout = aiohttp.ClientTimeout(total=5)
#信号量
sem_num = 100
vul_list = []
num = 0

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
           "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",}
           
def getinfo(filepath):
    fr = open(filepath, 'r')
    ips=fr.readlines()
    fr.close()
    return ips

def saveinfo():
    with open('vul_result.txt','a') as w:
        for url in vul_list:
            w.write(url+'\n')
            
            
async def laravelCheck(sem,url):
  global num
  conn=aiohttp.TCPConnector(verify_ssl=False)
  async with sem:
      async with aiohttp.ClientSession(connector=conn) as session:
        try:
            num = num + 1
            print('>> {}'.format(num))
            vuln_url = url + "/.env"
            async with session.get(vuln_url,timeout=timeout) as resp:
                status = resp.status
                text = await resp.text()
                if status == 200:
                    if "APP_NAME" in text and "DB_HOST" in text:
                        print("目标存在漏洞,路径为：{}".format(vuln_url))
                        vul_list.append(vuln_url)
        except Exception as e:
            print(e)


def poolmana(ips):
    http_tasks = []
    loop_http = asyncio.get_event_loop()
    loop_https = asyncio.get_event_loop()
    sem=asyncio.Semaphore(sem_num) #维持信号量
    for i in ips:
        i=i.replace('\n','')
        task = asyncio.ensure_future(laravelCheck(sem,i))
        http_tasks.append(task)
        
    loop_http.run_until_complete(asyncio.wait(http_tasks))
    #loop_http.close()

def run(filepath):
    ips=getinfo(filepath)
    poolmana(ips)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", dest='file', help="从文件加载目标")

    args = parser.parse_args()

    run(args.file)
    print("总数"+str(len(vul_list)))
    print("开始写入")
    saveinfo()
    print("程序运行结束，查收result.txt")
