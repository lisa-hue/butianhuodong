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
    with open('result.txt','a') as w:
        for url in vul_list:
            w.write(url+'\n')
            
async def sbcheck(sem,url):
  global num
  conn=aiohttp.TCPConnector(verify_ssl=False)
  async with sem:
      async with aiohttp.ClientSession(connector=conn) as session:
        try:
            num = num + 1
            print('>> {}'.format(num))
            url_tar = url + '/actuator/env'
            async with session.get(url_tar,timeout=timeout) as resp:
                status = resp.status
                text = await resp.text()
                if status == 200:
                    if 'password":"******"' in text:
                        #检测jolokia
                        url_tar2 = url + '/actuator/jolokia'
                        async with session.get(url_tar2,timeout=timeout) as res:
                            if res.status == 200:
                                print("目标站点开启了 jolokia 端点的未授权访问,路径为：{}".format(url_tar2))
                                #saveinfo(url)
                                vul_list.append(url)
                    else:
                        url_tar = url + '/env'
                        async with session.get(url_tar,timeout=timeout) as resp:
                            if resp.status == 200:
                                text = await resp.text()
                                if 'password":"******"' in text:
                                    url_tar2 = url + '/jolokia'
                                    async with session.get(url_tar2,timeout=timeout) as res:
                                        if res.status == 200:
                                            print("目标站点开启了 jolokia 端点的未授权访问,路径为：{}".format(url_tar2))
                                            #saveinfo(url)
                                            vul_list.append(url)
                else:
                    url_tar = url + '/env'
                    async with session.get(url_tar,timeout=timeout) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if 'password":"******"' in text:
                                url_tar2 = url + '/jolokia'
                                async with session.get(url_tar2,timeout=timeout) as res:
                                    if res.status == 200:
                                        print("目标站点开启了 jolokia 端点的未授权访问,路径为：{}".format(url_tar2))
                                        #saveinfo(url)
                                        vul_list.append(url)
        except Exception as e:
            print(e)


def poolmana(ips):
    http_tasks = []
    loop_http = asyncio.get_event_loop()
    loop_https = asyncio.get_event_loop()
    sem=asyncio.Semaphore(sem_num) #维持信号量
    for i in ips:
        i=i.replace('\n','')
        task = asyncio.ensure_future(sbcheck(sem,i))
        http_tasks.append(task)
        
    loop_http.run_until_complete(asyncio.wait(http_tasks))
    #loop_http.close()

def run(filepath):
    ips=getinfo(filepath)
    poolmana(ips)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest='url',help="单目标扫描")
    parser.add_argument("-s", "--surl", dest='surl', help="单目标扫描(跳过指纹)")
    parser.add_argument("-c", "--cidr", dest='cidr', help="CIDR扫描(80/443)")
    parser.add_argument("-f", "--file", dest='file', help="从文件加载目标")

    args = parser.parse_args()

    run(args.file)
    print("总数"+str(len(vul_list)))
    print("开始写入")
    saveinfo()
    print("程序运行结束，查收result.txt")
