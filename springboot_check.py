#!/usr/bin/env python3
# _*_ coding:utf-8 _*_

import argparse
import re
import requests
from multiprocessing import Pool, Manager
from concurrent.futures import ThreadPoolExecutor
import ipaddress


requests.packages.urllib3.disable_warnings()



headers = {"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0",
           "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",}

executor = ThreadPoolExecutor()


def getinfo(filepath):
    fr = open(filepath, 'r')
    ips=fr.readlines()
    fr.close()
    return ips

def saveinfo(result):
    if result:
        fw=open('result.txt','a')
        fw.write(result+'\n')
        fw.close()

def sbcheck(ip):
    url= str(ip)
    try:
        r = requests.get(url+ '/404', headers=headers,timeout=10,verify=False)
        if r.status_code==404 or r.status_code==403:
            if 'Whitelabel Error Page' in r.text  or 'There was an unexpected error'in r.text:
                print("It's A Spring Boot Web APP: {}".format(url))
                #saveinfo( "It's A Spring Boot Web APP: {}".format(url))
                executor.submit(sb_Actuator,url)
                return 1
    except requests.exceptions.ConnectTimeout:
        return 0.0
    except requests.exceptions.ConnectionError:
        return 0.1


def isSB(ip,q):
    print('>>>>> {}'.format(ip))
    sbcheck(ip)
    q.put(ip)



#Spring Boot env端点存在环境属性覆盖和XStream反序列化漏洞
def Envcheck_1(url):
    url_tar = url + '/env'
    r = requests.get(url_tar, headers=headers, verify=False)
    if r.status_code == 200:
        if 'spring.datasource.password' in r.text:
            print("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))
            saveinfo("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))
            return True
        elif 'spring.cloud.bootstrap.location' in r.text:
            print("目标站点开启了 env 端点且spring.cloud.bootstrap.location属性开启,可进行环境属性覆盖RCE测试,路径为：{}".format(url_tar))
            saveinfo("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))
            return True
        elif 'eureka.client.serviceUrl.defaultZone' in r.text:
            print("目标站点开启了 env 端点且eureka.client.serviceUrl.defaultZone属性开启,可进行XStream反序列化RCE测试,路径为：{}".format(url_tar))
            saveinfo("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))
            return True
    
    return False
    
#Spring Boot 1.x版本端点在根URL下注册。
def sb1_Actuator(url):
    Envcheck_1(url)
    

#Spring Boot 2.x版本存在H2配置不当导致的RCE，目前非正则判断，测试阶段
#另外开始我认为环境属性覆盖和XStream反序列化漏洞只有1.*版本存在
#后来证实2.*也是存在的，data需要以json格式发送，这个我后边会给出具体exp
def Envcheck_2(url):
    url_tar = url + '/actuator/env'
    r = requests.get(url_tar, headers=headers, verify=False)
    if r.status_code == 200:
        if 'spring.datasource.password' in r.text:
            print("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))
            saveinfo("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))
            return True
        elif 'spring.cloud.bootstrap.location' in r.text:
            print("目标站点开启了 env 端点且spring.cloud.bootstrap.location属性开启,可进行环境属性覆盖RCE测试,路径为：{}".format(url_tar))
            saveinfo("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))
        elif 'eureka.client.serviceUrl.defaultZone' in r.text:
            print("目标站点开启了 env 端点且eureka.client.serviceUrl.defaultZone属性开启,可进行XStream反序列化RCE测试,路径为：{}".format(url_tar))
            saveinfo("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))
        headers["Cache-Control"]="max-age=0"
        rr = requests.post(url+'/actuator/restart', headers=headers, verify=False)
        if rr.status_code == 200:
            print("目标站点开启了 env 端点且支持restart端点访问,可进行H2 RCE测试,路径为：{}".format(url+'/actuator/restart'))
            saveinfo("目标站点开启了 env 端点的未授权访问,路径为：{}".format(url_tar))



#Spring Boot 2.x版本端点移动到/actuator/路径。
def sb2_Actuator(url):
    Envcheck_2(url)


def sb_Actuator(url):
    try:
        if sb1_Actuator(url):
            pass
        else:
            sb2_Actuator(url)
    except:
        pass

def Cidr_ips(cidr):
    ips=[]
    for ip in ipaddress.IPv4Network(cidr):
        ips.append('%s'%ip)
    return ips


def cidrscan(cidr):
    if re.match(r"^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$",cidr):
        curls = []
        ips=Cidr_ips(cidr)
        for i in ips:
            curls.append('http://'+i)
            curls.append('https://'+i)
        poolmana(curls)
    else:
        print("CIDR格式输入有误，锤你昂w(ﾟДﾟ)w")


def poolmana(ips):
    p = Pool(20)
    q = Manager().Queue()
    for i in ips:
        i=i.replace('\n','')
        p.apply_async(isSB, args=(i,q,))
    p.close()
    p.join()
    print('检索完成>>>>>\n请查看当前路径下文件：result.txt')


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
    if args.url:
        res=sbcheck(args.url)
        if res==1:
            pass
        elif res==0.0:
            print("与目标网络连接异常，timeout默认为10s，请根据网络环境自行更改")
        elif res==0.1:
            print("与目标网络连接异常，目标计算机积极拒绝，无法连接")
        else:
            print("目标未使用spring boot或本脚本识别模块不够完善，如为后者欢迎反馈Issue")
    elif args.surl:
        sb_Actuator(args.surl)
    elif args.cidr:
        cidrscan(args.cidr)
    elif args.file:
        run(args.file)
