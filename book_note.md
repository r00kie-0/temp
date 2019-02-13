# 第一章 基础准备与工具

路由器漏洞分类：路由器密码破解漏洞、路由器web漏洞、路由器后门漏洞、路由器溢出漏洞。

该书分析的路由器都是基于linux系统。与普通的linux系统相比，路由器的linux系统有两个特点：一是指令架构，路由器是一种嵌入式系统，多采用MIPS和ARM；二是路由器的shell是基于BusyBox的。

## Mips 汇编基础
MIPS32寄存器分为两类：通用寄存器（GPR）和特殊寄存器。
通用寄存器：MIPS体系结构中有32个通用寄存器，汇编程序中用$0~$31表示。也可以用名称表示，如$sp、$t1、$ra等。


|    编号    | 寄存器名称 | 描述                                               |
| ---------- | -------  |                                                    |
| $0         |  $zero   | 第0号寄存器，其值始终为0。                            |
| $1         |  $at     | 保留寄存器                                          |
| $2-$3      |  $v0-$v1 | values，保存表达式或函数返回结果                      |
| $4-$7      |  $a0-$a3 | argument，作为函数的前四个参数                        |
| $8-$15     |  $t0-$t7 | temporaries，供汇编程序使用的临时寄存器                |
| $16-$23    |  $s0-$s7 | saved values，子函数使用时需先保存原寄存器的值          |
| $24-$25    |  $t8-$t9 | temporaries，供汇编程序使用的临时寄存器，补充$t0-$t7。  |
| $26-$27    |  $k0-$k1 | 保留，中断处理函数使用                                |
| $28        |  $gp     | global pointer，全局指针                            |
| $29        |  $sp     | stack pointer，堆栈指针，指向堆栈的栈顶               |
| $30        |  $fp     | frame pointer，保存栈指针                           |
| $31        |  $ra     | return address，返回地址                            |


特殊寄存器：有3个特殊寄存器：PC（程序计数器）、HI（乘除结果高位寄存器）和LO（乘除结果低位寄存器）。在乘法时，HI保存高32位，LO保存低32位。除法时HI保存余数，LO保存商。

寻址方式：寄存器寻址、立即数寻址、寄存器相对寻址和PC相对寻址。

指令特点：
* 固定4字节指令长度。
* 内存中的数据访问（load/store）必须严格对齐。
* MIPS默认不把子函数的返回地址存放到栈中，而是存放到$ra寄存器中。
* 流水线效应。MIPS采用了高度的流水线，其中一个重要的效应时分支延迟效应。

系统调用指令：SYSCALL指令是一个软中断，系统调用号存放在$v0中，参数存放在$a0-$a3中，如果参数过多，会有另一套机制，

# 第二章 必备软件和环境

软件：VMware、python、IDA pro
IDA的MIPS插件和脚本

1. `Git clone https://github.com/ray-cp/ida.git`
2. 将下载的plugins目录下所有后缀为py文件复制到ida目录的plugins下
3. 将script复制到ida目录下的scripts下
4. 完成上述步骤，将可在“edit->plugins”选项中可见

值得一提的是这些插件在ida6.7以后就无法使用了，因为api不兼容，具体可见[`http://www.hexblog.com/?p=886`](http://www.hexblog.com/?p=886)

## 安装漏洞分析环境
### binwalk安装
从固件镜像中提取文件
```C
sudo apt-get update  
sudo apt-get install build-essential autoconf git

# https://github.com/devttys0/binwalk/blob/master/INSTALL.md  
git clone https://github.com/devttys0/binwalk.git  
cd binwalk

# python2.7安装  
sudo python setup.py install

# python2.7手动安装依赖库  
sudo apt-get install python-lzma

sudo apt-get install python-crypto

sudo apt-get install libqt4-opengl python-opengl python-qt4 python-qt4-gl python-numpy python-scipy python-pip  
sudo pip install pyqtgraph

sudo apt-get install python-pip  
sudo pip install capstone

# Install standard extraction utilities（必选）  
sudo apt-get install mtd-utils gzip bzip2 tar arj lhasa p7zip p7zip-full cabextract cramfsprogs cramfsswap squashfs-tools

# Install sasquatch to extract non-standard SquashFS images（必选）  
sudo apt-get install zlib1g-dev liblzma-dev liblzo2-dev  
git clone https://github.com/devttys0/sasquatch  
(cd sasquatch && ./build.sh)

# Install jefferson to extract JFFS2 file systems（可选）  
sudo pip install cstruct  
git clone https://github.com/sviehb/jefferson  
(cd jefferson && sudo python setup.py install)

# Install ubi_reader to extract UBIFS file systems（可选）  
sudo apt-get install liblzo2-dev python-lzo  
git clone https://github.com/jrspruitt/ubi_reader  
(cd ubi_reader && sudo python setup.py install)

# Install yaffshiv to extract YAFFS file systems（可选）  
git clone https://github.com/devttys0/yaffshiv  
(cd yaffshiv && sudo python setup.py install)

# Install unstuff (closed source) to extract StuffIt archive files（可选） 
 
wget -O - http://my.smithmicro.com/downloads/files/stuffit520.611linux-i386.tar.gz | tar -zxv  
sudo cp bin/unstuff /usr/local/bin/
```
使用命令
```C
binwalk -Me firmware.bin
```
### qemu
#### 安装
模拟器
```C
sudo apt-get install qemu
```
运行
```C
qemu-mips -L ../ ./ls
```
#### 基本用法qemu
主要有两种模式：

1. User Mode，亦称为使用者模式。qemu能启动那些为不同处理器编译的Linux程序。
2. System Mode，亦称为系统模式。qemu能够模拟整个计算机系统。

qemu使用者模式mips程序共有两种模拟程序，分别是运行大端机格式的qume-mips和小端机格式的qume-mipsel，他们的执行参数都是一样的。

### MIPS 交叉编译环境
buildroot是Linux平台上一个构建嵌入式Linux系统的框架。整个Buildroot是由Makefile脚本和Kconfig配置文件构成的。可以和编译Linux内核一样，通过buildroot配置，menuconfig修改，编译出一个完整的可以直接烧写到机器上运行的Linux系统软件(包含boot、kernel、rootfs以及rootfs中的各种库和应用程序)。

1. 下载buildroot
```C
wget http://buildroot.uclibc.org/downloads/snapshots/buildroot-snapshot.tar.bz2
tar -jxvf buildroot-snapshot.tar.bz2
cd buildroot
```
2. 配置buildroot
```C
sudo apt-get install libncurses-dev patch
make clean
make menuconfig
```
在出现界面后，选择第一项“Target Architecture”，改成MIPS（little endian），另外，选择“Toolchain”，务必将“Kernel Headers”的Linux版本改成你自己主机的Linux版本（因为我们编译出的MIPS交叉工具是需要在我们的主机上运行的）
3. 安装
```C
sudo apt-get install texinfo
sudo apt-get install bison
sudo apt-get install flex
sudo make
```
经过约一小时，编译完成后，在buildroot文件夹下多了一个output文件夹，其中就是编译好的文件，可以在buildroot/output/host/usr/bin找到生成的交叉编译工具，编译器是该目录下的mips-linux-gcc文件。
4. 配置环境变量
```C
gedit ~/.bashrc
export PATH=$PATH:/Your_Path/buildroot/output/host/usr/bin
source ~/.bashrc
```
4. 测试
```C
#include<stdio.h>

int vul(char* src)
{
    char output[20]={0};
    strcpy(output,src);
    printf("%s\n",output);
    return 0;
}
 
int main(int argc,char *argv[])
{
    if(argc<2){
        printf("need more argument\n");
        return 1;
    }
    vul(argv[1]);
    return 0;
}
```
静态编译生成二进制文件`mips-linux-gcc -o hello hello.c -static`，使用`file`查看文件类型，最终使用`qemu-mipsel hello "hello world"`测试程序。如若输出，完成安装。

## 第四章 路由器web漏洞
xss利用站点内的信任用户，跨站攻击是指入侵者在远程web页面的HTML页面中插入具有恶意代码的数据，用户认为该页面是可信赖的，但是当浏览器下载该页面时，嵌入其中的脚本将被解释执行。

CSRF跨站请求伪造通过伪装来自受信任用户的请求达到利用受信任的网站的目的。

## 第五章 路由器后门漏洞

## 第六章 路由器溢出漏洞

MIPS32架构函数调用时对堆栈的分配和使用方式与x86架构有相似之处，但又有很大的区别。区别具体体现在：
* 栈操作：与x86架构一样，都是向低地址增长的。但是没有EBP（栈底指针），进入一个函数时，需要将当前栈指针向下移动n比特，这个大小为n比特的存储空间就是此函数的栈帧存储存储区域。
* 调用：如果函数A调用函数B，调用者函数（函数A）会在自己的栈顶预留一部分空间来保存被调用者（函数B）的参数，称之为调用参数空间。
* 参数传递方式：前四个参数通过$a0-$a3传递，多余的参数会放入调用参数空间。
* 返回地址：在x86架构中，使用call命令调用函数时，会先将当前执行位置压入堆栈，MIPS的调用指令把函数的返回地址直接存入$RA寄存器而不是堆栈中。

叶子函数：当前函数不再调用其他函数。
非叶子函数：当前函数调用其他函数。

函数调用的过程：父函数调用子函数时，复制当前$PC的值到$RA寄存器，然后跳到子函数执行；到子函数时，子函数如果为非叶子函数，则子函数的返回地址会先存入堆栈，否则仍在$RA寄存器中；返回时，如果子函数为叶子函数，则"jr $ra"直接返回，否则先从堆栈取出再返回。

利用堆栈溢出的可行性：在非叶子函数中，可以覆盖返回地址，劫持程序执行流程；而在非叶子函数中，可通过覆盖父函数的返回地址实现漏洞利用。

## 第七章 基于MIPS的shellcode开发

mips中可使用syscall指令来进行系统调用，调用的方法为：在使用系统调用syscall之前，$v0保存需要执行的系统调用的调用号，并且按照mips调用规则构造将要执行的系统调用参数。syscall调用的伪代码为：“syscall($v0,$a1,$a2,$a3,$a4...)”。

shellcode编码优化包括指令优化和shellcode编码。
指令优化：指令优化是指通过选择一些特殊的指令避免在shellcode中直接生成坏字符。

通常来说，shellcode可能会受到限制：首先，所有的字符串函数都会对“NULL”字节进行限制；其次，在某些处理流程中可能会限制0x0D（\r）、0x0A（\n）、或者0x20（空格）字符；最后，有些函数会要求shellcode必须为可见字符（ascii）或Unicode值。有些时候，还会受到基于特征的IDS系统对shellcode的拦截。

绕过以上限制的方法主要有两个：指令优化及shellcoe编码。后者更为通用。

shellcoe编码通常包含以下三种：base64编码、alpha_upper编码、xor编码。

## 第八章 路由器文件系统与提取

路由器漏洞的分析与利用的关键环节有获取固件、提取文件系统、漏洞分析与利用及漏洞挖掘。其中获取固件及提取文件系统是进行漏洞分析与利用的基础。

路由器固件中包含操作系统的内核及文件系统。路由器的固件不是硬件而是软件，因为在路由器中它通常是被固化在只读存储器中，所以称为固件。

在进行漏洞分析时获取路由器的固件通常有两种方式：一种是从路由器厂商提供的更新网站下载；一种是通过硬件接入，从路由器的Flash中提取固件。

### 文件系统

文件系统是操作系统的重要组成部分，是操作运行的基础。根文件系统会被打包成当前路由器所使用的文件系统格式，然后组装到固件中。路由器总是希望文件系统越小越好，所以这些文件系统中各种压缩格式随处可见。

Squashfs是一个只读格式的文件系统，具有超高压缩率，可达34%。当系统启动后，会将文件系统保存在一个压缩过的文件系统文件中，这个文件可以使用换回的形式挂载并对其中的文件进行访问，当进程需要某些文件时，仅将对应部分的压缩文件解压缩。Squashfs文件系统常用的压缩格式有GZIP、LZMA、LZO、XZ（LZMA2），在路由器中被普遍采用。

### 手动提取文件系统

文件系统中包含实现路由器各种功能的基础应用程序。文件系统能从固件中提取，而从路由器固件中提取文件系统是一个难点，原因之一在于不同的操作系统使用的文件系统不同。另外，路由器的文件系统压缩算法也有差异，有些路由器甚至会使用非标准的压缩算法打包文件系统。

手动提取文件系统类型包括：

1. 使用`file`命令查看文件系统类型。
2. 手动判断文件类型，包含如下步骤："strings|grep"检索文件系统magic签名头；“hexdump|grep”检索magic签名偏移；“dd|file”确定magic签名偏移处的文件类型。
3. 手动提取文件系统。：安装工具，`sudo apt-get install squashfs-tools`该工具目前仅支持GZIP、LZO、XZ（LZMA2）不支持LZMA格式。可以使用firmware-mod-kit解压缩，解压后得到所有文件。安装命令：
```C
git clone https://github.com/mirror/firmware-mod-kit.git
sudo apt-get install git build-essential zlib1g-dev liblzma-dev python-magic
cd firmware-mod-kit
./configure && make
```

### 自动提取文件系统

binwalk是路由器固件分析的必备工具，该工具最大的优点是可以自动完成指令文件的扫描，智能发掘潜藏在文件中所有可疑地文件类型及文件系统。

binwalk&&libmagic

binwalk提取与分析过程：

1. 固件扫描。通过扫描binwalk可发现目标文件中包含的所有可识别文件类型。
```C
binwaklk firmware.bin
```
2. 提取文件。选项“-e”和“--extract”用于按照预定义的配置文件中的提取方法从固件中提取探测到的文件及系统。选项“-M”，用于递归扫描。“-d”用于递归深度的限制。
```C
binwaklk -e firmware.bin
```
3. 显示完整的扫描结果。选项“-I”或“--invalid”用于显示扫描的所有结果。
4. 指令系统分析。选项“-A”和“--opcode”用于扫描指定文件中通用cpu架构的可执行代码。
```C
binwaklk -A 70|more
```

通常binwalk可对绝大多数路由器固件进行文件提取，如遇到无法识别的固件，可向binwalk添加下列提取规则和提取方法，实现对新的文件系统进行扫描和提取：
1. 基于magic签名文件自动提取。
2. 基于binwalk配置文件的提取。
## 第九章 漏洞分析简介

漏洞分析是指在代码中迅速定位漏洞，弄清攻击原理，准确地估计潜在的漏洞利用方式和风险等级的过程。

### 漏洞分析方法

可以通过一些漏洞公布网站获取漏洞信息。网上公布的poc有很多形式，只要能触发漏洞、重现攻击过程即可。在得到poc后，就需要部署漏洞分析实验环境，利用poc重现攻击过程，定位漏洞函数，分析漏洞产生的具体原因，根据poc和漏洞情况实现对漏洞的利用。

漏洞分析中常用的两种分析方法：动态调试以及静态分析。

## 第十章 D-Link DIR-815路由器多次溢出漏洞分析

### 漏洞介绍

### 漏洞分析
下载固件: google 搜索DIR-815_FIRMWARE_1.01.ZIP。或者去官方链接下载`ftp://ftp2.dlink.com/PRODUCTS/DIR-815/REVA/DIR-815_FIRMWARE_1.01.zip`。解压缩得到固件`DIR-815 FW 1.01b14_1.01b14.bin`。

使用binwalk将固件中的文件系统提取出来。
```C 
binwalk -Me "DIR-815 FW 1.01b14_1.01b14.bin"
```
该漏洞的核心组件为`/htdocs/web/hedwig.cgi`。该组件是一个指向`/htdocs/cgibin`的符号链接。

漏洞公告中描述漏洞产生的原因是Cookie的值`过长`


