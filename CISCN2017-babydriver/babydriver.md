# BabyDriver 

第一次做kernel pwn的题目，用CISCN2017的babydriver做个入门吧。从编译内核到调试内核环境都做一做吧。

## 编译内核

**Download**

从[Linux Kernel](https://www.kernel.org)官网下载并且解压内核源代码

```
xz -d linux-4.4.217.tar.xz
tar xvf linux-4.4.217.tar
cd linux-4.4.217/
```

**安装依赖**

```
sudo apt-get update
sudo apt-get install build-essential libncurses5-dev
```

**编译**

[参考](http://eternalsakura13.com/2018/04/13/qemu/)

```
$ make menuconfig
进入Kernel hacking
勾选以下项目
Kernel debugging
Compile-time checks and compiler options —> Compile the kernel with debug info和Compile the kernel with frame pointers
KGDB
然后保存退出
```

![RLl1Ev](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/RLl1Ev.png)

生成镜像文件bzImage，编译完成之后可以在arch/x86/boot中找到。

```
$ make bzImage
...
Kernel: arch/x86/boot/bzImage is ready  (#1)
make[1]: warning:  Clock skew detected.  Your build may be incomplete.
```

**构建文件系统**

下载busybox，解压、配置并且编译。

```
wget https://busybox.net/downloads/busybox-1.27.2.tar.bz2
tar -jxvf busybox-1.27.2.tar.bz2
cd busybox-1.27.2
make menuconfig # Busybox Settings -> Build Options -> Build Busybox as a static binary
make install
```

建立文件系统

```
cd _install
mkdir proc
mkdir sys
touch init
chmod +x init
```

编写init

```shell
#!/bin/sh
mkdir /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
mdev -s # We need this to find /dev/sda later
setsid /bin/cttyhack setuidgid 1000 /bin/sh

umount /proc
umount /sys
poweroff -d 0  -f

```

打包文件系统

```
find . | cpio -o --format=newc > ../../rootfs.img
```

**boot**

编写启动脚本boot.sh

```shell
#!/bin/bash

qemu-system-x86_64 -initrd rootfs.img -kernel bzImage -append 'console=ttyS0' --nographic
```



## 环境配置

[参考](https://www.cnblogs.com/61355ing/p/10386955.html)

**qemu**

安装依赖

```
sudo apt-get install libsdl2-2.0 libsdl2-dev libpixman-1-dev flex bison
```

下载Qemu[代码](https://download.qemu.org),并且编译

```
./configure --enable-debug  --target-list=x86_64-softmmu
sudo make
sudo make install
```

运行题目提供的boot.sh脚本时出现如下

```
$ ./boot.sh 
Could not access KVM kernel module: No such file or directory
qemu-system-x86_64: failed to initialize KVM: No such file or directory
```

说明该虚拟机硬件不支持虚拟化，所以在VMfusion中选择**虚拟机->处理器和内存->高级选项->虚拟化Inter VT-x/EPT**，并且重启虚拟机。

**gdb**

安装pwdbg/peda/gef等插件

[qemu+gdb调试Linux内核](https://blog.csdn.net/jasonLee_lijiaqi/article/details/80967912)

gdb加载编译好的源代码

![qDHOk9](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/qDHOk9.png)

设置监听端口（默认1234），然后为boot.sh设定的代码加上参数-s运行。就可以使用gdb对系统内核进行有源代码的调试了。断点·`hb start_kernel`

![qsCTiW](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/qsCTiW.png)



## BabyDriver

题目一般都会提供四个文件，拿本题的四个文件举例**bzImage**  **rootfs.cpio**  **babydriver.ko**  **boot.sh**，分别是内核镜像、文件系统、一个包含漏洞的LKM驱动和启动脚本。之前自己编译过内核，应该就知道这一部分的意义。

解包文件系统。在文件系统中，可以看到init文件，调用了insmod加载了包含了漏洞的babydriver.ko。

```shell
cpio -idmv < rootfs.cpio  #解包
find . | cpio -o --format=newc > ../rootfs.cpio#打包
```

![Vx1vlC](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Vx1vlC.png)

**init**文件

```shell
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs devtmpfs /dev
chown root:root flag
chmod 400 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console

insmod /lib/modules/4.4.72/babydriver.ko
chmod 777 /dev/babydev
echo -e "\nBoot took $(cut -d' ' -f1 /proc/uptime) seconds\n"
setsid cttyhack setuidgid 1000 sh

umount /proc
umount /sys
poweroff -d 0  -f
```

运行./boot.sh起系统。当然，比赛提供的文件系统中自然是没有flag的，所以显示No such file，不过本地可以自己写在文件系统里然后打包。比赛中，打服务器也是将自己脚本上传到tmp，然后运行提权。

![opn3rf](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/opn3rf.png)

**漏洞分析**

使用[checksec](https://github.com/slimm609/checksec.sh)检查保护机制

![5JjqTu](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/5JjqTu.png)

IDA中Shift+F9查看有哪些结构体

![dvhk29](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/dvhk29.png)

s

**printk**并不会输出在console中，需要使用dmesg命令才能查看输出。





**Getshell**

最后打包文件系统，重新起系统。在/tmp目录下运行exp即可获得一个root权限的shell。

```
find . | cpio -o --format=newc > ../rootfs.cpio
```





## 附录

**LKM入门**[参考]()