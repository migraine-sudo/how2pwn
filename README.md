# HOW2PWN

记录各个比赛或者平台的pwn题解题思路和EXP。

做题中的知识点会逐渐汇总起来.

​               					*--From 2020 By Migraine*

# POINT

**shellcode**

- EONEW平台的[shellcode](https://github.com/migraine-sudo/how2pwn/tree/master/EONEW/SHELLCODE)
  - Linux沙盒机制
  - 通过open来读取flag

**数据泄露**

- EONEW平台的[EASYSTACK](https://github.com/migraine-sudo/how2pwn/tree/master/EONEW/EASYSTACK)
  - 字符串拼接泄露libc
  - ret2__libc_start_main函数的操作

- xmctf平台的[BabyStack](https://github.com/migraine-sudo/how2pwn/tree/master/xmctf/BABYSTACK)
  - 字符串拼接泄露canary

**No leak**

- 攻防世界的[Noleak](https://github.com/migraine-sudo/how2pwn/tree/master/攻防世界/Noleak)
  - Partial Write
  - House of Roman(方法二)
- 高校战役的[easyheap](https://github.com/migraine-sudo/how2pwn/tree/master/高校战役/easyheap)
  - UAF
  - got表覆盖->leak
- 高校战役[woodenhouse](https://github.com/migraine-sudo/how2pwn/tree/master/高校战役/woodenbox)
  - House of Roman
  - Partial Write+IO_FILE地址泄露(方法二)

**overlap**

- xmctf平台的[BabyHeap](https://github.com/migraine-sudo/how2pwn/tree/master/xmctf/BABYHEAP)
  - global_max_fast的利用(unsortbin attack)
  - free_hook的覆盖
- 攻防世界的[babyheap](https://github.com/migraine-sudo/how2pwn/tree/master/攻防世界/babyheap)
  - overlap的切割法泄露地址
  - realloc调整栈使得one_gadget可用

**root**

- BJDCTF的[diff](https://github.com/migraine-sudo/how2pwn/tree/master/BJDCTF/diff)
  - 提权入门
  - bss段写

# Send Word

***Stay hungry ，Stay Foolish***

