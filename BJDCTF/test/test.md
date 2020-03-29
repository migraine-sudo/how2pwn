# Test

一个提权类，不需要写脚本。（这个题目有点像后渗透提权。。

获取题目ELF和源代码

scp -r -P 29664  ctf@node3.buuoj.cn:/home/ctf/test.c test.c

$ scp -r -P 29664  ctf@node3.buuoj.cn:/home/ctf/test test

代码

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(){
    char cmd[0x100] = {0};
    puts("Welcome to Pwn-Game by TaQini.");
    puts("Your ID:");
    system("id");
    printf("$ ");
    gets(cmd);
    if( strstr(cmd, "n")
       ||strstr(cmd, "e")
       ||strstr(cmd, "p")
       ||strstr(cmd, "b")
       ||strstr(cmd, "u")
       ||strstr(cmd, "s")
       ||strstr(cmd, "h")
       ||strstr(cmd, "i")
       ||strstr(cmd, "f")
       ||strstr(cmd, "l")
       ||strstr(cmd, "a")
       ||strstr(cmd, "g")
       ||strstr(cmd, "|")
       ||strstr(cmd, "/")
       ||strstr(cmd, "$")
       ||strstr(cmd, "`")
       ||strstr(cmd, "-")
       ||strstr(cmd, "<")
       ||strstr(cmd, ">")
       ||strstr(cmd, ".")){
        exit(0);    
    }else{
        system(cmd);
    }
    return 0;
}

```

通过test提权执行命令，反弹shell或者读取flag，想办法读取flag文件。不过程序对命令进行了黑名单过滤。

![xshgPc](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/xshgPc.png)



不能用$字符串拼接，不能直接用cat *输出，大小写也没办法绕过

只能去/usr/bin找一找，找到一个od，可以输出8进制。。。

![ROrzUG](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/ROrzUG.png)

![dlvfiJ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/dlvfiJ.png)

![WtXlWJ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/WtXlWJ.png)

```
066146 063541 032573 034061 062463 062071 026470 061467
060460 032055 030070 026544 034541 030465 062055 062461
032545 031142 034471 034063 076461 077412 046105 001106
000401
```

写个脚本转化一下

![HFnCqY](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/HFnCqY.png)



获取**flag{5183e9d8-7c0a-480d-a951-d1ee5b299381}**

EXP

```python
OD='066146','063541','032573','034061','062463','062071','026470','061467','060460','032055','030070','026544','034541','030465','062055','062461','032545','031142','034471','034063','076461','077412','046105','001106','000401'

for i in OD:
    x1=int(i,8)/256
    x2=int(i,8)%256
    #print i+'->'+hex(int(i,8))+"->"+chr(int(i,8))
    #print "x1="+hex(x1)+" x2="+hex(x2)
    print (chr(x2)+chr(x1),

```

还有个解法，执行x86_64反弹一个shell。。。出题者应该没考虑到这个问题。





关于类似题目的参考，字符串拼接,或者用*来替代匹配flag，或者用大小写。。。
[参考链接](https://www.jianshu.com/p/e13964824acf)

[参考链接](https://bbs.pediy.com/thread-225418.htm)

