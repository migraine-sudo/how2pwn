



![VPGLch](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/VPGLch.png)

![ntok5q](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/ntok5q.png)







拷贝到本地

`$ scp -r -P 29523 ctf@node3.buuoj.cn:/home/ctf/diff diff`



这个程序好简洁，似乎是汇编写的？

![jy08em](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/jy08em.png)

![iz284q](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/iz284q.png)



![Os1cZQ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/Os1cZQ.png)

![HBRpRy](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/HBRpRy.png)



应该是利用diff来提权，程序没有加载链接库，栈溢出之后很难getshell。不过使用diff 将flag读入内存，然后想办法用sys_write出来。

![6cIgsW](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/6cIgsW.png)

![IXfvFZ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/IXfvFZ.png)

```
sys_write 
eax=0x4
ebx=1. ;fd
ecx= 0x3 ;flag 文件句柄
edx =len
```



