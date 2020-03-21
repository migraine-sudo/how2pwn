#!/usr/bin/python
from pwn import *

p=process("./ydsneedgirlfriend2.dms",env={"LD_PRELOAD":"libc-2.27.so"})
gdb.attach(p)

p.interactive()
