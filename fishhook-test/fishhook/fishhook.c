// Copyright (c) 2013, Facebook, Inc.
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//   * Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//   * Neither the name Facebook nor the names of its contributors may be used to
//     endorse or promote products derived from this software without specific
//     prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "fishhook.h"

#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <stdio.h>



#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST  "__DATA_CONST"
#endif

// 链表的节点
struct rebindings_entry {
  // 指向 rebinding 类型结构体的指针（用来指向传入结构体数组的首元素地址）
  struct rebinding *rebindings;
  // rebindings_nel：记录此次要重绑定的数量（用于开辟对应大小的空间）
  size_t rebindings_nel;
  // 指向下一个 rebindings_entry 类型的结构体（记录下一次需要重绑定的数据）
  struct rebindings_entry *next;
};
// _rebindings_head链表
static struct rebindings_entry *_rebindings_head;

static int prepend_rebindings(struct rebindings_entry **rebindings_head,
                              struct rebinding rebindings[],
                              size_t nel) {
  // 创建新rebindings_entry节点
  struct rebindings_entry *new_entry = (struct rebindings_entry *) malloc(sizeof(struct rebindings_entry));
  if (!new_entry) {
    return -1;
  }
  // new_entry->rebindings指向为rebinding结构分配nel个数的空间
  new_entry->rebindings = (struct rebinding *) malloc(sizeof(struct rebinding) * nel);
  if (!new_entry->rebindings) {
    free(new_entry);
    return -1;
  }
  // 将外部设置的rebindings内容复制到新分配的空间中
  memcpy(new_entry->rebindings, rebindings, sizeof(struct rebinding) * nel);
  // 设置rebindings_nel数量
  new_entry->rebindings_nel = nel;
  // 将新节点的next指针指向头结点内容
  new_entry->next = *rebindings_head;
  // 头结点更新
  *rebindings_head = new_entry;
    
  return 0;
    
  // 通过以上操作，构建起一个_rebindings_head链表。新插入的节点在链表头部
}


/**
 Mach-O文件的知识:
 
 1.函数的调用是通过跳转指令跳到函数对应的内存地址，而动态库是在程序启动时才去链接的，
   因此动态库中函数的地址在一开始是不知道的，所以这些函数的地址存放在__DATA,__la_symbol_prt表中，也就是所谓的PIC(位置无关代码)。
   在函数第一次调用的时候例如NSLog()函数，这个表中的地址不是直接指向NSLog的正确地址，而是指向了dyld_stub_binder函数地址，
   它的作用就是去计算出NSLog的真正地址，然后将__DATA,__la_symbol_prt中NSLog对应的地址改为它的实际地址，
   这样第二次调用的时候就是直接调用到NSLog。
 
 2.另外除了__la_symbol_prt表之外，还有与之对应的indirect Symbols、Symbol Table以及String Table。
   它们之间的关系是，首先通过符号在__la_symbol_prt的index，加上在Load Command中对__la_symbol_prt的描述信息reversed1，找到indirect Symbols中 index+reversed1 位置的数据index2，然后在找到Symbol Table中index2位置的数据拿到偏移地址offset，最后在String Table中找offset处的数据，该数据就是函数名"_NSLog"

 */
static void perform_rebinding_with_section(struct rebindings_entry *rebindings,
                                           section_t *section, //
                                           intptr_t slide,
                                           nlist_t *symtab,
                                           char *strtab,
                                           uint32_t *indirect_symtab) {
    
  /**
    0. 在Section64 Header(__lay_symbol_ptrs)和Section64 Header(got)中的reserved1中记录着section中的符号其在indirect_symtab表中起始index
   
    1. 这里是通过indirect_symtab地址 + 对应section->reserved1可以定位到对应section中的符号在indirect_symtab表中的数组地址
       这里的section从fishhook的源码来看指的是(__DATA,__la_symbol_ptrs) 、 (__DATA_const,got)这两个数据节
   
    2. 在indirect Symbols中包含了各个section中符号在Symbol Table的index
   */
  
  // 对应section中符号的在Symtab Table中的index数组
  uint32_t *indirect_symbol_indices = indirect_symtab + section->reserved1;
  
  //slide + section->addr得到了符号指针表(__DATA,__la_symbol_ptrs) or (__DATA_const,got)的实际地址
  // (__DATA,__la_symbol_ptrs) or (__DATA_const,got) 存放的是指针的指针（没有指定类型）即指针数组--函数的地址数组
  void **indirect_symbol_bindings = (void **)((uintptr_t)slide + section->addr);
    
  for (uint i = 0; i < section->size / sizeof(void *); i++) {
    //找到符号在Symbol Table(数组)中的下标
    uint32_t symtab_index = indirect_symbol_indices[i];
      
    if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
        symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS)) {
      continue;
    }

      
// This is the symbol table entry structure for 64-bit architectures.
      
// symbol表结构
//     struct nlist_64 {
//         union {
//             uint32_t  n_strx; /* index into the string table */
//         } n_un;
//         uint8_t n_type;        /* type flag, see below */
//         uint8_t n_sect;        /* section number or NO_SECT */
//         uint16_t n_desc;       /* see <mach-o/stab.h> */
//         uint64_t n_value;      /* value of this symbol (or stab offset) */
//     };
      
    //从Symbol Table中找到符号在String Table中的偏移量
    uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
      
    //String Table的起始地址 + 偏移量，得到符号的名称
    char *symbol_name = strtab + strtab_offset; /// 获取的值是二进制数据,使用char *取值便可以得到字符串
      

    // 判断函数名称是否有两个字符 为什么要这么判断 因为函数前有个_,所以函数名称至少有一个字符
      /**
       调试信息
         (lldb) p symbol_name
         (char *) $4 = 0x0000000105a713ad "_NSLog"
         (lldb) p symbol_name[1]
         (char) $5 = 'N'
         (lldb) p symbol_name[0]
         (char) $6 = '_'
       */
    bool symbol_name_longer_than_1 = symbol_name[0] && symbol_name[1];
      
    /** 以上操作就找到了 (__DATA,__la_symbol_ptrs---懒加载符号指针表) or (__DATA_const,got---非懒加载符号指针边)中的实际符号
        注意 (__DATA,__la_symbol_ptrs) , (__DATA_const,got)存放的并不是符号的名字
     **/
      
      
    // 遍历最初链表，依次进行hook
    struct rebindings_entry *cur = rebindings;
    while (cur) {
      for (uint j = 0; j < cur->rebindings_nel; j++) {
        /// strcmp用来判断 &symbol_name[1]与rebindings中对应的函数名是否相等 相等即为目标hook函数
          
          // 调试信息
               // (lldb) p cur->rebindings[0].name
               // (const char *) $8 = 0x0000000105a6c236 "NSLog"
               
               // (lldb) p &symbol_name[1]
               // (char *) $10 = 0x0000000105a713ae "NSLog"

        if (symbol_name_longer_than_1 &&
            strcmp(&symbol_name[1], cur->rebindings[j].name) == 0) {
        
          //编译的时候会将符号转成带下划线的，比如printf会转成_printf,所以从下划线后面的字符开始比较
          if (cur->rebindings[j].replaced != NULL &&
              indirect_symbol_bindings[i] != cur->rebindings[j].replacement) {
              
            // 记录函数地址
            *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
            /**
             我对fishhook最大的疑问?
                 *(cur->rebindings[j].replaced) = indirect_symbol_bindings[i]
             该操作是将__DATA.__la_symbol_ptr 和 __DATA.__la_symbol_ptr 的 Indirect Pointer值赋值给*(cur->rebindings[j].replaced)
             那么问题来了,当第一次使用懒加载符号时对应的indirect_symbol_bindings[i]中存放的是 __stub_helper的执行地址。即*(cur->rebindings[j].replaced)保存的是__stub_helper的执行地址。
             
             通过调试发现 我们需要hook的函数被其他image调用了，且该image的懒加载表或非懒加载表里面已经是真实的函数地址，那么fishhook在处理的时候，虽然第一次是拿到了我们image内指向stub_helper的地址，但是后面会被其他image里面的真实的函数地址所覆盖。所以调用原函数指针对应的函数并不影响我们image里面的懒加载表。 因为fishhook的通过_dyld_register_func_for_add_image注册了image加载回调。
             但是还是不能保证，我们通过*(cur->rebindings[j].replaced)记录的hook的函数符号有正确的地址，所以最好在hook函数前，先将该函数调用一下，保证改函数符号已经绑定了正确的地址
             
             参考:
             https://www.jianshu.com/p/828ec78d4ae1
             http://m.desgard.com/2017/12/17/fishook-1/index.html
             https://www.jianshu.com/p/4b32e8c54389
             */
          }
          // 替换符号指针表中的地址
          indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
            
          // 退出链表的遍历，即针对同一符号多次调用fishhook重绑定，只有会对最后一次调用的生效
          goto symbol_loop;
        }
      }
      cur = cur->next;
        
    }
  symbol_loop:;
  }
}

/**
    这段方法主要描述了替换 __DATA.__la_symbol_ptr 和 __DATA.__la_symbol_ptr 的 Indirect Pointer 主要过程。从 reserved1 字段获取到 Indirect Symbols 对应的位置。从中我们可以获取到指定符号的偏移量，这个偏移量主要用来在 String Table 中检索出符号名称字符串。之后我们找到 __DATA.__la_symbol_ptr 和 __DATA.__la_symbol_ptr 这两个 Section。这两个表中，都是由 Indirect Pointer 构成的指针数组，但是其中的元素决定了我们调用的方法应该以哪个代码段的方法来执行。我们遍历这个指针数组中每一个指针，在每一层遍历中取出其符号名称，与我们的 rebindings 链表中每一个元素进行比对，当名称匹配的时候，重写其指向地址。
 
 */

static void rebind_symbols_for_image(struct rebindings_entry *rebindings,
                                     const struct mach_header *header,
                                     intptr_t slide) {
    
    printf("header: %p\n", header);
    
  // dladdr函数作用: 在程序中查找header
  Dl_info info;
  if (dladdr(header, &info) == 0) {
    return;
  }
 
  segment_command_t *cur_seg_cmd; //当前的LoadCommand
  segment_command_t *linkedit_segment = NULL; //__LINKEDIT段的LoadCommand  {LC_SEGMENT_64(__LINKEDIT)}
  struct symtab_command* symtab_cmd = NULL; //LC_SYMTAB,可以找到Symbol Table的地址
  struct dysymtab_command* dysymtab_cmd = NULL; //LC_DYSYMTAB,可以找到indirect Symbols的地址
  
    
   /** segment_command_64结构
    
    struct segment_command_64 { for 64-bit architectures
        uint32_t    cmd;            LC_SEGMENT_64
        uint32_t    cmdsize;        includes sizeof section_64 structs
        char        segname[16];    segment name
        uint64_t    vmaddr;         memory address of this segment
        uint64_t    vmsize;         memory size of this segment
        uint64_t    fileoff;        file offset of this segment
        uint64_t    filesize;       amount to map from the file
        vm_prot_t    maxprot;       maximum VM protection
        vm_prot_t    initprot;      initial VM protection
        uint32_t    nsects;         number of sections in segment
        uint32_t    flags;          flags
    };*/
    
  // 跳过header 当前内存地址指向LoadCommand起始地址
  uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    
    //第一次遍历所有的LoadCommand
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    
    cur_seg_cmd = (segment_command_t *)cur; // 保存当前的LoadCommand
      
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) { /// for 64-bit architectures
        
      if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0) { /// __LINKEDIT
        //判断segment的名称是否为__LINKEDIT
        linkedit_segment = cur_seg_cmd;
          
      }
    } else if (cur_seg_cmd->cmd == LC_SYMTAB) { /// 获取到LC_SYMTAB : link-edit stab symbol table info
        //判断是否是LC_SYMTAB，symtab_cmd->symoff 找到Symbol Table的偏移地址
      symtab_cmd = (struct symtab_command*)cur_seg_cmd;
        
    } else if (cur_seg_cmd->cmd == LC_DYSYMTAB) { /// 获取到LC_DYSYMTAB: dynamic link-edit symbol table info
        //判断是否是LC_DYSYMTAB，dysymtab_cmd->indirectsymoff 找到indirect Symbols的偏移地址
      dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
    }
      
  }

  if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment ||
      !dysymtab_cmd->nindirectsyms) {
    return;
  }

  // Find base symbol/string table addresses
  
  // slide是ASLR的随机偏移，linkedit_segment->vmaddr - linkedit_segment->fileoff是"mach-o"在文件中的基地址，两者相加就是ASLR后的mach-o加载进内存的基地址
    
  // 链接时程序的基址 = __LINKEDIT.VM_address - __LINKEDIT.File_offset + slide的改变值    (跳过了LC_SEGMENT_64(__PAGEZERO)这个Command)
    
  uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
    
  // Symbol Table地址 = 基址 + 符号表偏移量
  nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
    
  // String Table地址 = 基址 + 字符串表偏移量
  char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);

  // Get indirect symbol table (array of uint32_t indices into symbol table)
  // indirect symbols表地址 = 基址 + 动态符号表表偏移量
  uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);

  //指针指向LoadCommand起始地址
  cur = (uintptr_t)header + sizeof(mach_header_t);
    
  //第二次遍历所有的LoadCommand
  for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize) {
    
    cur_seg_cmd = (segment_command_t *)cur;
      
    if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT) { /// for 64-bit architectures
      /// 查找LC_SEGMENT_64(__DATA) LC_SEGMENT_64(__DATA_CONST)段
      if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 &&
          strcmp(cur_seg_cmd->segname, SEG_DATA_CONST) != 0) {
          //如果不是__DATA段就跳过
        continue;
      }
      
      //如果是__DATA段，则遍历该Segment下的Sections
      for (uint j = 0; j < cur_seg_cmd->nsects; j++) {
        section_t *sect =
          (section_t *)(cur + sizeof(segment_command_t)) + j;
          // 找到__la_symbol_ptrs懒加载符号指针表
        if ((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
            //重绑定
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
            
        }
          
          /***
           section_64结构
           struct section_64 {  // for 64-bit architectures
               char        sectname[16];    name of this section
               char        segname[16];     segment this section goes in
               uint64_t    addr;            memory address of this section
               uint64_t    size;            size in bytes of this section
               uint32_t    offset;          file offset of this section
               uint32_t    align;           section alignment (power of 2)
               uint32_t    reloff;          file offset of relocation entries
               uint32_t    nreloc;          number of relocation entries
               uint32_t    flags;           flags (section type and attributes)
               uint32_t    reserved1;       reserved (for offset or index)
               uint32_t    reserved2;       reserved (for count or sizeof)
               uint32_t    reserved3;       reserved
           };
           */
          
        //找到_nla_symbol_ptr
        //重绑定
        if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS) {
          perform_rebinding_with_section(rebindings, sect, slide, symtab, strtab, indirect_symtab);
            
        }
      }
    }
  }
}

static void _rebind_symbols_for_image(const struct mach_header *header,
                                      intptr_t slide) {
    
    // 将存着待绑定函数信息的链表_rebindings_head作为参数传入，用于符号查找和函数指针的交换，
    // 第二个参数 header是 当前 image 的头信息，
    // 第三个参数 slide是 ASLR 的偏移
    rebind_symbols_for_image(_rebindings_head, header, slide);
    
}

int rebind_symbols_image(void *header,
                         intptr_t slide,
                         struct rebinding rebindings[],
                         size_t rebindings_nel) {
    
    struct rebindings_entry *rebindings_head = NULL;
    int retval = prepend_rebindings(&rebindings_head, rebindings, rebindings_nel);
    
    rebind_symbols_for_image(rebindings_head, (const struct mach_header *) header, slide);
    
    if (rebindings_head) {
      free(rebindings_head->rebindings);
    }
    free(rebindings_head);
    return retval;
}

int rebind_symbols(struct rebinding rebindings[], size_t rebindings_nel) {

  // 将新加入的 rebindings 数组不断的添加到 _rebindings_head 这个链表的头部成为新的头节点。
  int retval = prepend_rebindings(&_rebindings_head, rebindings, rebindings_nel);
  if (retval < 0) {
    return retval;
  }
  // If this was the first call, register callback for image additions (which is also invoked for
  // existing images, otherwise, just run on existing images
    
  // 如果_rebindings_head->next == NULL说明是第一次调用rebind_symbols函数
  // 如果是第一次调用就使用_dyld_register_func_for_add_image系统函数来注册监听方法
  if (!_rebindings_head->next) {
     /**
      _dyld_register_func_for_add_image系统函数说明
      
        The following functions allow you to install callbacks which will be called by dyld whenever an image is loaded or unloaded.
      
        During a call to _dyld_register_func_for_add_image() the callback func is called for every existing image.
      
        Later, it is called as each new image is loaded and bound (but initializers not yet run).
      */
      // 1.当image被加载或卸载时会调用回调函数。
      // 2.已被dyld加载的image会立即进入回调、之后的加载的image会在dyld装载的时候触发回调，回调方法就是_rebind_symbols_for_image
      _dyld_register_func_for_add_image(_rebind_symbols_for_image);
      
  } else {
      
    uint32_t c = _dyld_image_count();
    // 遍历所有的image(Mach-O文件) 找到所有的目标函数依次进行hook
    for (uint32_t i = 0; i < c; i++) {
      _rebind_symbols_for_image(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
    }
  }
  return retval;
}
