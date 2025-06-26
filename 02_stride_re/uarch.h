#ifndef UARCH_H
#define UARCH_H

extern void _load_gadget_asm_start(void);
extern void _load_gadget_asm_end(void);

#ifdef __x86_64__
    #define PAGE_SIZE 4096  // 定义页面大小为 4096 字节（4KB）
    #define CACHE_LINE_SIZE 64  // 定义缓存行大小为 64 字节
    
    // 定义第一个函数参数寄存器为 "rdi"，这是 x86_64 调用约定中的第一个参数寄存器
    #define REG_ARG_1 "rdi"
    // 定义一个宏，用于汇编访问内存地址。pre 是一个可选的前缀字符串。
    // 它通过 mov 指令将地址 addr 的内容加载到 %%al 寄存器中，实现内存访问。
    #define _maccess(pre, addr) asm volatile(pre "mov (%0), %%al" :: "r" (addr) : "rax")
    // 定义一个更简单的宏，直接调用 _maccess，不带前缀，实现内存访问
    #define maccess(addr) _maccess("", addr)
    // 定义一个宏，用于插入内存屏障指令 mfence，确保在此指令之前的所有内存操作完成
    #define mfence() asm volatile("mfence")
    // 定义一个宏，用于将指定地址 addr 对应的缓存行从 CPU 缓存中刷新出去
    #define flush(addr) asm volatile("clflush (%0)" :: "r" (addr))
    // 定义一个宏，用于汇编中的函数返回指令
    #define return_asm() "ret"

    #define nop() asm volatile("nop")
    
    #define VIRTUAL_ADDRESS_BITS 48 // 定义虚拟地址位数，在 x86_64 架构下通常为 48 位
#elif defined (__aarch64__)
    #define PAGE_SIZE 4096
    #define CACHE_LINE_SIZE 64
    
    // 定义第一个函数参数寄存器为 "x0"，这是 aarch64 调用约定中的第一个参数寄存器
    #define REG_ARG_1 "x0"
    // 定义一个宏，用于汇编访问内存地址。pre 是一个可选的前缀字符串。
    // 它通过 ldrb 指令将地址 addr 的内容加载到 w0 寄存器中（字节加载），实现内存访问。
    #define _maccess(pre, addr) asm volatile(pre "ldrb w0, [%0]" :: "r" (addr) : "x0")
    // 定义一个更简单的宏，直接调用 _maccess，不带前缀，实现内存访问
    #define maccess(addr) _maccess("", addr)
    
    // 定义一个宏，用于插入内存屏障和指令同步屏障，确保内存操作的顺序和可见性
    #define mfence() asm volatile("DMB SY\nISB")
    // 定义一个宏，用于将指定地址 addr 对应的缓存行从 CPU 缓存中清理并失效
    #define flush(addr) asm volatile("DC CIVAC, %0" :: "r" (addr))
    // 定义一个宏，用于汇编中的函数返回指令
    #define return_asm() "ret"
    // 定义一个宏，用于插入空操作指令
    #define nop() asm volatile("nop")
    
    #define VIRTUAL_ADDRESS_BITS 48 // 定义虚拟地址位数，在 aarch64 架构下通常为 48 位
#else
    #error "unknown architecture. Only x86_64 and aarch64 are supported"
#endif

#endif /* UARCH_H */
