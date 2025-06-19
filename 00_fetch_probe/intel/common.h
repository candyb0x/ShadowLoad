#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>

#include "kernel_module/fetchprobe_module.h"

#define CACHE_LINE_SIZE 64
#define PAGE_SIZE 4096

// 定义一个函数指针类型 load_gadget_f，指向一个接受 void* 参数且没有返回值的函数。这个函数指针将用于调用被映射到用户空间的“加载小工具”指令。
typedef void (*load_gadget_f)(void*);
// 定义 maccess 宏，用于执行一个内存访问操作。它将内存地址 x 处的一个字节加载到 %%al 寄存器。
// "r" (x) 表示 x 作为通用寄存器输入。
// "rax" 表示该指令会修改 rax 寄存器（尽管这里只用了 al，但通常会影响整个 rax）。
#define maccess(x) asm volatile("mov (%0), %%al" :: "r" (x) : "rax")
// 定义 mfence 宏，用于执行一个内存屏障指令。这会确保在 mfence 之前的内存操作都在 mfence 之后的内存操作之前完成，对于精确测量时间至关重要。
#define mfence() asm volatile("mfence")
// 定义 nop 宏，用于执行一个空操作指令。
#define nop() asm volatile("nop")
// 定义 flush 宏，用于执行一个 clflush 指令，将指定内存地址 x 所在的缓存行从所有缓存级别中清除。
#define flush(x) asm volatile("clflush (%0)" :: "r" (x));

// 映射一个用户空间缓冲区到指定的虚拟地址
static uint8_t* map_buffer(uintptr_t address, uint64_t size) {
    // 调用 mmap 函数进行内存映射：
    // (void*)address: 尝试映射到指定的虚拟地址。
    // size: 映射区域的大小。
    // PROT_READ | PROT_WRITE: 映射区域可读可写。
    // MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE:
    //   MAP_ANONYMOUS: 映射不与任何文件关联，内容初始化为零。
    //   MAP_PRIVATE: 创建一个私有映射，写入不会影响其他进程。
    //   MAP_POPULATE: 预填充页面表，提前将物理页映射到虚拟地址空间，避免后续的缺页中断延迟。
    //   MAP_FIXED_NOREPLACE: 尝试映射到指定的地址，如果该地址范围已被占用，则失败并返回 MAP_FAILED，而不是寻找其他地址。
    // -1: 文件描述符，MAP_ANONYMOUS 时为 -1。
    // 0: 文件偏移量，MAP_ANONYMOUS 时为 0。
    void* mapping = mmap((void*)address, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE, -1, 0);
    if(mapping == MAP_FAILED) { // 如果映射失败
        return NULL;
    }
    if(mapping != (void*)address) { // 如果实际映射的地址与请求的地址不符 (尽管 MAP_FIXED_NOREPLACE 应该防止这种情况)
        munmap(mapping, size);  // 解除映射
        return NULL;
    }
    return mapping; // 返回映射的地址
}

// 在 common.S 汇编文件中定义，表示加载小工具代码的开始和结束标签
extern void load_gadget_start();
extern void load_gadget_end();

// 映射并准备一个“加载小工具”（load gadget）函数
static load_gadget_f map_gadget(uintptr_t address) {
    // 计算要映射的内存页起始地址。将其对齐到页边界，并映射两个页，以确保包含 gadget。
    uint8_t* mapping = map_buffer(address - (address % PAGE_SIZE), 2 * PAGE_SIZE);
    if(!mapping){
        return NULL;
    }
    // 将 load_gadget_start 到 load_gadget_end 之间的汇编代码复制到映射的内存区域。
    memcpy((void*)address, load_gadget_start, (uintptr_t)load_gadget_end - (uintptr_t)load_gadget_start);
    // 改变映射内存区域的保护权限为可读和可执行，以便可以执行其中的代码。
    mprotect(mapping, 2 * PAGE_SIZE, PROT_READ | PROT_EXEC);
    // 调整 mapping 指针，使其指向实际的 gadget 函数的起始地址（在页内的偏移）。
    mapping += address % PAGE_SIZE;
    // 将调整后的地址转换为 load_gadget_f 函数指针类型并返回。
    return (load_gadget_f)(void*) mapping;
}

// 使用 GCC 的 __attribute__((always_inline)) 强制内联，优化性能。
// 读取时间戳计数器 (RDTSC) 指令，用于测量时间。
static inline __attribute__((always_inline)) uint64_t _rdtsc(void) {
    uint64_t a, d;
    mfence();
    asm volatile("rdtsc" : "=a"(a), "=d"(d));   // 执行 rdtsc 指令，将低 32 位放入 eax (a)，高 32 位放入 edx (d)。
    a = (d << 32) | a;  // 将 eax 和 edx 的值组合成一个 64 位的整数。
    mfence();
    return a;
}

// 用于 qsort 函数的比较器，比较两个 int64_t 类型的值。
static int compare_int64(const void * a, const void * b) {
    return *(int64_t*)a - *(int64_t*)b;
}

// 探测函数：测量访问给定地址所需的时间
static inline __attribute__((always_inline)) uint64_t probe(void* addr){
    uint64_t start, end;
    start = _rdtsc();
    maccess(addr);
    end = _rdtsc();
    return end - start;
}

// 计算缓存命中/未命中的阈值
static uint64_t calculate_threshold(){
    uint64_t vals[100]; // 存储 100 次探测结果
    // 循环执行大量 nop 指令，旨在清空缓存并让系统进入稳定状态，避免之前操作的影响。
    for(uint32_t i = 0; i < 1000000000; ++i) nop();
    for(uint32_t i = 0; i < 100; i++){
        // 探测 vals[50] 的访问时间。由于 vals[50] 应该已经在缓存中（因为它之前被访问过，并且在数组内部），
        // 这些探测结果应该代表缓存命中的时间。
        vals[i] = probe(&vals[50]);
        mfence();   // 内存屏障，确保每次探测的独立性。
    }
    // 对探测结果进行排序
    qsort(vals, 100, sizeof(uint64_t), compare_int64); 
    // 返回排序后的第 90 个值加上一个额外的偏移量 40。
    // 这通常用于设置一个相对保守的阈值，高于大多数缓存命中时间，低于大多数缓存未命中时间。
    // 这样做是为了在实际攻击中更可靠地区分命中和未命中。
    return vals[90] + 40;
}

#endif /* COMMON_H */
