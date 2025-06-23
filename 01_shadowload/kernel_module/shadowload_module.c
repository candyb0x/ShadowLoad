#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "shadowload_module.h"

MODULE_AUTHOR("Redacted");
MODULE_DESCRIPTION("ShadowLoad PoC Kernel Module");
MODULE_LICENSE("GPL");

#define BUFFER_SIZE (PAGE_SIZE * 5) // 定义内核缓冲区的大小为 5 个页面

static uint8_t* kernel_buffer;  // 声明一个指向 uint8_t 类型的指针，将用于存储内核缓冲区。

// 用户空间应用程序打开设备文件的处理函数
static int device_open(struct inode *inode, struct file *file) {
  /* Lock module */
  try_module_get(THIS_MODULE);  // 增加模块使用计数
  return 0;
}

// 用户空间应用程序关闭设备文件的处理函数
static int device_release(struct inode *inode, struct file *file) {
  /* Unlock module */
  module_put(THIS_MODULE);  // 减少模块使用计数
  return 0;
}
/* 架构相关代码 */
#if defined(__x86_64__) // 如果是 x86-64 架构
#define flush(x) asm volatile("clflush (%0)" :: "r" (x))  // x86 clflush 指令，用于刷新缓存行
#define maccess(x) asm volatile("mov (%0), %%rax" :: "r" (x) : "rax") // x86 内存访问指令
#define mfence() asm volatile("mfence") // x86 内存屏障
#ifdef APERF // 如果定义了 APERF（一种性能计数器）
    static inline __attribute__((always_inline)) uint64_t _rdtsc(void) {
      uint64_t a, d;
      asm volatile("mfence");
      asm volatile("rdpru" : "=a" (a), "=d" (d) : "c" (1)); // 读取 APERF 计数器（需要特定的 CPU 支持和权限）
      a = (d << 32) | a;
      asm volatile("mfence");
      return a;
    }
#else // 否则使用 rdtsc
static inline __attribute__((always_inline)) uint64_t _rdtsc(void) {
    uint64_t a, d;
    mfence();
    asm volatile("rdtsc" : "=a"(a), "=d"(d)); // 读取时间戳计数器
    a = (d << 32) | a;
    mfence();
    return a;
}
#endif /* APERF */
#elif defined (__aarch64__) // 如果是 ARM64 架构
#define flush(x) asm volatile("DC CIVAC, %0" :: "r" (x))  // ARM DC CIVAC 指令，用于清除/刷新缓存（数据缓存，清理并作废）
#define maccess(x) asm volatile("ldr x0, [%0]" :: "r" (x) : "x0") // ARM 内存访问指令（加载到 x0 寄存器）
#define mfence() asm volatile("DSB SY\nISB")  // ARM 内存屏障（数据同步屏障和指令同步屏障）
static inline __attribute__((always_inline)) uint64_t _rdtsc(void) {
    uint64_t a;
    mfence();
    asm volatile("mrs %0, PMCCNTR_EL0" : "=r" (a)); // 读取性能监控计数器（PMCCNTR_EL0）
    mfence();
    return a;
}
#endif /* ARCHITECTURE */

// 测量内存加载所需的时间
static inline __attribute__((always_inline)) uint64_t probe(void* addr){
    uint64_t start, end;
    start = _rdtsc(); // 记录开始时间
    maccess(addr);  // 访问内存地址
    end = _rdtsc(); // 记录结束时间
    return end - start; // 返回时间差
}

// 声明一个汇编函数 __gadget，它将在 ioctl 处理程序中定义
void __gadget(uint64_t);

// 这是 ioctl 设备的处理程序，允许用户空间应用程序与内核模块进行交互
static long device_ioctl(struct file *file, unsigned int ioctl_num,
                         unsigned long ioctl_param) {
  size_t i;
  
  switch(ioctl_num) { // 根据用户空间传递的 ioctl 命令编号进行分支
  
  // CMD_GADGET 命令的处理：执行一个内存加载操作
  case CMD_GADGET: {
      #ifdef __x86_64__ // x86-64 架构的汇编指令
      // 定义一个全局符号 __gadget，其后的汇编指令将加载 kernel_buffer 中 ioctl_param 偏移量处的内容。
      asm volatile(".global __gadget\n__gadget:\n mov (%0), %%rax" :: "r" (&kernel_buffer[ioctl_param]) : "rax");
      #else // aarch64 架构的汇编指令
      // 定义一个全局符号 __gadget，其后的汇编指令将加载 kernel_buffer 中 ioctl_param 偏移量处的内容。
      asm volatile(".global __gadget\n__gadget:\n ldr x0, [%0]" :: "r" (&kernel_buffer[ioctl_param]) : "x0");
      #endif /* ARCHITECTURE */
      break;
  }
  // CMD_FLUSH 命令的处理：刷新内核缓冲区
  case CMD_FLUSH: {
      // 遍历整个 kernel_buffer，并使用架构特定的 flush 宏将每个缓存行从缓存中清除。
      for(i = 0; i < BUFFER_SIZE; i += 64) {  // 每次增加一个缓存行的大小
          flush(&kernel_buffer[i]);
      }
      break;
  }
  // CMD_INFO 命令的处理：提供内核地址信息给用户空间
  case CMD_INFO: {
      struct shadowload_kernel_info info;
      info.kernel_buffer = (uintptr_t)kernel_buffer;  // 存储 kernel_buffer 的虚拟地址
      info.kernel_access = (uintptr_t)__gadget; // 存储 __gadget 汇编指令的虚拟地址
      // 将 info 结构体的数据复制到用户空间（ioctl_param 指向的地址）
      copy_to_user((void*)ioctl_param, &info, sizeof(info));
      break;
  }
  // CMD_PROBE 命令的处理：测量内核缓冲区某个偏移量的访问时间
  case CMD_PROBE: {
      // 从用户空间复制要探测的偏移量
      copy_from_user(&i, (void*)ioctl_param, sizeof(i));
      // 在内核空间执行探测
      i = probe(&kernel_buffer[i]);
      // 将探测结果复制回用户空间
      copy_to_user((void*)ioctl_param, &i, sizeof(i));
      break;
  }
  
  default:  // 未知的 ioctl 命令
    return -1;
  }

  return 0;
}

// 定义文件操作结构体，将上面定义的函数与设备文件操作关联起来
static struct file_operations f_ops = {.unlocked_ioctl = device_ioctl,  // ioctl 命令处理函数
                                       .open = device_open, // 打开设备文件处理函数
                                       .release = device_release};  // 关闭设备文件处理函数

// 定义一个杂项设备结构体
static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,  // 动态分配次设备号
    .name = SHADOWLOAD_MODULE_DEVICE_NAME,  // 设备名称
    .fops = &f_ops, // 关联文件操作结构体
    .mode = S_IRWXUGO,  // 设置设备文件的权限
};

#ifdef __aarch64__  // ARM64 架构特有的 PMU（性能监控单元）配置

// https://github.com/jerinjacobk/armv8_pmu_cycle_counter_el0/blob/master/armv8_pmu_el0_cycle_counter.c
// 启用用户模式下对性能监控单元循环计数器的访问
static void
enable_cycle_counter_el0(void* data)
{
	u64 val;
	/* Disable cycle counter overflow interrupt */
	asm volatile("msr pmintenclr_el1, %0" : : "r" ((u64)(1 << 31)));  // 清除计数器溢出中断
	/* Enable cycle counter */
	asm volatile("msr pmcntenset_el0, %0" :: "r" BIT(31));  // 启用 PMCCNTR_EL0 计数器
	/* Enable user-mode access to cycle counters. */
	asm volatile("msr pmuserenr_el0, %0" : : "r"(BIT(0) | BIT(2))); // 允许用户模式访问 PMCCNTR_EL0 和其他计数器
	/* Clear cycle counter and start */
	asm volatile("mrs %0, pmcr_el0" : "=r" (val));  // 读取 PMCR_EL0 寄存器
	val |= (BIT(0) | BIT(2)); // 设置 EN (Enable) 和 C (Cycle counter reset) 位
	isb();  // 指令同步屏障
	asm volatile("msr pmcr_el0, %0" : : "r" (val)); // 写回 PMCR_EL0 寄存器以启动计数器
	val = BIT(27);
	asm volatile("msr pmccfiltr_el0, %0" : : "r" (val));  // 配置 PMCCNTR_EL0 的过滤器（这里可能设置为计数所有指令）
}

// 禁用用户模式下对性能监控单元循环计数器的访问
static void
disable_cycle_counter_el0(void* data)
{
	/* Disable cycle counter */
	asm volatile("msr pmcntenset_el0, %0" :: "r" (0 << 31));  // 禁用 PMCCNTR_EL0
	/* Disable user-mode access to counters. */
	asm volatile("msr pmuserenr_el0, %0" : : "r"((u64)0));  // 禁用用户模式访问计数器

}

#endif /* __aarch64__ */

// 模块初始化函数，当模块被加载时执行
int init_module(void) {
  int r;
  
  #ifdef __aarch64__  // 如果是 ARM64 架构，为每个 CPU 核心启用循环计数器
  on_each_cpu(enable_cycle_counter_el0, NULL, 1);
  #endif /* __aarch64__ */
  
  /* Register device */
  r = misc_register(&misc_dev); // 注册杂项设备
  if (r != 0) { // 如果注册失败
    printk(KERN_ALERT "[shadowload-poc] Failed registering device with %d\n", r);
    return 1; // 返回非零表示失败
  }

  kernel_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL); // 分配内核缓冲区内存
  // 打印内核缓冲区和 gadget 的地址，这些地址将传递给用户空间程序
  printk(KERN_INFO "[shadowload-poc] buffer address: 0x%016llx\n", (uint64_t)kernel_buffer);
  printk(KERN_INFO "[shadowload-poc] gadget address: 0x%016llx\n", (uint64_t)__gadget);

  return 0;
}

void cleanup_module(void) {
  
  #ifdef __aarch64__  // 如果是 ARM64 架构，为每个 CPU 核心禁用循环计数器
  on_each_cpu(disable_cycle_counter_el0, NULL, 1);
  #endif /* __aarch64__ */

  misc_deregister(&misc_dev); // 注销杂项设备
  
  kfree(kernel_buffer); // 释放内核缓冲区内存
  
  printk(KERN_INFO "[shadowload-poc] Removed.\n");  // 打印模块卸载信息
}

