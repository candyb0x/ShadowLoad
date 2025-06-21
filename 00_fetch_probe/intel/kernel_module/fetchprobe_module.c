#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "fetchprobe_module.h"

MODULE_AUTHOR("Redacted");
MODULE_DESCRIPTION("FetchProbe PoC Kernel Module (Intel)");
MODULE_LICENSE("GPL");

uint8_t* secret;  // 声明一个指向 uint8_t 类型的指针，将用于存储“秘密”数据，这是攻击者试图泄露的目标。
uint8_t* kernel_buffer; // 声明一个指向 uint8_t 类型的指针，指向一个内核缓冲区，其访问模式将受 secret 影响。

// 用户空间应用程序打开设备文件的处理函数
static int device_open(struct inode *inode, struct file *file) {
  /* Lock module */
  try_module_get(THIS_MODULE);
  return 0;
}

// 用户空间应用程序关闭设备文件的处理函数
static int device_release(struct inode *inode, struct file *file) {
  /* Unlock module */
  module_put(THIS_MODULE);
  return 0;
}

// gadget used for fetchprobe_cf
void __gadget_cf(uint64_t);

// gadget used for fetchprobe_offset
void __gadget_off(uint64_t);

// 这是ioctl设备的处理程序，允许用户空间应用程序与内核模块进行交互
static long device_ioctl(struct file *file, unsigned int ioctl_num,
                         unsigned long ioctl_param) {
  /*
   * file：指向文件结构体的指针，用于与文件相关的操作
   * ioctl_num：用户空间应用程序传递的ioctl命令编号
   * ioctl_param：用户空间应用程序传递的参数
  */
  u64 i;
  
  switch(ioctl_num) {
  // 定义函数
  case CMD_GADGET_CF: {
      // 核心逻辑：如果 secret 数组中对应偏移量（由 ioctl_param 给出）的比特为 1，则执行一个加载操作。
      // if(secret_bit[offset]) *kernel_buffer;
      if(secret[ioctl_param / 8] & (1 << (ioctl_param % 8))) {  // 检查 secret 数组中特定字节的特定比特是否为 1
          asm volatile("mfence"); // 内存栅栏指令 
          // 定义一个全局符号 __gadget_cf，其后的汇编指令将被编译到内核模块中。
          // 当此 if 块被执行时，`mov (%0), %%al` 指令会直接加载 `kernel_buffer` 的内容到 `al` 寄存器。
          // "r" (kernel_buffer): 将 kernel_buffer 的地址作为输入操作数。
          // "rax": 声明 rax 寄存器会被修改（因为使用了 al）。
          asm volatile(".global __gadget_cf\n__gadget_cf:\n mov (%0), %%al" :: "r" (kernel_buffer) : "rax");
      }
      break;
  }
  // CMD_GADGET_OFF 命令的处理
  case CMD_GADGET_OFF: {
      // 核心逻辑：根据 secret 数组中对应偏移量（由 ioctl_param 给出）的比特值，访问 kernel_buffer 中不同的偏移量。
      // *(kernel_buffer + secret[offset])
      // 定义一个全局符号 __gadget_off，其后的汇编指令将被编译到内核模块中。
      // `&kernel_buffer[(secret[ioctl_param / 8] & (1 << (ioctl_param % 8))) != 0]`
      // 这段代码计算了一个偏移量：如果秘密比特为 1，则偏移量为 1；如果为 0，则偏移量为 0。
      // 也就是说，如果秘密比特是 0，会访问 `kernel_buffer[0]`；如果秘密比特是 1，会访问 `kernel_buffer[1]`。
      // 这允许用户空间通过观察不同偏移量的缓存行为来推断秘密比特。
      asm volatile(".global __gadget_off\n__gadget_off:\n mov (%0), %%al" :: "r" (&kernel_buffer[(secret[ioctl_param / 8] & (1 << (ioctl_param % 8))) != 0]) : "rax");
      break;
  }
  // 用户空间使用此命令从内核模块获取关键地址。
  case CMD_INFO: {
      // 提供了所需地址（内核缓冲区地址和两个 gadget 的地址）给用户空间应用程序。
      struct fetchprobe_kernel_info info;
      info.kernel_buffer = (uintptr_t)kernel_buffer;    // 存储 kernel_buffer 的虚拟地址。
      info.kernel_access_cf = (uintptr_t)__gadget_cf;   // 存储 __gadget_cf 汇编指令的虚拟地址。
      info.kernel_access_off = (uintptr_t)__gadget_off; // 存储 __gadget_off 汇编指令的虚拟地址。
      copy_to_user((void*)ioctl_param, &info, sizeof(info));
      break;
  }
  
  // CMD_RESET 命令的处理
  case CMD_RESET: {
    // 用户空间使用此命令重置秘密缓冲区，以便重新开始泄漏过程。
      // fill secret page with pseudo-random data.
      // We use a seed provided by the userspace attacker such that the userspace attacker can calculate the same random bytes to judge how much data was leaked correctly.
      seed = ioctl_param;
      for(i = 0; i < BUFFER_SIZE; i++) {
          secret[i] = (uint8_t)rand64();
      }
      break;
  }
  
  default:
    return -1;
  }

  return 0;
}


static struct file_operations f_ops = {.unlocked_ioctl = device_ioctl,
                                       .open = device_open,
                                       .release = device_release};

static struct miscdevice misc_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = FETCHPROBE_MODULE_DEVICE_NAME,
    .fops = &f_ops,
    .mode = S_IRWXUGO,
};

int init_module(void) {
  int r;
  
  /* 注册设备 */
  r = misc_register(&misc_dev);
  if (r != 0) {
    printk(KERN_ALERT "[fetchprobe-poc-intel] Failed registering device with %d\n", r);
    return 1;
  }

  // 分配内核内存用于 secret 和 kernel_buffer
  kernel_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL); // 分配 BUFFER_SIZE 大小的内存给 kernel_buffer
  secret = kmalloc(BUFFER_SIZE, GFP_KERNEL);  // 分配 BUFFER_SIZE 大小的内存给 secret
  // 检查 kmalloc 是否成功，并在失败时处理（当前代码没有显式检查，生产代码应有）

  
  /* 输出相关地址信息 */
  printk(KERN_INFO "[fetchprobe-poc-intel] buffer address: 0x%016llx\n", (uint64_t)kernel_buffer);
  printk(KERN_INFO "[fetchprobe-poc-intel] control-flow gadget address: 0x%016llx\n", (uint64_t)__gadget_cf);
  printk(KERN_INFO "[fetchprobe-poc-intel] offset gadget address: 0x%016llx\n", (uint64_t)__gadget_off);

  return 0;
}

void cleanup_module(void) {
  misc_deregister(&misc_dev);
  
  kfree(kernel_buffer);
  kfree(secret);
  
  printk(KERN_INFO "[fetchprobe-poc-intel] Removed.\n");
}

