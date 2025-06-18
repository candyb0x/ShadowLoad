#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include "fetchprobe_module.h"

MODULE_AUTHOR("Redacted");
MODULE_DESCRIPTION("FetchProbe PoC Kernel Module (Intel)");
MODULE_LICENSE("GPL");

uint8_t* secret;
uint8_t* kernel_buffer;

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
  
  case CMD_GADGET_CF: {
      // if(secret_bit[offset]) *kernel_buffer;
      if(secret[ioctl_param / 8] & (1 << (ioctl_param % 8))) {
          asm volatile("mfence"); // 内存栅栏指令 
          asm volatile(".global __gadget_cf\n__gadget_cf:\n mov (%0), %%al" :: "r" (kernel_buffer) : "rax");
      }
      break;
  }
  
  case CMD_GADGET_OFF: {
      // *(kernel_buffer + secret[offset])
      asm volatile(".global __gadget_off\n__gadget_off:\n mov (%0), %%al" :: "r" (&kernel_buffer[(secret[ioctl_param / 8] & (1 << (ioctl_param % 8))) != 0]) : "rax");
      break;
  }
  // 用户空间使用此命令从内核模块获取关键地址。
  case CMD_INFO: {
      // provides information about required addresses to userspace
      struct fetchprobe_kernel_info info;
      info.kernel_buffer = (uintptr_t)kernel_buffer;    // 存储 kernel_buffer 的虚拟地址。
      info.kernel_access_cf = (uintptr_t)__gadget_cf;   // 存储 __gadget_cf 汇编指令的虚拟地址。
      info.kernel_access_off = (uintptr_t)__gadget_off; // 存储 __gadget_off 汇编指令的虚拟地址。
      copy_to_user((void*)ioctl_param, &info, sizeof(info));
      break;
  }
  // 用户空间使用此命令重置秘密缓冲区，以便重新开始泄漏过程。
  case CMD_RESET: {
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

  kernel_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  secret = kmalloc(BUFFER_SIZE, GFP_KERNEL);
  
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

