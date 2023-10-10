## 背景

当前linux内核在内存安全方面还有需要加固的空间，memory_security模块为内存安全定制相应的功能来增强安全能力。

## MEMORY_SECURITY 模块

memory_security模块定制化内存的安全增强能力

### MEMORY_SECURITY/hideaddr 模块

MEMORY_SECURITY/hideaddr模块通过检查渲染进程映射的匿名内存是否具有可执行的权限，来针对性的将映射后的内存地址的start和end值设置为NULL，以此达到隐藏内存地址的目的

#### 1.进程类型检查

通过进程的selinux安全上下文来判定当前proc/[pid]/maps中的pid对应的进程是否为渲染进程

#### 2.匿名内存区域权限检查

内存区域的权限由vm_flags_t结构体的 flags成员呈现，通过检查flags是否具有-x-权限来决定是否将其所对应的地址隐藏起来。

## 目录

## MEMORY_SECURITY执行权限管控的主要代码目录结构如下：

```
# 代码路径 /kernel/linux/common_modules/memory_security
├── hideaddr.h                   # memory_security 头文件
├── hideaddr.c                   # memory_security 管控代码
├── Konfig
├── Makefile
```

## MEMORY_SECURITY配置指导

1. MEMORY_SECURITY/HIDEADDR使能
   `CONFIG_HIDE_MEM_ADDRESS=y`

2. MEMORY_SECURITY/HIDEADDR禁用
   `CONFIG_HIDE_MEM_ADDRESS=n`

## 相关仓

[内核子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E5%86%85%E6%A0%B8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

[kernel_linux_5.10](https://gitee.com/openharmony/kernel_linux_5.10)

[kernel_linux_config](https://gitee.com/openharmony/kernel_linux_config)

[device_board_hihope](https://gitee.com/openharmony/device_board_hihope)

[security_selinux_adapter](https://gitee.com/openharmony/security_selinux_adapter)
