## 背景

当前linux内核在内存安全方面还有需要加固的空间，memory_security模块为内存安全定制相应的功能来增强安全能力。

## MEMORY_SECURITY 模块

memory_security模块定制化内存的安全增强能力

### MEMORY_SECURITY/hideaddr 模块

MEMORY_SECURITY/hideaddr模块通过检查渲染进程映射的匿名内存是否具有可执行的权限，来针对性的将映射后的内存地址的start和end值设置为NULL，以此达到隐藏内存地址的目的

#### 1. 进程类型检查

通过进程的selinux安全上下文来判定当前proc/[pid]/maps中的pid对应的进程是否为渲染进程

#### 2. 匿名内存区域权限检查

内存区域的权限由vm_flags_t结构体的 flags成员呈现，通过检查flags是否具有-x-权限来决定是否将其所对应的地址隐藏起来。

### MEMORT_SECURITY/jit_memory 模块

MEMORT_SECURITY/jit_memory模块禁止渲染进程直接申请匿名可执行内存，以及限制将已申请的内存变更为可执行的内存，渲染进程在申请匿名可执行内存前首先需要在`mmap`时携带`flag &= MAP_JIT`，然后该段内存才可以在之后通过`mprotect`变更为可执行的内存。

#### 1. 进程类型检查

通过进程的selinux安全上下文来判定当前proc/[pid]/maps中的pid对应的进程是否为渲染进程

#### 2. 可执行内存预申请
进程在申请匿名可执行内存前首先需要在`mmap`时携带`flag &= MAP_JIT`，即预先声明该段内存之后会被用于存储可执行的代码段，在之后运行时才可使用`mprotect`将其更改为可执行的内存。

## 目录

## MEMORY_SECURITY执行权限管控的主要代码目录结构如下：

```
# 代码路径 /kernel/linux/common_modules/memory_security
│  module.c                      # memory_security 模块初始化
│  apply_hideaddr.sh
│  README_zh.md
│  Kconfig
│  Makefile
│  
├─src
│      jit_memory.c              # jit_memory 接口
│      jit_process.c             # jit_memory 进程相关
│      hideaddr.c                # hide_addr 挂载与实现
│      jit_space_list.c          # jit_memory 进程所拥有内存相关
│      jit_memory_module.c       # jit_memory 模块挂载
│      
└─include
        jit_memory.h
        jit_memory_log.h
        jit_process.h
        hideaddr.h
        jit_memory_module.h
        jit_space_list.h

```

## MEMORY_SECURITY配置指导
1. MEMORY_SECURITY使能：`CONFIG_MEMORY_SECURTIY=y`

   **只有在启用MEMORYSECURITY后，HIDEADDR与JIT_MEMORY才可以被正常使能。**
2. MEMORY_SECURITY禁用：`CONFIG_MEMORY_SECURTIY=n`

3. MEMORY_SECURITY/JIT_MEM_CONTROL使能: `CONFIG_JIT_MEM_CTRL=y`
4. MEMORY_SECURITY/JIT_MEM_CONTROL禁用: `CONFIG_JIT_MEM_CTRL=n`
5. MEMORY_SECURITY/HIDEADDR禁用: `CONFIG_HIDE_MEM_ADDRESS=y`
6. MEMORY_SECURITY/HIDEADDR禁用: `CONFIG_HIDE_MEM_ADDRESS=n`

## 相关仓

[内核子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E5%86%85%E6%A0%B8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

[kernel_linux_5.10](https://gitee.com/openharmony/kernel_linux_5.10)

[kernel_linux_config](https://gitee.com/openharmony/kernel_linux_config)

[device_board_hihope](https://gitee.com/openharmony/device_board_hihope)

[security_selinux_adapter](https://gitee.com/openharmony/security_selinux_adapter)
