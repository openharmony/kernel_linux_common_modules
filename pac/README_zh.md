## 背景

现阶段，内存安全漏洞是对计算机系统安全最严重的威胁。从漏洞利用的角度分析，借助常见的攻击手段，包括利用缓冲区溢出等实现JOP/ROP攻击，攻击者可以实现控制流劫持，最终导致任意代码执行，这严重摧毁了一个系统的安全性。另一方面，在攻击者利用内存漏洞做提权的过程中，通常会修改指向关键数据（如Cred）的数据指针，这类攻击被归纳为DOP攻击，同样会对系统安全产生严重威胁。
因此，系统需要高效的漏洞防利用机制，以保护系统的控制流完整性和数据流完整性，这对于提升系统的安全竞争力具有重要意义。当前，从安全性角度，对于系统安全主流的JOP/ROP/DOP攻击，PAC机制均能实现有效防护。

## PAC（Pointer Authentication Code）模块

PAC模块利用ARMv8.3-a架构提供的PAC特性，基于linux内核提供PAC相关的特性支持，包括密钥管理、数据和指针签名验签，以及任务切换上下文、异常中断上下文的PAC保护机制。PAC主要功能实现如下：

### 1.密钥管理

ARMv8.3-a指令集引入了硬件安全特性PAC，用于保护内存中指针和其他数据的完整性。原理是：ARM硬件基于QARMA密码算法，将被保护的指针或数据、用于签名的密钥和盐值作为输入，计算输出一个MAC值，对于指针来说，将有效的MAC值存放在指针的未使用高位，对于数据来说，需要另开辟内存用于保存MAC值。

<img src="./figures/pac.png" width=600 alt="PAC原理"/>

Linux内核的密钥管理分为用户态密钥和内核态密钥，示意图如下：

![密钥管理](figures/key.png)

### 2.关键数据和指针保护

Linux内核可以利用PAC模块对任务切换上下文、异常中断上下文中的关键字段进行保护，防止在上下文切换的过程中，攻击者利用内存漏洞提权修改关键字段，最终导致任意代码执行。

![linux context保护](figures/pac_context.png)

## 目录

PAC主要代码目录结构如下：

```
# 代码路径 /kernel/linux/common_modules/pac
├── config                     # 关键数据、指针标记配置文件
├── figures                    # ReadMe 内嵌图例
├── include                    # PAC头文件
├── src                        # PAC代码
└── Makefile
```

## 配置指导

1. PAC使能

   `CONFIG_ARM64_PTR_AUTH=y`

2. 密钥使能

   `CONFIG_ARM64_PTR_AUTH_EXT=y`

3. 关键数据和指针保护使能

   `CONFIG_ARM64_PTR_AUTH_DATA_PTR=y`

   `CONFIG_ARM64_PTR_AUTH_DATA_FIELD=y`

4. 前向CFI使能

   `CONFIG_ARM64_PTR_AUTH_FWD_CFI=y`

## 相关仓

[内核子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E5%86%85%E6%A0%B8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

[kernel_linux_5.10](https://gitee.com/openharmony/kernel_linux_5.10)

[kernel_linux_config](https://gitee.com/openharmony/kernel_linux_config)

[kernel_linux_build](https://gitee.com/openharmony/kernel_linux_build)
