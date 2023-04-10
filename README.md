# kernel_linux_common_modules

#### 介绍
仓用途：为Linux内核通用模块放置仓，为各内核领域公共仓。该仓不提供任何特性或能力，仅为集中容纳各内核独立模块，方便内核仓管理。
适用模块：通用内核模块，可在OpenHarmony支持的任何Linux内核版本上使用。对特定平台或硬件等依赖的模块不适合合入该仓。

#### 目录结构

```
kernel/linux/
       └ ─ ─  common_modules/
                  ├ ─ ─  xxx/                        # xxx内核独立模块目录
                  │       ├ ─ ─  include/            # 模块头文件目录，可自定义
                  │       ├ ─ ─  src/                # 模块源文件目录，可自定义
                  │       ├ ─ ─  README.OpenSource   # 模块资源配置文件
                  │       ├ ─ ─  README.md           # 模块自简介文件
                  │       └ ─ ─  README_en.md
                  ├ ─ ─  yyy/                        # yyy内核独立模块目录
                  ├ ─ ─  LICENSE                     # 许可配置文件，合入模块同步更新
                  ├ ─ ─  OAT.xml                     # OAT扫描配置文件，合入模块同步更新
                  ├ ─ ─  README.md                   # linux内核通用模块仓介绍文档
                  └ ─ ─  README_en.md
```

#### 贡献流程

1.  以模块特性为名新建仓下新目录，合入代码并提交。
2.  更新OAT和license文件。
3.  申请内核SIG会议进行评审。
4.  评审通过由内核SIG committer审核合入，未评审通过可解决遗留问题再次上会评审，或评审不适合该仓则放弃合入。
5.  内核SIG会议申请流程详见[kernel_sig community](https://gitee.com/openharmony/community/blob/master/sig/sig-kernel/sig_kernel_cn.md) 。

### 提交指导参考

1. 【LICENSE】由于该仓下都为Linux模块，统一使用GPL系列协议，可参考NewIP添加如下：
```
Copyright (c) 2023 Huawei Device Co., Ltd. All rights reserved.

+ The newip subdirectories is licensed under GPL-2.0+.

a) Valid-License-Identifier: GPL-2.0
```
2. 【OAT】OAT为OpenHarmony社区的自动化开源审视工具，OAT.xml本仓扫描规则，各模块文件规则不一，模块上库时需更新已有OAT.xml文档，具体修改方法请参考[OAT tool README](https://gitee.com/openharmony-sig/tools_oat/blob/master/README_zh.md) 。
3. 【构建】当前内核树外模块可以通过软链接的方式参与内核构建，可由模块目录下独立脚本执行完成动态软链接创建，可参考[NewIP软链接创建脚本](https://gitee.com/openharmony-sig/kernel_linux_common_modules/blob/master/newip/apply_newip.sh) 。
4. 【模块README】模块目录下提供介绍文件。文件需包含模块功能说明、架构目录说明、使用说明、构建说明、相关依赖仓说明等。可参考[NewIP README文件](https://gitee.com/openharmony-sig/kernel_linux_common_modules/blob/master/newip/README_zh.md) 。
5. 【README.OpenSource】如本模块借鉴或使用某一开源软件则需要配置该文件，该文件描述被借鉴软件的信息，以NewIP（借鉴Linux下IPv4 IPv6协议）为例进行说明如下：
```
[
    {
        "Name": "linux-5.10",              # 借鉴或使用的软件名，
        "License": "GPL-2.0+",             # 使用的许可
        "License File": "COPYING",         # 许可所在文件
        "Version Number": "5.10.93",       # 借鉴时该软件的版本
        "Owner": "xxx@xxx.com",            # 借鉴软件引入及拥有人邮箱
        "Upstream URL": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/log/?h=linux-5.10.y",   # 借鉴软件开源地址链接
        "Description": "linux kernel 5.10" # 对借鉴的开源软件模块的描述
    }
]
```

### 合入检视规则

1. 【规则】内核完整性：同时对内核有侵入的修改提交，仅允许解耦后的插桩侵入修改，不得对已有接口（包括但不限于函数、参数、结构体、枚举类型等）进行修改、删除等操作。
2. 【规则】内核构建独立性：内核不对仓下模块存在升级、构建依赖。谋爱删除或去配置后，内核可单独构建出版本。
3. 【规则】内核运行独立性：内核不对仓下模块存在运行时依赖，即模块不参与编译，系统可启动且其它功能无异常。
4. 【规则】可构建性：仓中内核独立解耦模块能够通过动态创建软链接形势参与内核构建，且实际参与具体平台产品构建。
5. 【规则】可配置性：独立模块可通过配置，选择是否参与内核构建。需确定该模块适用产品形态（standard、small...）
6. 【规则】License：linux common_modules仓统一适用GPL协议，新增模块需要配置仓下license文件。
7. 【规则】OAT：合入模块需要更新OAT文件，评审需提供OAT扫描结果。
8. 【规则】可读性：合入模块需独立目录，README.md文件需同步提交，如有对开源软件的使用或借鉴需同步提交README.OpenSource文件。使用 README\_XXX.md 来支持不同的语言，如: README\_en.md或README\_zh.md。
9. 【建议】具备编译ko的条件，在ko构建能力上线后可适配整改构建出ko文件。
