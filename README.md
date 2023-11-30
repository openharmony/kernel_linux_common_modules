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
               │       ├ ─ ─  third_party/        # 三方引入文件目录
               │       │       └ ─ ─  LICENSES/   # 三方使用的license文件目录
               │       ├ ─ ─  README.md           # 模块自简介文件
               │       └ ─ ─  README_en.md
               ├ ─ ─  LICENSE                     # 许可配置文件，合入模块同步更新
               ├ ─ ─  OAT.xml                     # OAT扫描配置文件，合入模块同步更新
               ├ ─ ─  README.md                   # linux内核通用模块仓介绍文档
               ├ ─ ─  README_en.md
               ├ ─ ─  README.OpenSource           # 模块资源配置文件
               ├ ─ ─  BUILD.gn                    # 内核ko模块参与构建的编译配置文件
               └ ─ ─  module_smple                # 内核ko示例
                       ├ ─ ─  BUILD.gn            # 内核ko模块编译配置文件
                       └ ─ ─  *.c                 # ko源码文件（支持子目录以及多源码文件）

```

#### 贡献流程

1.  以模块特性为名新建仓下新目录，合入代码并提交。
2.  更新仓根目录下OAT.xml、LICENSE以及README.OpenSource文件。
3.  申请内核SIG会议进行评审，[会议申请详见](https://gitee.com/openharmony/community/blob/master/sig/sig_kernel/sig_kernel_cn.md#%E4%BC%9A%E8%AE%AE)。
4.  评审通过由内核SIG committer审核合入，未评审通过可解决遗留问题再次上会评审，或评审不适合该仓则放弃合入。会上无法决策的可申请架设SIG会议评审。

### 提交指导参考

1. 【根目录LICENSE】：请把模块目录添加到对应的license条目下，如下的“newip”模块。如文件中没有指定的license可自行添加(2)、(3)等：
```
(1) The directories below are licensed under GPL-2.0-or-later.
    ./newip/
```
2. 【OAT】OAT为OpenHarmony社区的自动化开源审视工具，OAT.xml本仓扫描规则，各模块文件规则不一，模块上库时需更新已有OAT.xml文档。
    在<policylist>中配置自己模块的扫描规则。
	在"copyrightPolicyFilter"的<filefilter>中添加需要过滤扫描的版权信息文件或目录。
	在"defaultPolicyFilter"的<filefilter>中添加需要过滤扫描的license文件或目录。
	在"binaryFileTypePolicyFilter"的<filefilter>中添加需要过滤扫描的二进制文件。	
	具体OAT文件修改方法请参考[OAT tool README](https://gitee.com/openharmony-sig/tools_oat/blob/master/README_zh.md) 。
3. 【README.OpenSource】如本模块借鉴或引用某一开源软件则需要在该文件中添加一条，该文件描述被借鉴软件的信息，以NewIP（借鉴Linux下IPv4 IPv6协议）为例进行说明如下：
```
[
    {
        "Name": "linux-5.10",										# 借鉴或引用的软件名
        "License": "GPL-2.0+",										# 使用的许可
        "License File": "newip/third_party/linux-5.10/LICENSES",	# 指向许可所在文件或目录
        "Version Number": "5.10.93",								# 借鉴或引用该软件的版本
        "Owner": "xxx@xxx.com",										# 借鉴或引用软件引入人邮箱
        "Upstream URL": "https://xxx",								# 借鉴或引用软件开源地址链接
        "Description": "linux kernel 5.10"							# 对借鉴或引用的开源软件模块的描述
    }
]
```
4. 【模块README】模块目录下提供介绍文件。文件需包含模块功能说明、架构目录说明、使用说明、构建说明、相关依赖仓说明等。[文档模板](https://gitee.com/openharmony/docs/blob/master/zh-cn/contribute/template/README-template.md) ，[可参考NewIP README文件](https://gitee.com/openharmony-sig/kernel_linux_common_modules/blob/master/newip/README_zh.md) 。
5. 【模块LICENSE】模块的third_party下放置借鉴或引用软件的License文件或目录，可参考[NewIP LICENSE](https://gitee.com/openharmony-sig/kernel_linux_common_modules/tree/master/newip/third_party/linux-5.10/LICENSES) 。
6. 【参与构建】当前内核树外模块可以通过软链接的方式参与内核构建，可由模块目录下独立脚本执行完成动态软链接创建。脚本可放置到构建系统中调用执行。可参考[NewIP软链接创建脚本](https://gitee.com/openharmony-sig/kernel_linux_common_modules/blob/master/newip/apply_newip.sh) ，[NewIP脚本调用样例](https://gitee.com/openharmony/device_board_hihope/blob/master/rk3568/kernel/build_kernel.sh) 。

### 合入检视规则

1. 【规则】合入该仓模块在构建及运行时只能正向依赖内核，不得产生反向依赖。
2. 【规则】合入时同步提供可编译方案，不可仅代码上库。模块可以通过构建和config配置选择参与版本构建，以适应不同形态产品内核模块的可选择性需求。
3. 【规则】该仓为内核通用模块仓，合入模块不可依赖于特定芯片平台、产品、硬件等。
4. 【规则】该仓使用GPL系列协议，新增自研模块如有使用新License需要在仓根目录添加新LICENSE文件。如有借鉴或引用开源软件则需要配置third_party目录下LICENSE文件。
5. 【规则】合入模块如有借鉴三方开源代码，需在文件头罗列所有借鉴代码文件的copyright/author信息。
6. 【规则】合入模块需更新OAT文件，并完成合入模块OAT扫描，评审时提供扫描报告。
7. 【规则】合入模块需在该仓下创建独立目录，同时模块目录下同步提交README文件。
8. 【规则】合入模块如有借鉴或引用三方开源模块的需要在README.OpenSource文件中进行添加说明。
9. 【建议】具备编译ko的条件，在ko构建能力上线后可适配整改构建出ko模块。

### ko模块指导

1. BUILD.gn文件

(1) 参与构建

参与编译ko模块在common_modules下的BUILD.gn中deps字段中进行添加，格式为“模块目录:模块名”，例如：
```
group("ko_build") {
  deps = [ 
    "module_sample:ko_sample", # 示例ko
    "my_sample:new_ko",        # 新建ko
  ]
}
```


(2) 模块编译配置文件，示例如下
```
import("//build/templates/kernel/ohos_kernel_build.gni")  # 包含编译ko所需的模板配置

ohos_build_ko("ko_sample") {      # 内核ko模块编译名，用于参与构建依赖，必须配置
  sources = [                     # 涉及源码文件填写，必须配置
    "ko_sample.c",
    "sample_fun.c",
  ]
  target_ko_name = "kosample"     # 内核ko最终模块名，不用带扩展名“.ko”，必须配置
  device_name = device_name       # 参与的设备名，如rk3568，默认使用编译参数device_name配置即可
  device_arch = "arm64"           # 适用架构配置，必须配置
}
```


2. 编译

新增编译目标mk_chip_ckm_img，所有填入BUILD.gn的ko模块将会被编译生成。以rk3568为例：
```
./build.sh --product-name rk3568 --build-target mk_chip_ckm_img  --ccache --jobs 4
```


3. 产物

所有构建后ko生成在新增的chip_ckm目录下，以rk3568为例：
```
out/rk3568/packages/phone/chip_ckm/
                           └ ─ ─  *.ko
```
ko全部打包到独立镜像chip_ckm.img镜像中，镜像位置以rk3568为例：
```
out/rk3568/packages/phone/images/
                           └ ─ ─  chip_ckm.img
```