# kernel_linux_common_modules

#### 介绍
该仓为Linux内核通用模块仓。通用内核模块可在系统支持的任何Linux内核版本上使用。新增模块需要通过内核SIG会议评审。

#### 目录结构

```
kernel/linux/
       └ ─ ─  common_modules/
                  ├ ─ ─  xxx/                        # xxx内核独立模块目录
                  │       ├ ─ ─  include/            # 模块头文件目录，可自定义
                  │       ├ ─ ─  src/                # 模块源文件目录，可自定义
                  │       ├ ─ ─  README.OpenSource   # 模块资源配置文件
                  │       ├ ─ ─  README.md           # 模块自简介文件
                  │       └ ─ ─  README_zh.md
                  ├ ─ ─  yyy/
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
5.  内核SIG会议申请流程详见[https://gitee.com/openharmony/community/blob/master/sig/sig-kernel/sig_kernel_cn.md](https://gitee.com/openharmony/community/blob/master/sig/sig-kernel/sig_kernel_cn.md) 。

### 合入规则

1. 【规则】内核完整性：同时对内核有侵入的修改提交，仅允许解耦后的插桩侵入修改，不得对已有接口（包括但不限于函数、参数、结构体、枚举类型等）进行修改、删除等操作。
2. 【规则】内核构建独立性：内核不对仓下模块存在升级、构建依赖。谋爱删除或去配置后，内核可单独构建出版本。
3. 【规则】内核运行独立性：内核不对仓下模块存在运行时依赖，即模块不参与编译，系统可启动且其它功能无异常。
4. 【规则】可构建性：仓中内核独立解耦模块能够通过动态创建软链接形势参与内核构建，且实际参与具体平台产品构建。
5. 【规则】可配置性：独立模块可通过配置，选择是否参与内核构建。需确定该模块适用产品形态（standard、small...）
6. 【规则】License：linux common_modules仓统一适用GPL协议，新增模块需要配置仓下license文件。
7. 【规则】OAT：合入模块需要更新OAT文件，评审需提供OAT扫描结果。
8. 【规则】可读性：合入模块需独立目录，README.md及README.OpenSource文件需同步提交，使用 README\_XXX.md 来支持不同的语言，例如 README\_en.md, README\_zh.md
9. 【建议】具备编译ko的条件，在ko构建能力上线后可适配整改构建出ko文件。
