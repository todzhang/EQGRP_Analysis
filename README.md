# EQGRP_Analysis
分析EQGRP的技巧

## 概述

现在全面分析方程式代码的条件成熟了，建立一个项目来分析其中的代码技巧。



## 工具



### Xor47 Deobfuscation

一个简单工具，用于反混淆字符串

#### 安装

将xor_plugin.py放到IDA的plugings目录下即可



#### 使用方法

![Xor47解码](README.assets/xor47_2022-03-21_14-13-10.png)

如上图所示，在IDA View中，将光标放在需要解码的字符第一个字符所在的地址上，然后执行Edit->Plugins->Xor47 Deobfuscation，即可解码。

也可以使用Shift+D快捷键进行解码

