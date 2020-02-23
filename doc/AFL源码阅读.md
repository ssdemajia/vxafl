---
title: AFL源码阅读
date: 2020-02-12 21:59:18
tags:afl

---

AFL是基于覆盖率指导变异的模糊测试方法，相对于符号执行的缓慢，AFL在实际应用中很有效，因此我十分好奇它的原理：

- 如何获得代码覆盖率

- 如何对测试用例进行变异(变异策略)

- 如何筛选测试用例

- 如何统计测试信息

## 项目结构

- afl-analyze.c 分析测试程序所使用的文件格式
- afl-cmin.c 减少大规模预料库中冗余的预料文件
- afl-tmin.c 减少触发相同执行路径的测试用例
- 

## 变异策略

## 输出

测试过程中会产生三个文件夹分别是：

1. queue/ ：每个独立执行路径对应的测试用例队列，也包括用户提供的初始测试用例。
2. crashes/ ：引起程序触发致命错误的测试用例。
3. hangs/ ：引起测试程序超时的测试用例。

## afl-analyze.c

## afl-tmin.c

## afl-cmin.c

## 参考

1. afl-analyze介绍，https://lcamtuf.blogspot.com/2016/02/say-hello-to-afl-analyze.html