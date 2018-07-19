# ShellCodeFrame_x64 工程介绍
  
  项目详细介绍，查看“Windows平台下高级Shellcode编程技术.doc”
  
  这是一个使用VS2008生成的编写x64位shellcode的框架。
	在shellcode主代码中，按照内存对齐大小，将dll在内存中进行展开，修复导入表，修复重定位，根据导出表，寻找dll中函数的地址，调用指定dll的函数。

=====================UnModuelInject================

使用生成的shellcode对静态dll进行无模块注入


配置 x64  插入汇编的VS环境。