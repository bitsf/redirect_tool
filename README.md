# 重定向工具

## 概述
这是一个用Rust构建的命令行工具，用于处理网络重定向。

## 依赖
- tokio (1.28.0): 带有完整功能的异步运行时
- clap (4.3.0): 命令行参数解析
- anyhow (1.0.71): 错误处理

## 特性
- 管理员可以方便的指定本地监听端口和目标转发端口
- 管理员可以指定预设密码，或者自动生成随机密码打印在屏幕上
- 当一个新用户第一次访问监听端口时，会要求输入预设的密码，验证成功后才能使用转发
- 新用户根据IP进行识别
- 如果用户在一段时间内没有网络流量，则自动删除此用户，用户再次使用时需要重新输入密码认证

## 用法
- 使用以下命令允许用户访问8888端口时将流量转发到8080端口，并且将预设密码设置为12345
redirect_tool 127.0.0.1:8888 127.0.0.1:8080 -p 12345

## 安装
```bash
cargo build --release
```

## 开发


## 许可证
MIT