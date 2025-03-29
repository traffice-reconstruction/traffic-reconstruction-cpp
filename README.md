# Traffic Reconstruction in C++

一个基于C++的网络流量捕获和重建工具，能够实时捕获HTTP流量并重建响应内容。

## 功能特点

- 实时捕获网络接口上的HTTP流量
- 解析HTTP请求和响应
- 支持分块传输编码(chunked transfer encoding)
- 根据Content-Type和URL自动确定文件类型
- 保存HTTP响应内容到本地文件

## 系统要求

- C++20 兼容的编译器
- CMake 3.28 或更高版本
- vcpkg 包管理器

## 依赖库

- libtins: 网络数据包捕获和解析
- libpcap: 底层网络数据包捕获
- spdlog: 日志记录
- fmt: 格式化库
- Boost.Regex: 正则表达式处理
- GTest: 单元测试框架(可选)

## 构建说明

### 使用vcpkg安装依赖

```bash
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
./vcpkg install libtins spdlog fmt boost-regex gtest
```

### 构建项目

```bash
git clone https://github.com/yourusername/traffic-reconstruction-cpp.git
cd traffic-reconstruction-cpp
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build .
```

或者使用CMake预设:

```bash
cmake --preset=default
cmake --build build
```

## 使用方法

```bash
./traffic_test [interface] [filter] [output_directory]
```

参数说明:
- `interface`: 要监听的网络接口名称(例如: eth0)
- `filter`: BPF过滤表达式(例如: "tcp port 80 or tcp port 443")
- `output_directory`: 保存捕获文件的目录

示例:
```bash
./traffic_test eth0 "tcp port 80 or tcp port 443" ./output
```

## 项目结构

- `include/`: 头文件目录
  - `capture_module.h`: 数据包捕获模块
  - `filter_module.h`: 数据过滤模块
  - `save_module.h`: 数据保存模块
  - `control_module.h`: 控制模块
  - `packet.h`: 数据包结构定义
- `src/`: 源代码目录
- `tests/`: 单元测试目录

## 模块说明

- **CaptureModule**: 负责网络数据包捕获
- **FilterModule**: 负责数据过滤和处理
- **SaveModule**: 负责保存响应数据
- **ControlModule**: 作为控制中心协调各模块工作

## 许可证

[MIT License](LICENSE)

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request
```