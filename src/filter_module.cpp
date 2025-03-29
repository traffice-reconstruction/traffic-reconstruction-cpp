#include "filter_module.h"
 
#include <spdlog/spdlog.h>
#include <algorithm>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using std::string;
// =========== 过滤模块实现 ===========

// 处理分块传输数据
std::vector<uint8_t>
FilterModule::handle_chunked_transfer(const std::vector<uint8_t> &raw_data) {
  std::vector<uint8_t> result;
  size_t pos = 0;

  // 找到响应体开始的位置（跳过响应头）
  const std::string header_end = "\r\n\r\n";
  auto body_start = std::search(raw_data.begin(), raw_data.end(),
                                header_end.begin(), header_end.end());
  if (body_start == raw_data.end()) {
    return result;
  }
  pos = (body_start - raw_data.begin()) + header_end.length();

  // 处理每个分块
  while (pos < raw_data.size()) {
    // 读取分块大小
    std::string chunk_size_str;
    while (pos < raw_data.size() && raw_data[pos] != '\r') {
      chunk_size_str += raw_data[pos++];
    }
    pos += 2; // 跳过\r\n

    // 转换分块大小（十六进制）
    size_t chunk_size;
    std::stringstream ss;
    ss << std::hex << chunk_size_str;
    ss >> chunk_size;

    // 如果分块大小为0，说明是最后一个分块
    if (chunk_size == 0) {
      break;
    }

    // 检查是否有足够的数据
    if (pos + chunk_size > raw_data.size()) {
      
      spdlog::error("分块大小超出数据范围");
      break;
    }

    // 复制分块数据
    result.insert(result.end(), raw_data.begin() + pos,
                  raw_data.begin() + pos + chunk_size);

    pos += chunk_size + 2; // 跳过分块数据和\r\n
  }

  return result;
}

//
std::string
FilterModule::determine_extension(const std::string &content_type,
                                  const Stream::payload_type &server_payload,
                                  const std::string &url) {
  // 将内容类型映射到文件扩展名
  static const std::map<std::string, std::string> extensions = {
      {"text/html", ".html"},
      {"text/plain", ".txt"},
      {"text/css", ".css"},
      {"text/javascript", ".js"},
      {"application/javascript", ".js"},
      {"application/json", ".json"},
      {"image/jpeg", ".jpg"},
      {"image/png", ".png"},
      {"image/gif", ".gif"},
      {"image/svg+xml", ".svg"},
      {"image/webp", ".webp"},
      {"audio/mpeg", ".mp3"},
      {"audio/wav", ".wav"},
      {"video/mp4", ".mp4"},
      {"video/webm", ".webm"},
      {"application/pdf", ".pdf"},
      {"application/zip", ".zip"},
      {"application/x-www-form-urlencoded", ".form"}};

  // 优先级1：基于Content-Type的扩展名
  if (!content_type.empty()) {
    auto it = extensions.find(content_type);
    if (it != extensions.end())
      return it->second;
  }

  // 优先级2：基于魔数的扩展名检测

  // 优先级3：基于URL路径的扩展名猜测（如/download/file.exe）
  size_t last_dot = url.find_last_of('.');
  if (last_dot != std::string::npos) {
    std::string ext = url.substr(last_dot);
    if (ext.size() <= 5 && ext.find('?') == std::string::npos) {
      // 限制扩展名长度，防止类似“.html?param=1”的情况
      return ext;
    }
  }

  return ".bin"; // 最终默认值
}