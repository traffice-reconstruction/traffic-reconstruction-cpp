#include "save_module.h"
#include "filter_module.h"
#include <filesystem>
#include <fstream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>

FilterModule filter_module;

bool SaveModule::save_response_data(
    const Tins::TCPIP::Stream::payload_type &server_payload,
    const std::string &transfer_encoding, const std::string &content_type,
    const std::string &host, const std::string &url) {
  std::string file_name;
  std::string extension =
      filter_module.determine_extension(content_type, server_payload, url);
  if (url.ends_with('/')) {
    file_name = "output/" + host + url + "index" + extension;
  } else {
    file_name = "output/" + host + url;
  }

  if (!std::filesystem::exists("output/" + host)) {
    spdlog::info("目录{}不存在，正在创建", "output/" + host);
    // 创建目录
    std::filesystem::create_directory("output/" + host);
  }

  std::ofstream file(file_name, std::ios::binary);
  if (!file.is_open()) {
    spdlog::error("无法打开文件:{}进行写入", file_name);
    return false;
  }

  // 找到响应体开始的位置（跳过响应头）
  const std::string header_end = "\r\n\r\n";
  auto body_start = std::search(server_payload.begin(), server_payload.end(),
                                header_end.begin(), header_end.end());
  if (body_start == server_payload.end()) {
    spdlog::error("未找到响应体的开始位置");
    return false;
  }

  // 计算响应体的偏移
  size_t body_offset =
      (body_start - server_payload.begin()) + header_end.length();

  if (transfer_encoding == "chunked") {
    // 处理分块传输
    auto decoded_data = filter_module.handle_chunked_transfer(server_payload);
    file.write(reinterpret_cast<const char *>(decoded_data.data()),
               decoded_data.size());
    spdlog::info("已处理分块传输，解码后大小: {} 字节", decoded_data.size());
  } else {
    // 普通传输
    file.write(
        reinterpret_cast<const char *>(server_payload.data() + body_offset),
        server_payload.size() - body_offset);
  }
  auto success_logger = spdlog::stdout_color_mt("success"); //创建独立logger方便突出显示。
  success_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] %^[SUCCESS]%$ %v");
  success_logger->info("文件：{} 保存成功", file_name);

  file.close();
  return true;
}