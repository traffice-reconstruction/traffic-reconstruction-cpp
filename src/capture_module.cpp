// =========== 抓包模块实现 ===========
#include "capture_module.h"
#include "filter_module.h"
#include "packet.h"
#include "save_module.h"

#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <spdlog/spdlog.h>

#include "boost/regex.hpp"
#include "save_module.h"

#include <string>
#include <tins/tcp_ip/stream_follower.h>
#include <tins/tins.h> //新增：Tins库
#include <vector>

using boost::match_results;
using boost::regex;
using std::string;
using Tins::TCPIP::Stream;
using Tins::TCPIP::StreamFollower;

const size_t MAX_PAYLOAD = 300 * 1024;
// 查找请求头的正则表达式
regex request_regex("([\\w]+) ([^ ]+).+\r\nHost: ([\\d\\w\\.-]+)\r\n");
// 查找响应头的正则表达式
regex response_regex("HTTP/[^ ]+ ([\\d]+)");

// 在文件开头添加响应头相关的正则表达式
regex response_header_regex(
    "HTTP/([\\d\\.]+) (\\d{3}) ([^\\r\\n]+)\\r\\n([\\s\\S]*?)\\r\\n\\r\\n");
regex header_field_regex("([^:\\r\\n]+): ([^\\r\\n]+)\\r\\n");
// 提取HTTP请求信息
bool extract_request_info(const Stream::payload_type &client_payload,
                          string &method, string &url, string &host) {
  match_results<Stream::payload_type::const_iterator> client_match;
  bool valid = regex_search(client_payload.begin(), client_payload.end(),
                            client_match, request_regex);

  if (valid) {
    method = string(client_match[1].first, client_match[1].second);
    url = string(client_match[2].first, client_match[2].second);
    host = string(client_match[3].first, client_match[3].second);
  }

  return valid;
}

// 提取HTTP响应信息
bool extract_response_info(const Stream::payload_type &server_payload,
                           string &http_version, string &status_code,
                           string &status_message, string &headers_section) {
  match_results<Stream::payload_type::const_iterator> server_match;
  bool valid = regex_search(server_payload.begin(), server_payload.end(),
                            server_match, response_header_regex);

  if (valid) {
    http_version = string(server_match[1].first, server_match[1].second);
    status_code = string(server_match[2].first, server_match[2].second);
    status_message = string(server_match[3].first, server_match[3].second);
    headers_section = string(server_match[4].first, server_match[4].second);
  }

  return valid;
}

// 解析HTTP响应头
void parse_response_headers(const string &headers_section, string &content_type,
                            string &transfer_encoding, string &content_length) {
  string::const_iterator headers_begin = headers_section.begin();
  string::const_iterator headers_end = headers_section.end();
  match_results<string::const_iterator> header_field_match;

  // 遍历所有响应头字段
  while (regex_search(headers_begin, headers_end, header_field_match,
                      header_field_regex)) {
    string header_name = header_field_match[1];
    string header_value = header_field_match[2];
    spdlog::info("响应头: {} = {}", header_name, header_value);

    if (header_name == "Content-Type" || header_name == "content-type") {
      content_type = header_value.substr(0, header_value.find(';'));
    } else if (header_name == "Transfer-Encoding" ||
               header_name == "transfer-encoding") {
      transfer_encoding = header_value;
    } else if (header_name == "Content-Length" ||
               header_name == "content-length") {
      content_length = header_value;
    }

    headers_begin = header_field_match[0].second;
  }
}
// 收到服务器数据
void on_server_data(Stream &stream) {
  spdlog::info("收到服务器数据包");
  // 获取客户端和服务器的有效载荷
  const Stream::payload_type &client_payload = stream.client_payload();
  const Stream::payload_type &server_payload = stream.server_payload();

  // 提取请求信息
  string method, url, host;
  bool valid_request = extract_request_info(client_payload, method, url, host);

  // 提取响应信息
  string http_version, status_code, status_message, headers_section;
  bool valid_response =
      extract_response_info(server_payload, http_version, status_code,
                            status_message, headers_section);

  if (valid_request && valid_response) {
    // 记录基本响应信息
    spdlog::info("{} {} http://{} ", method, url, host);
    spdlog::info("HTTP响应: 版本{} 状态码{} 状态消息{}, {}字节", http_version,
                 status_code, status_message, server_payload.size());

    // 解析HTTP头部
    string content_type, transfer_encoding, content_length;
    parse_response_headers(headers_section, content_type, transfer_encoding,
                           content_length);
    // 修改判断逻辑
    if (!content_length.empty() &&
        server_payload.size() >= std::stoi(content_length)) {
      // 普通传输
      SaveModule::save_response_data(server_payload, transfer_encoding,
                                     content_type, host, url);
    } else if (transfer_encoding == "chunked") {
      // 分块传输
      SaveModule::save_response_data(server_payload, transfer_encoding,
                                     content_type, host, url);
    }

    // 告诉流处理器忽略已处理的数据
    stream.ignore_client_data();
    stream.ignore_server_data();
  }
}


// 收到客户端数据
void on_client_data(Stream &stream) {
  // Don't hold more than 3kb of data from the client's flow

  if (stream.client_payload().size() > MAX_PAYLOAD) {
    stream.ignore_client_data();
  }
}
// 嗅探到新的TCP流
void on_new_connection(Stream &stream) {
  std::string server_addr = stream.server_addr_v4().to_string();
  std::string client_addr = stream.client_addr_v4().to_string();
  auto server_port = stream.server_port();
  auto client_port = stream.client_port();

  spdlog::info("嗅探到新TCP流:{}:{}->{}:{}", client_addr, client_port,
               server_addr, server_port);
  stream.client_data_callback(&on_client_data);
  stream.server_data_callback(&on_server_data);
  stream.auto_cleanup_payloads(false);
}
// 嗅探到TCP流终止
void on_stream_terminated(Stream &stream,
                          StreamFollower::TerminationReason reason) {
  std::string server_addr = stream.server_addr_v4().to_string();
  std::string client_addr = stream.client_addr_v4().to_string();
  auto server_port = stream.server_port();
  auto client_port = stream.client_port();
  spdlog::info("TCP流终止:{}:{}->{}:{}", client_addr, client_port, server_addr,
               server_port);
}

CaptureModule::CaptureModule(const std::string &iface,
                             const std::string &filter)
    : interface(iface), filter_expr(filter) {}

CaptureModule::~CaptureModule() { stop(); }

bool CaptureModule::initialize() {

  try {
    using namespace Tins;
    // 新增：使用libtins库进行抓包
    SnifferConfiguration config;
    config.set_filter(filter_expr);
    config.set_promisc_mode(true);
    config.set_snap_len(MAX_PACKET_SIZE);

    // 创建嗅探器
    sniffer = std::make_unique<Tins::Sniffer>(interface, config);
    return true;
  } catch (const std::runtime_error &e) {
    spdlog::error("初始化抓包模块出错：{}", e.what());
    return false;
  }
}
// 抓包工作线程函数
void CaptureModule::capture_thread_func() {
  try {
    using namespace Tins;
    StreamFollower follower;
    follower.new_stream_callback(on_new_connection);
    follower.stream_termination_callback(on_stream_terminated);
    this->sniffer->sniff_loop([&](PDU &pdu) -> bool {
      if (!this->running) {
        return false;
      }
      follower.process_packet(pdu);
      return true;
    });

  } catch (const std::exception &e) {
    if (running) {
      spdlog::error("捕获线程出错: {}", e.what());
    }
  }
}
// 抓包模块启动
void CaptureModule::start() {
  if (running) {
    return;
  }

  running = true;
  capture_thread = std::thread(&CaptureModule::capture_thread_func, this);
}
// 抓包模块停止
void CaptureModule::stop() {
  if (!running) {
    return;
  }

  running = false;
  if (sniffer) {
    sniffer->stop_sniff();
  }

  if (capture_thread.joinable()) {
    capture_thread.join();
  }
}

std::vector<Packet> CaptureModule::get_packets() {
  std::lock_guard<std::mutex> lock(packet_mutex);
  std::vector<Packet> packets = std::move(packet_buffer);
  packet_buffer.clear();
  return packets;
}