#ifndef SAVE_MODULE_H
#define SAVE_MODULE_H

#include <tins/tcp_ip/stream_follower.h>
#include <string>

class SaveModule {
public:
  // 保存响应数据到文件
  static bool
  save_response_data(const Tins::TCPIP::Stream::payload_type &server_payload,
                     const std::string &transfer_encoding,
                     const std::string &content_type, const std::string &host,
                     const std::string &url);
};

#endif // SAVE_MODULE_H