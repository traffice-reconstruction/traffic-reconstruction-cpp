#ifndef FILTER_MODULE_H
#define FILTER_MODULE_H

#include "packet.h"
#include <map>
#include <string>
#include <vector>
#include <tins/tins.h>
#include <tins/tcp_ip/stream_follower.h>

using Tins::TCPIP::Stream;

class FilterModule {
private:
  std::map<std::string, std::string> url_paths; // 添加URL路径映射

public:
  FilterModule() = default;

  std::vector<uint8_t>
  handle_chunked_transfer(const std::vector<uint8_t> &raw_data);

  std::string determine_extension(const std::string &content_type,
                                  const Stream::payload_type &server_payload,
                                  const std::string &url);
};

#endif // FILTER_MODULE_H