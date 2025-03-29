#ifndef CAPTURE_MODULE_H
#define CAPTURE_MODULE_H

#include "packet.h"

#include <mutex>
#include <pcap.h>
#include <thread>
#include <vector>

// 前向声明libtins类
namespace Tins {
class Sniffer;
class PDU;
} // namespace Tins

class CaptureModule {
private:
  std::unique_ptr<Tins::Sniffer> sniffer;
  std::string interface;
  std::string filter_expr;
  std::atomic<bool> running{false};
  std::thread capture_thread;
  std::mutex packet_mutex;
  std::vector<Packet> packet_buffer;

  bool packet_handler(Tins::PDU &pdu);

  void capture_thread_func();

public:
  CaptureModule(const std::string &iface, const std::string &filter);

  ~CaptureModule();

  bool initialize();

  void start();

  void stop();

  std::vector<Packet> get_packets();
};

#endif // CAPTURE_MODULE_H