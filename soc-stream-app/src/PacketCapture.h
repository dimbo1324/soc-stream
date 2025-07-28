#pragma once
#include <pcap.h>
#include <string>

class PacketCapture {
public:
    PacketCapture(const std::string& iface);
    ~PacketCapture();
    void startCapture(size_t packetCount);
private:
    pcap_t* handle_{ nullptr };
};
