#include "PacketCapture.h"
#include <iostream>

PacketCapture::PacketCapture(const std::string& iface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
    if (!handle_) {
        throw std::runtime_error(errbuf);
    }
}

PacketCapture::~PacketCapture() {
    if (handle_) pcap_close(handle_);
}

void PacketCapture::startCapture(size_t packetCount) {
    struct pcap_pkthdr* header;
    const u_char* data;
    for (size_t i = 0; i < packetCount; ++i) {
        int res = pcap_next_ex(handle_, &header, &data);
        if (res <= 0) { --i; continue; }
        // Предположим, Ethernet + IPv4 + TCP/UDP
        const auto* ip = data + 14; // минус заголовок Ethernet
        uint8_t version = (ip[0] & 0xF0) >> 4;
        if (version == 4) {
            uint32_t src = ntohl(*(uint32_t*)(ip + 12));
            uint32_t dst = ntohl(*(uint32_t*)(ip + 16));
            std::cout << "Packet " << i + 1
                << " len=" << header->len
                << " src=" << ((src >> 24) & 0xFF) << '.' << ((src >> 16) & 0xFF)
                << '.' << ((src >> 8) & 0xFF) << '.' << (src & 0xFF)
                << " dst=" << ((dst >> 24) & 0xFF) << '.' << ((dst >> 16) & 0xFF)
                << '.' << ((dst >> 8) & 0xFF) << '.' << (dst & 0xFF)
                << "\n";
        }
    }
}
