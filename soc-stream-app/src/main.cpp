#include <pcap.h>
#include <iostream>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1) Получаем список всех доступных интерфейсов
    pcap_if_t* alldevs = nullptr;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error finding devices: " << errbuf << "\n";
        return 1;
    }
    if (!alldevs) {
        std::cerr << "No interfaces found.\n";
        return 1;
    }

    // Выбираем первый интерфейс
    const char* dev = alldevs->name;
    std::cout << "Using interface: " << dev << "\n";

    // 2) Открываем его для захвата
    pcap_t* handle = pcap_open_live(dev, 65536, /*promisc=*/1, /*timeout_ms=*/1000, errbuf);
    if (!handle) {
        std::cerr << "Error opening device: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 3) Захватываем один пакет
    struct pcap_pkthdr* header;
    const u_char* data;
    int res = pcap_next_ex(handle, &header, &data);
    if (res == 1) {
        std::cout << "Captured a packet, length: " << header->len << "\n";
    }
    else if (res == 0) {
        std::cout << "Timeout elapsed, no packet received.\n";
    }
    else {
        std::cout << "Error capturing packet: " << pcap_geterr(handle) << "\n";
    }

    // Освобождаем ресурсы
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
