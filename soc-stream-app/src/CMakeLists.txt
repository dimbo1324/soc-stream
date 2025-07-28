# src/CMakeLists.txt

# 1) Собираем библиотеку packet_capture
add_library(packet_capture
    PacketCapture.cpp
    PacketCapture.h
)

# 2) Include‑директории: Npcap SDK и текущая папка (для PacketCapture.h)
target_include_directories(packet_capture
    PUBLIC
        ${PCAP_INCLUDE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# 3) Линкуем её с wpcap.lib и Packet.lib + Ws2_32 (для функций сети)
target_link_libraries(packet_capture
    PUBLIC
        ${PCAP_LIBRARIES}
        Ws2_32
)

# 4) Собираем исполняемый
add_executable(capture_app main.cpp)

# 5) Линкуем capture_app с packet_capture (подтянутся инклуды и либа)
target_link_libraries(capture_app
    PRIVATE
        packet_capture
)
