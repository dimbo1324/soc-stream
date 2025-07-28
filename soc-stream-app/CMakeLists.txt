# CMakeLists.txt (корневой)
cmake_minimum_required(VERSION 3.20)
project(soc_stream_app LANGUAGES CXX)

# 1) Включаем C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_options(/utf-8)

# 2) Подрубаем vcpkg (если вы хотите брать spdlog, gtest и т.п. из vcpkg)
set(CMAKE_TOOLCHAIN_FILE "C:/cManager/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "Vcpkg toolchain file")

# 3) Указываем путь до include/lib Npcap SDK
set(PCAP_SDK_DIR "${CMAKE_SOURCE_DIR}/libs/npcap-sdk-1.15")

find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h
    HINTS "${PCAP_SDK_DIR}/Include"
)
find_library(WPCAP_LIBRARY
    NAMES wpcap
    HINTS "${PCAP_SDK_DIR}/Lib/x64"
)
find_library(PACKET_LIBRARY
    NAMES Packet
    HINTS "${PCAP_SDK_DIR}/Lib/x64"
)

if(NOT PCAP_INCLUDE_DIR)
    message(FATAL_ERROR "Не найден каталог Include Npcap SDK (pcap.h). Проверьте PCAP_SDK_DIR")
endif()
if(NOT WPCAP_LIBRARY)
    message(FATAL_ERROR "Не найден wpcap.lib в ${PCAP_SDK_DIR}/Lib/x64")
endif()

# Собираем список линковочных библиотек
set(PCAP_LIBRARIES
    ${WPCAP_LIBRARY}
    ${PACKET_LIBRARY}    # на всякий случай, если понадобится
)

# 4) Выведем пути в CMake‑логи
message(STATUS "PCAP include: ${PCAP_INCLUDE_DIR}")
message(STATUS "WPCAP lib:    ${WPCAP_LIBRARY}")
message(STATUS "Packet lib:   ${PACKET_LIBRARY}")

# 5) Подключаем папку src
add_subdirectory(src)
