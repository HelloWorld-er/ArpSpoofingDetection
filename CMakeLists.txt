cmake_minimum_required(VERSION 3.30)
project(ArpSpoofingDetection)

set(CMAKE_CXX_STANDARD 14)

add_executable(MainExecutable
    main.cpp
)

target_include_directories(MainExecutable PUBLIC include/ether_structure)

# Find and link libpcap
if (WIN32)
    include_directories("C:/Program Files/npcap-sdk-1.15/Include")
    link_directories("C:/Program Files/npcap-sdk-1.15/Lib/arm64")
    target_link_libraries(MainExecutable PRIVATE "C:/Program Files/npcap-sdk-1.15/Lib/arm64/wpcap.lib" "C:/Program Files/npcap-sdk-1.15/Lib/arm64/Packet.lib" Ws2_32)
elseif (APPLE)
    find_library(PCAP_LIBRARY pcap)
    if (NOT PCAP_LIBRARY)
        message(FATAL_ERROR "libpcap not found!")
    endif()
    target_link_libraries(MainExecutable ${PCAP_LIBRARY})
endif()
