cmake_minimum_required(VERSION 3.30)
project(ArpSpoofingDetection)

set(CMAKE_CXX_STANDARD 14)

add_executable(MainExecutable
    main.cpp
)

target_include_directories(MainExecutable PUBLIC include/ether_structure)

# Find and link libpcap
if (APPLE)
    find_library(PCAP_LIBRARY pcap)
    if (NOT PCAP_LIBRARY)
        message(FATAL_ERROR "libpcap not found!")
    endif()
endif()

target_link_libraries(MainExecutable ${PCAP_LIBRARY})
