cmake_minimum_required(VERSION 3.30)
project(ArpSpoofingDetection)

set(CMAKE_CXX_STANDARD 14)

add_executable(MainExecutable
    main.cpp)

# Find and link libpcap
find_library(PCAP_LIBRARY pcap)
if (NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found!")
endif()

target_link_libraries(MainExecutable ${PCAP_LIBRARY})
