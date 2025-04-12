cmake_minimum_required(VERSION 3.30)
project(ArpSpoofingDetection)

set(CMAKE_CXX_STANDARD 14)

add_executable(MainExecutable
    main.cpp
)

target_include_directories(MainExecutable PUBLIC include/ether_structure)

# Find and link libpcap
if (WIN32)
    if (CMAKE_GENERATOR_PLATFORM STREQUAL "x64")
        set(ARCHITECTURE_ID "x64")
    elseif (CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64")
        set(ARCHITECTURE_ID "ARM64")
    elseif (CMAKE_GENERATOR_PLATFORM STREQUAL "Win32")
        set(ARCHITECTURE_ID "")
    else ()
        message(FATAL_ERROR "no version of Npcap for ARCHITECTURE ${CMAKE_GENERATOR_PLATFORM}")
    endif()
    include_directories("C:/Program Files/npcap-sdk-1.15/Include")
    link_directories("C:/Program Files/npcap-sdk-1.15/Lib/${ARCHITECTURE_ID}")
    target_link_libraries(MainExecutable PRIVATE "C:/Program Files/npcap-sdk-1.15/Lib/${ARCHITECTURE_ID}/wpcap.lib" "C:/Program Files/npcap-sdk-1.15/Lib/${ARCHITECTURE_ID}/Packet.lib" Ws2_32)
elseif (APPLE)
    find_library(PCAP_LIBRARY pcap)
    if (NOT PCAP_LIBRARY)
        message(FATAL_ERROR "libpcap not found!")
    endif()
    target_link_libraries(MainExecutable ${PCAP_LIBRARY})
endif()
