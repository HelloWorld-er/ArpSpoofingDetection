cmake_minimum_required(VERSION 3.30)
project(ArpSpoofingDetection C CXX)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_STANDARD 14)
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DVK_PROTOTYPES")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVK_PROTOTYPES")

set(CMAKE_C_COMPILER "/opt/homebrew/bin/x86_64-w64-mingw32-gcc")
set(CMAKE_CXX_COMPILER "/opt/homebrew/bin/x86_64-w64-mingw32-g++")


# GLFW
if(NOT GLFW_DIR)
    set(GLFW_DIR ./glfw) # Set this to point to an up-to-date GLFW repo
endif()
option(GLFW_BUILD_EXAMPLES "Build the GLFW example programs" OFF)
option(GLFW_BUILD_TESTS "Build the GLFW test programs" OFF)
option(GLFW_BUILD_DOCS "Build the GLFW documentation" OFF)
option(GLFW_INSTALL "Generate installation target" OFF)
option(GLFW_DOCUMENT_INTERNALS "Include internals in documentation" OFF)
add_subdirectory(${GLFW_DIR} binary_dir EXCLUDE_FROM_ALL)
include_directories(${GLFW_DIR}/include)

# Dear ImGui
set(IMGUI_DIR ./imgui)
include_directories(${IMGUI_DIR} ${IMGUI_DIR}/backends ${IMGUI_DIR}/misc/freetype)

# Libraries
find_package(Vulkan REQUIRED)
#find_library(VULKAN_LIBRARY
#NAMES vulkan vulkan-1)
#set(LIBRARIES "glfw;${VULKAN_LIBRARY}")

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
    set(PCAP_LIBRARIES "C:/Program Files/npcap-sdk-1.15/Lib/${ARCHITECTURE_ID}/wpcap.lib;C:/Program Files/npcap-sdk-1.15/Lib/${ARCHITECTURE_ID}/Packet.lib;Ws2_32")
elseif (APPLE)
    find_library(PCAP_LIBRARY pcap)
    if (NOT PCAP_LIBRARY)
        message(FATAL_ERROR "libpcap not found!")
    endif()
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
endif()

# additional package/libraries for imgui
#find_package(Freetype REQUIRED)
#include_directories(${FREETYPE_INCLUDE_DIRS})

# set LIBRARIES variable
set(LIBRARIES "glfw;Vulkan::Vulkan;${PCAP_LIBRARIES}")

# Use vulkan headers from glfw:
include_directories(${GLFW_DIR}/deps)



file(GLOB sources *.cpp)
file(COPY ${CMAKE_SOURCE_DIR}/resources DESTINATION ${CMAKE_BINARY_DIR})

add_executable(ArpSpoofingDetector
    main.cpp
        ArpSpoofingDetector.cpp
        ArpSpoofingDetector.h
        ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp ${IMGUI_DIR}/backends/imgui_impl_vulkan.cpp ${IMGUI_DIR}/imgui.cpp ${IMGUI_DIR}/imgui_draw.cpp ${IMGUI_DIR}/imgui_demo.cpp ${IMGUI_DIR}/imgui_tables.cpp ${IMGUI_DIR}/imgui_widgets.cpp
        UI.cpp
        UI.h
)
target_link_libraries(ArpSpoofingDetector ${LIBRARIES})
target_include_directories(ArpSpoofingDetector PUBLIC include/ether_structure)


set(MACOSX_BUNDLE_ICON_FILE "/resources/icons/icon.icns")
set_source_files_properties("/resources/icons/icon.icns" PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
set_target_properties(ArpSpoofingDetector PROPERTIES MACOSX_BUNDLE TRUE)
