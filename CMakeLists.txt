cmake_minimum_required(VERSION 3.15)
project(sniffer)

set(CMAKE_CXX_STANDARD 14)

SET(GCC_COVERAGE_LINK_FLAGS    "-lpcap")

include(FindPCAP.cmake)
set(SOURCE_FILES src/main.c)

add_executable(sniffer ${SOURCE_FILES})
target_link_libraries(sniffer ${PCAP_LIBRARY})
