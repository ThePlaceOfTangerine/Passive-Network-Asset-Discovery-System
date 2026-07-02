cmake_minimum_required(VERSION 3.10)

project(asset_collector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(CURL REQUIRED)

add_executable(asset_collector
    src/main.cpp
    src/HttpClient.cpp
    src/ArpParser.cpp
)

target_include_directories(asset_collector PRIVATE include)

target_link_libraries(asset_collector
    pcap
    CURL::libcurl
)
