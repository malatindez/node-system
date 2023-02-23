cmake_minimum_required(VERSION 3.21)


set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

project(node_system LANGUAGES CXX C)

if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Rpass=inline -Winline -W4")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")

elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Intel")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Winline /W4")
elseif (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /W4")
endif()
make_directory(${CMAKE_BINARY_DIR}/binary)
set(BINARY_OUTPUT_DIR ${CMAKE_BINARY_DIR}/binary)

include("${CMAKE_CURRENT_SOURCE_DIR}/third_party/CMakeLists.txt")
include("${CMAKE_CURRENT_SOURCE_DIR}/node_system/CMakeLists.txt")
include("${CMAKE_CURRENT_SOURCE_DIR}/L1_basic/CMakeLists.txt")
include("${CMAKE_CURRENT_SOURCE_DIR}/L2_core/CMakeLists.txt")
include("${CMAKE_CURRENT_SOURCE_DIR}/keygen/CMakeLists.txt")
