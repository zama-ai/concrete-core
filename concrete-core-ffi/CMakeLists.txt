# concrete-core-ffi/CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(concrete-core-ffi C)
set(SOURCE tests/*.c)
enable_testing()
add_subdirectory(tests)
