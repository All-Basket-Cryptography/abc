cmake_minimum_required(VERSION 3.20)
project(abc_cpp_consumer LANGUAGES CXX)

find_package(ABCCryptoCpp 0.1 CONFIG REQUIRED)
enable_testing()

add_executable(abc_cpp_consumer consumer.cpp)
target_link_libraries(abc_cpp_consumer PRIVATE ABC::cpp)
add_test(NAME abc_cpp_consumer COMMAND abc_cpp_consumer)
