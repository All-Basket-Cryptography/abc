cmake_minimum_required(VERSION 3.20)
project(abc_c_consumer LANGUAGES C)

find_package(ABCCrypto 0.1 CONFIG REQUIRED)
enable_testing()

add_executable(abc_static_consumer consumer.c)
target_link_libraries(abc_static_consumer PRIVATE ABC::c)
target_compile_features(abc_static_consumer PRIVATE c_std_11)
add_test(NAME abc_static_consumer COMMAND abc_static_consumer)

add_executable(abc_shared_consumer consumer.c)
target_link_libraries(abc_shared_consumer PRIVATE ABC::c_shared)
target_compile_features(abc_shared_consumer PRIVATE c_std_11)
add_test(NAME abc_shared_consumer COMMAND abc_shared_consumer)

if(WIN32)
    add_custom_command(TARGET abc_shared_consumer POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                $<TARGET_FILE:ABC::c_shared> $<TARGET_FILE_DIR:abc_shared_consumer>)
endif()
