cmake_minimum_required(VERSION 3.25)
project(revana VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(REVANA_BUILD_TITLE "Build the generated Vana360 title" OFF)
set(REVANA_REXSDK_DIR "${CMAKE_CURRENT_LIST_DIR}/../vana360-sdk"
    CACHE PATH "Path to the pinned ReXGlue SDK checkout")

add_library(revana_login
    src/login/auth_client.cpp
    src/login/auth_protocol.cpp
    src/login/lobby_client.cpp
    src/login/lobby_packets.cpp
)
target_compile_features(revana_login PUBLIC cxx_std_23)
target_include_directories(revana_login PUBLIC src)
if(WIN32)
    target_link_libraries(revana_login PRIVATE bcrypt crypt32 secur32 ws2_32)
endif()

set(REVANA_JSON_INCLUDE
    "${REVANA_REXSDK_DIR}/thirdparty/inja/third_party/include")
if(NOT EXISTS "${REVANA_JSON_INCLUDE}/nlohmann/json.hpp")
    message(FATAL_ERROR
        "nlohmann/json.hpp not found under REVANA_REXSDK_DIR")
endif()
target_include_directories(revana_login PRIVATE "${REVANA_JSON_INCLUDE}")

enable_testing()

add_executable(revana_lobby_packets_test tests/lobby_packets_test.cpp)
target_link_libraries(revana_lobby_packets_test PRIVATE revana_login)
add_test(NAME revana_lobby_packets COMMAND revana_lobby_packets_test)

add_executable(revana_lobby_client_test tests/lobby_client_test.cpp)
target_link_libraries(revana_lobby_client_test PRIVATE revana_login)
if(WIN32)
    target_link_libraries(revana_lobby_client_test PRIVATE ws2_32)
endif()
add_test(NAME revana_lobby_client COMMAND revana_lobby_client_test)

add_executable(revana_auth_protocol_test tests/auth_protocol_test.cpp)
target_link_libraries(revana_auth_protocol_test PRIVATE revana_login)
add_test(NAME revana_auth_protocol COMMAND revana_auth_protocol_test)

if(REVANA_BUILD_TITLE)
    if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/generated/rexglue.cmake")
        message(FATAL_ERROR
            "Run ReXGlue generation before enabling REVANA_BUILD_TITLE")
    endif()

    include(generated/rexglue.cmake)
    include(cmake/build_info.cmake)

    add_library(revana_hooks SHARED src/runtime/revana_hooks.cpp)
    set_target_properties(revana_hooks PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
    target_include_directories(revana_hooks PRIVATE src)
    target_link_libraries(revana_hooks PRIVATE rex::runtime)
    if(WIN32)
        target_link_libraries(revana_hooks PRIVATE bcrypt)
    endif()

    if(WIN32)
        add_executable(revana WIN32 src/main.cpp src/runtime/lobby_bridge.cpp)
    else()
        add_executable(revana src/main.cpp src/runtime/lobby_bridge.cpp)
    endif()
    rexglue_setup_target(revana GPU_PLUGINS xenos)
    revana_add_build_info(revana)
    target_include_directories(revana PRIVATE src)
    target_link_libraries(revana PRIVATE revana_hooks revana_login)
    foreach(module FFXiMain FFXi PolCoreContent)
        target_link_libraries(revana_${module} PRIVATE revana_hooks)
    endforeach()

    if(TARGET imgui)
        target_include_directories(revana PRIVATE
            "$<TARGET_PROPERTY:imgui,INTERFACE_INCLUDE_DIRECTORIES>")
    endif()
endif()
