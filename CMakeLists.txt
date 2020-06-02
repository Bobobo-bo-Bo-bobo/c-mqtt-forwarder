cmake_minimum_required(VERSION 2.6)
project(c-mqtt-forwarder)
set(C_MQTT_FORWARDER_VERSION "1.0.0-20200602")

set(CMAKE_BUILD_TYPE Debug)
set(DEBUG_BUILD 0)
string(TOUPPER "${CMAKE_BUILD_TYPE}" BUILD_TYPE)
if (BUILD_TYPE STREQUAL DEBUG)
    set(DEBUG_BUILD 1)
endif(BUILD_TYPE STREQUAL DEBUG)

include (CheckFunctionExists)
include (CheckIncludeFile)
include (FindPkgConfig)

check_function_exists(memset HAVE_MEMSET)
check_function_exists(calloc HAVE_CALLOC)
check_function_exists(sigaction HAVE_SIGACTION)
check_include_file(stdbool.h HAVE_STDBOOL_H)

# check for libmosquitto
find_library(LIBMOSQUITTO mosquitto)
if (LIBMOSQUITTO-NOTFOUND)
    message(FATAL_ERROR "Required library libmosquitto not found")
endif(LIBMOSQUITTO-NOTFOUND)

# check for uuid
pkg_search_module(LIBUUID REQUIRED uuid)
include_directories(SYSTEM ${LIBUUID_INCLUDE_DIRS})
link_directories(${LIBUUID_LIBRARY_DIRS})

check_include_file(uthash.h HAVE_UTHASH_H)
if (NOT HAVE_UTHASH_H)
    message(FATAL_ERROR "Required include file uthash.h not found")
endif(NOT HAVE_UTHASH_H)

check_include_file(cjson/cJSON.h HAVE_CJSON_H)
if (NOT HAVE_CJSON_H)
    message(FATAL_ERROR "Required include file cjson/cJSON.h not found")
endif(NOT HAVE_CJSON_H)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package (Threads)
find_package(Threads REQUIRED)

add_library(usage usage.c)
add_library(parse_cfg parse_cfg.c)
add_library(mqtt mqtt.c)
add_library(process_msgs process_msgs.c)
add_library(util util.c)
add_library(signal_handler signal_handler.c)

# log.c: https://github.com/rxi/log.c
add_library(log log/log.c)
add_definitions("-DLOG_USE_COLOR")

# yuarel.c: https://github.com/jacketizer/libyuarel
add_library(yuarel yuarel/yuarel.c)

configure_file("${PROJECT_SOURCE_DIR}/c-mqtt-forwarder.h.in" "${PROJECT_SOURCE_DIR}/c-mqtt-forwarder.h")

add_executable(c-mqtt-forwarder main.c)

target_link_libraries(c-mqtt-forwarder log)
target_link_libraries(c-mqtt-forwarder mqtt)
target_link_libraries(c-mqtt-forwarder signal_handler)
target_link_libraries(c-mqtt-forwarder usage)
target_link_libraries(c-mqtt-forwarder util)
target_link_libraries(c-mqtt-forwarder parse_cfg)
target_link_libraries(c-mqtt-forwarder process_msgs)
target_link_libraries(c-mqtt-forwarder signal_handler)
target_link_libraries(c-mqtt-forwarder yuarel)
target_link_libraries(c-mqtt-forwarder "-lmosquitto")
target_link_libraries(c-mqtt-forwarder "-lm")
target_link_libraries(c-mqtt-forwarder ${LIBUUID_LIBRARIES})
target_link_libraries(c-mqtt-forwarder ${LIBMOSQUITTO_LIBRARIES})
target_link_libraries(c-mqtt-forwarder "-lcjson")
target_link_libraries(c-mqtt-forwarder ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS c-mqtt-forwarder DESTINATION bin)

