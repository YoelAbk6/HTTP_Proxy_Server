cmake_minimum_required(VERSION 3.21)
project(HTTP_Proxy_Server C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS -pthread)

add_executable(HTTP_Proxy_Server threadpool.h threadpool.c proxyServer.c)
