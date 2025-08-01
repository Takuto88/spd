cmake_minimum_required(VERSION 3.31)
project(spd
    VERSION 0.0.1
    DESCRIPTION "SMS PDU Decoder"
    LANGUAGES C)

set(CMAKE_C_STANDARD 11)

add_executable(spd src/main.c src/sms_pdu.c)
