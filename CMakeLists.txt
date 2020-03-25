# Description:
#   ./README
# Help:
#   [https://cmake.org/cmake/help/latest/]
#   [https://zhuanlan.zhihu.com/p/93895403]
# Author: imgrass

cmake_minimum_required(VERSION 3.0)

# set the project name
project(wireshark C)
set(EXECUTABLE_FILE_NAME wireshark)

# print environment argvs
message(STATUS "[CMAKE_SYSTEM] system:${CMAKE_SYSTEM}")
message(STATUS "[CMAKE_C_COMPILER_ID] ${CMAKE_C_COMPILER_ID}")
if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    message(FATAL_ERROR "We want GNU-C compiler, but now is
                         ${CMAKE_C_COMPILER_ID}")
endif()


# set complilation flags
add_compile_options(-O2 -g -D_FORTIFY_SOURCE=2 -fPIE -fstack-protector-strong
                    --param=ssp-buffer-size=4 -Wmissing-prototypes -Wall)

#==============================================================================
# SOURCE FILES
#==============================================================================
macro(add_dir_for_src_lst src_list dir src_list_base)
    message(STATUS "==+ Include src files under <dir:${${dir}}>")
    foreach(src IN LISTS ${src_list_base})
        message(STATUS "==> Add src file <${src}>")
        set(${src_list} ${${src_list}} ${${dir}}/${src})
    endforeach()
    message(STATUS "... src_list is ${${src_list}}")
    set(src_list "xxx")
endmacro()

set(DIR_SRC src)
set(SRC_FILES)
set(SRC_FILES_BASE
    main.c parse_pcap_util.c recv_packet.c send_packet.c
)
add_dir_for_src_lst(SRC_FILES DIR_SRC SRC_FILES_BASE)

#==============================================================================
# THE DIRECTORIES OF HEADER FILES
#==============================================================================
set(DIR_HEADER
    include
    lib/libevent/include
    lib/libpcap/include
)
include_directories(${DIR_HEADER})

#==============================================================================
# THE DIRECTORIES OF STATIC LINK LIBRARY
#==============================================================================
set(DIR_LIB
    lib/libevent/lib
    lib/libpcap/lib
)
link_directories(${DIR_LIB})


#==============================================================================
# TARGET BINARY FILE
#==============================================================================
add_executable(${EXECUTABLE_FILE_NAME} ${SRC_FILES})

#------------------------------------------------------------------------------
# find crossponding lib file
find_library(LIB_PCAP pcap ${DIR_LIB})
find_library(LIB_EVENT event ${DIR_LIB})
#...

#------------------------------------------------------------------------------
# implement link ...
target_link_libraries(${EXECUTABLE_FILE_NAME}
    ${LIB_PCAP}
    ${LIB_EVENT}
)
