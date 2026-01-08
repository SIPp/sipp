cmake_minimum_required(VERSION 3.10)

# set the project name
project(SIPp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -pedantic -Wno-deprecated-copy -Wno-array-bounds")
endif()

# Include binary dir first, where we add generated config.h and
# version.h. If nothing is found there (release tar) use the version.h
# from the source.
include_directories(
  ${PROJECT_BINARY_DIR}
  ${PROJECT_SOURCE_DIR}/include)

if(BUILD_STATIC)
  set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
  set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
endif(BUILD_STATIC)

function(optional_library LIB_NAME DESCRIPTION)
  set(USE_${LIB_NAME} "DEFAULT" CACHE STRING "${DESCRIPTION}")

  string(TOLOWER "${LIB_NAME}" LIB_LOWER)
  if(USE_${LIB_NAME} STREQUAL "ON" OR USE_${LIB_NAME} STREQUAL "1")
    find_library(${LIB_NAME}_LIBRARY ${LIB_LOWER})
    set(USE_${LIB_NAME} 1)
  elseif(USE_${LIB_NAME} STREQUAL "OFF" OR USE_${LIB_NAME} STREQUAL "0")
    set(USE_${LIB_NAME} 0)
  else()
    find_library(${LIB_NAME}_LIBRARY ${LIB_LOWER})
    if(${LIB_NAME}_LIBRARY)
      message(STATUS "${LIB_NAME} is enabled")
      set(USE_${LIB_NAME} 1 PARENT_SCOPE)
    else()
      message(STATUS "${LIB_NAME} is disabled")
      set(USE_${LIB_NAME} 0 PARENT_SCOPE)
    endif()
  endif()
endfunction()

function(add_sipp_target TARGET_NAME)
  cmake_parse_arguments(SIPP "EXCLUDE_FROM_ALL" "" "SOURCES;EXTRA_LIBRARIES;EXTRA_INCLUDES;COMPILE_DEFINITIONS" ${ARGN})

  if(SIPP_EXCLUDE_FROM_ALL)
    add_executable(${TARGET_NAME} EXCLUDE_FROM_ALL ${all_SRCS} ${SIPP_SOURCES})
  else()
    add_executable(${TARGET_NAME} ${all_SRCS} ${SIPP_SOURCES})
  endif()

  if(SIPP_COMPILE_DEFINITIONS)
    target_compile_definitions(${TARGET_NAME} PUBLIC ${SIPP_COMPILE_DEFINITIONS})
  endif()

  if(SIPP_EXTRA_INCLUDES)
    target_include_directories(${TARGET_NAME} SYSTEM PUBLIC ${SIPP_EXTRA_INCLUDES})
  endif()

  apply_common_sipp_dependencies(${TARGET_NAME})

  if(SIPP_EXTRA_LIBRARIES)
    target_link_libraries(${TARGET_NAME} ${SIPP_EXTRA_LIBRARIES})
  endif()
endfunction()

function(apply_common_sipp_dependencies TARGET_NAME)
  # Basic libraries that all targets need
  target_link_libraries(${TARGET_NAME} dl pthread)

  # Enable symbol export for plugins
  set_target_properties(${TARGET_NAME} PROPERTIES ENABLE_EXPORTS ON)

  # Conditional libraries based on configuration
  if(CURSES_LIBRARY)
    target_link_libraries(${TARGET_NAME} ${CURSES_LIBRARY})
    if(CURSES_LIBRARY_INCLUDE_DIRS OR TINFO_LIBRARY_INCLUDE_DIRS)
      target_include_directories(${TARGET_NAME} SYSTEM PUBLIC ${CURSES_LIBRARY_INCLUDE_DIRS} ${TINFO_LIBRARY_INCLUDE_DIRS})
    endif()
  endif()

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND TINFO_LIBRARY)
    target_link_libraries(${TARGET_NAME} ${TINFO_LIBRARY})
  endif()

  if(RT_LIBRARY)
    target_link_libraries(${TARGET_NAME} ${RT_LIBRARY})
  endif()

  if(USE_GSL AND GSL_LIBRARY AND GSLCBLAS_LIBRARY)
    target_link_libraries(${TARGET_NAME} ${GSL_LIBRARY} ${GSLCBLAS_LIBRARY})
  endif()

  target_link_libraries(${TARGET_NAME} ${SSL_LIBRARIES})
  if(SSL_LIBRARY_DIRS)
    target_link_directories(${TARGET_NAME} PRIVATE ${SSL_LIBRARY_DIRS})
  endif()
  if(SSL_INCLUDE_DIRS)
    target_include_directories(${TARGET_NAME} SYSTEM PUBLIC ${SSL_INCLUDE_DIRS})
  endif()

  if(USE_PCAP AND PCAP_LIBRARIES)
    target_link_libraries(${TARGET_NAME} ${PCAP_LIBRARIES})
    if(CAP_LIBRARY)
      target_link_libraries(${TARGET_NAME} ${CAP_LIBRARY})
    endif()
  endif()

  if(USE_SCTP AND SCTP_LIBRARY)
    target_link_libraries(${TARGET_NAME} ${SCTP_LIBRARY})
  endif()

  if(BUILD_STATIC AND MSYS)
    target_link_libraries(${TARGET_NAME} crypt32)
  endif()
endfunction()

optional_library(SCTP "Build with SCTP support")
optional_library(PCAP "Build with PCAP playback support")
optional_library(GSL "Build with improved statistical support")

option(USE_WOLFSSL "Use WolfSSL instead of OpenSSL" OFF)
option(TLS_KEY_LOGGING "Enable TLS session key logging (OpenSSL only)" OFF)

find_package(PkgConfig QUIET)  # import pkg_check_modules() and friends

if(USE_WOLFSSL)
    pkg_search_module(SSL REQUIRED wolfssl>=3.15.0)
    if(TLS_KEY_LOGGING)
        message(WARNING "TLS key logging is only supported with OpenSSL, ignoring")
        set(TLS_KEY_LOGGING OFF)
    endif()
    add_definitions("-DUSE_WOLFSSL" "-DOPENSSL_ALL")
else()
    pkg_search_module(SSL REQUIRED openssl>=1.1.1)
    add_definitions("-DUSE_OPENSSL")
    if(TLS_KEY_LOGGING)
        add_definitions("-DUSE_OPENSSL_KL")
    endif()
endif()

option(BUILD_STATIC "Build a statically-linked binary" OFF)
option(USE_LOCAL_IP_HINTS "Build with local ip hints priority" OFF)
option(USE_ASAN "Build with AddressSanitizer support" OFF)

if(USE_ASAN)
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
    message(STATUS "AddressSanitizer enabled")
  else()
    message(WARNING "AddressSanitizer is only supported with GCC or Clang")
    set(USE_ASAN OFF)
  endif()
endif(USE_ASAN)

file(GLOB all_SRCS
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/*.c"
  )

include(${CMAKE_ROOT}/Modules/CheckCXXSourceCompiles.cmake)
include(${CMAKE_ROOT}/Modules/CheckIncludeFile.cmake)
include(${CMAKE_ROOT}/Modules/CheckSymbolExists.cmake)
include(${CMAKE_ROOT}/Modules/CheckStructHasMember.cmake)

CHECK_INCLUDE_FILE("endian.h" HAVE_ENDIAN_H)
CHECK_INCLUDE_FILE("sys/endian.h" HAVE_SYS_ENDIAN_H)
CHECK_INCLUDE_FILE("sys/epoll.h" HAVE_EPOLL)
CHECK_STRUCT_HAS_MEMBER("struct udphdr" uh_sport "sys/types.h;netinet/udp.h"  HAVE_UDP_UH_PREFIX)

CHECK_SYMBOL_EXISTS(le16toh "endian.h" HAVE_DECL_LE16TOH)
CHECK_SYMBOL_EXISTS(le16toh "sys/endian.h" HAVE_DECL_LE16TOH_BSD)


configure_file("${PROJECT_SOURCE_DIR}/include/config.h.in"
               "${PROJECT_BINARY_DIR}/config.h" )

list(REMOVE_ITEM all_SRCS
  "${PROJECT_SOURCE_DIR}/src/sipp_unittest.cpp")

list(REMOVE_ITEM all_SRCS
  "${PROJECT_SOURCE_DIR}/src/sipp.cpp")

if(NOT USE_PCAP)
  list(REMOVE_ITEM all_SRCS
    "${PROJECT_SOURCE_DIR}/src/prepare_pcap.c"
    "${PROJECT_SOURCE_DIR}/src/send_packets.c")
endif(NOT USE_PCAP)

if(USE_PCAP)
  add_definitions("-DPCAPPLAY")
endif(USE_PCAP)

if(USE_LOCAL_IP_HINTS)
  add_definitions("-DUSE_LOCAL_IP_HINTS")
endif(USE_LOCAL_IP_HINTS)

if(USE_GSL)
  add_definitions("-DHAVE_GSL")
endif(USE_GSL)

if(USE_SCTP)
  add_definitions("-DUSE_SCTP")
endif(USE_SCTP)

# Find all libraries before creating targets
if(PKG_CONFIG_FOUND)
  pkg_search_module(CURSES_LIBRARY ncursesw cursesw ncurses curses)
  if(CURSES_LIBRARY_FOUND)
    set(CURSES_LIBRARY ${CURSES_LIBRARY_LIBRARIES})
  endif()
  pkg_search_module(TINFO_LIBRARY tinfo)
  if(TINFO_LIBRARY_FOUND)
    set(TINFO_LIBRARY ${TINFO_LIBRARY_LIBRARIES})
  endif()
endif()
if(NOT CURSES_LIBRARY)
  find_library(CURSES_LIBRARY NAMES ncursesw cursesw ncurses curses)
endif()
if(NOT TINFO_LIBRARY)
  find_library(TINFO_LIBRARY NAMES tinfo)
endif()
if(NOT CURSES_LIBRARY)
  message(FATAL_ERROR "libcurses / libncurses was not found; please install devel package")
endif()
if(BUILD_STATIC)
  add_definitions("-DNCURSES_STATIC")
endif(BUILD_STATIC)

find_library(RT_LIBRARY NAMES rt)

if(USE_GSL)
  find_library(GSLCBLAS_LIBRARY gslcblas)
endif(USE_GSL)

if(USE_PCAP)
  set(PCAP_LIBRARIES ${PCAP_LIBRARY})
  if(PKG_CONFIG_FOUND)
    pkg_search_module(PCAP libpcap)
    if(BUILD_STATIC AND PCAP_STATIC_LIBRARIES)
      set(PCAP_LIBRARIES ${PCAP_STATIC_LIBRARIES})
      find_library(CAP_LIBRARY cap)
    endif()
  endif()
endif(USE_PCAP)

if(USE_SCTP)
  find_library(SCTP_LIBRARY sctp)
endif()

# add the main executable
add_sipp_target(sipp
  SOURCES "${PROJECT_SOURCE_DIR}/src/sipp.cpp"
)
target_compile_features(sipp PUBLIC cxx_auto_type cxx_range_for)

if(EXISTS ${PROJECT_SOURCE_DIR}/gtest/googletest)
  add_sipp_target(sipp_unittest
    EXCLUDE_FROM_ALL
    SOURCES "${PROJECT_SOURCE_DIR}/src/sipp_unittest.cpp"
            "${PROJECT_SOURCE_DIR}/gtest/googletest/src/gtest-all.cc"
            "${PROJECT_SOURCE_DIR}/gtest/googlemock/src/gmock-all.cc"
    COMPILE_DEFINITIONS "-DGTEST"
    EXTRA_INCLUDES ${PROJECT_SOURCE_DIR}/gtest/googletest
                   ${PROJECT_SOURCE_DIR}/gtest/googlemock
                   ${PROJECT_SOURCE_DIR}/gtest/googletest/include
                   ${PROJECT_SOURCE_DIR}/gtest/googlemock/include
  )
else()
  add_sipp_target(sipp_unittest
    EXCLUDE_FROM_ALL
    SOURCES "${PROJECT_SOURCE_DIR}/src/sipp_unittest.cpp"
  )
endif()

# add version
find_package(Git)
file(WRITE ${PROJECT_SOURCE_DIR}/include/version.cmake
"execute_process(
     COMMAND ${GIT_EXECUTABLE} describe --tags --always --first-parent
     WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
     OUTPUT_VARIABLE VERSION
     OUTPUT_STRIP_TRAILING_WHITESPACE
 )
 configure_file(\${SRC} \${DST} @ONLY)
")
if(EXISTS ${PROJECT_SOURCE_DIR}/.git)
  add_custom_target(
      version
      ${CMAKE_COMMAND} -D SRC=${PROJECT_SOURCE_DIR}/include/version.h.in
      -D DST=${PROJECT_BINARY_DIR}/version.h
      -P ${PROJECT_SOURCE_DIR}/include/version.cmake
  )
  add_dependencies(sipp version)
  add_dependencies(sipp_unittest version)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT TINFO_LIBRARY)
  message(WARNING "libtinfo was not found -- please install package if linking fails")
endif()

if(DEBUG)
  add_definitions("-g -O0")
endif(DEBUG)

if(SIPP_MAX_MSG_SIZE)
  add_definitions("-DSIPP_MAX_MSG_SIZE=${SIPP_MAX_MSG_SIZE}")
endif(SIPP_MAX_MSG_SIZE)

if(CYGWIN)
  add_definitions("-D_GNU_SOURCE")
endif(CYGWIN)

install(TARGETS sipp DESTINATION bin)
