cmake_minimum_required(VERSION 3.1)

# set the project name
project(SIPp)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS False)
# specify the C++ standard on older CMake (<3.8)
set(CMAKE_REQUIRED_FLAGS "-std=c++11")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -pedantic -Wno-error=format-truncation -Wno-error=deprecated-declarations")

# Include binary dir first, where we add generated config.h and
# version.h. If nothing is found there (release tar) use the version.h
# from the source.
include_directories(
  ${PROJECT_BINARY_DIR}
  ${PROJECT_SOURCE_DIR}/include
  "/usr/local/include")

option(BUILD_STATIC "Build a statically-linked binary" OFF)
option(USE_SSL "Build with SIPS support" OFF)
option(USE_SCTP "Build with SCTP support" OFF)
option(USE_PCAP "Build with PCAP playback support" OFF)
option(USE_GSL "Build with improved statistical support" ON)

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

if(NOT USE_SSL)
  list(REMOVE_ITEM all_SRCS
    "${PROJECT_SOURCE_DIR}/src/sslsocket.cpp")
endif(NOT USE_SSL)

if(NOT USE_PCAP)
  list(REMOVE_ITEM all_SRCS
    "${PROJECT_SOURCE_DIR}/src/prepare_pcap.c")
  list(REMOVE_ITEM all_SRCS
    "${PROJECT_SOURCE_DIR}/src/send_packets.c")
endif(NOT USE_PCAP)

find_package(PkgConfig QUIET)  # import pkg_check_modules() and friends
if(USE_SSL)
  if(PKG_CONFIG_FOUND)
    pkg_search_module(SSL openssl>=0.9.8 wolfssl>=3.15.0)
  endif()
  if(SSL_FOUND)
    if("${SSL_LIBRARIES}" MATCHES "wolfssl")
      set(WOLFSSL_FOUND True)
    else()
      set(OPENSSL_FOUND True)
    endif()
  else()
    find_library(OPENSSL_SSL_LIBRARY NAMES ssl)
    find_library(OPENSSL_CRYPTO_LIBRARY NAMES crypto)
    if(OPENSSL_SSL_LIBRARY AND OPENSSL_CRYPTO_LIBRARY)
      set(SSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
      set(OPENSSL_FOUND True)
    else()
      find_library(WOLFSSL_LIBRARY NAMES wolfssl)
      if(WOLFSSL_LIBRARY)
        set(SSL_LIBRARIES ${WOLFSSL_LIBRARY})
        set(WOLFSSL_FOUND True)
      endif()
    endif()
    if(NOT OPENSSL_FOUND AND NOT WOLFSSL_FOUND)
      message(FATAL_ERROR "Neither OpenSSL nor WolfSSL was found; please install a devel package")
    endif()
  endif()
  if(OPENSSL_FOUND)
    add_definitions("-DUSE_TLS" "-DUSE_OPENSSL")
  elseif(WOLFSSL_FOUND)
    add_definitions("-DUSE_TLS" "-DUSE_WOLFSSL" "-DOPENSSL_ALL")
  endif()
endif()

if(USE_PCAP)
  add_definitions("-DPCAPPLAY")
endif(USE_PCAP)

if(USE_GSL)
  find_library(GSL_LIBRARY gsl)
  if(GSL_LIBRARY)
    add_definitions("-DHAVE_GSL")
  endif(GSL_LIBRARY)
endif(USE_GSL)

if(USE_SCTP)
  add_definitions("-DUSE_SCTP")
endif(USE_SCTP)

# add the executable
link_directories("/usr/local/lib")
add_executable(sipp ${all_SRCS} "${PROJECT_SOURCE_DIR}/src/sipp.cpp")
target_compile_features(sipp PUBLIC cxx_auto_type cxx_range_for)
add_executable(sipp_unittest EXCLUDE_FROM_ALL
  ${all_SRCS}
  "${PROJECT_SOURCE_DIR}/src/sipp_unittest.cpp"
  "${PROJECT_SOURCE_DIR}/gtest/googletest/src/gtest-all.cc"
  "${PROJECT_SOURCE_DIR}/gtest/googlemock/src/gmock-all.cc"
)
target_compile_features(sipp_unittest PUBLIC cxx_auto_type cxx_range_for)
target_compile_definitions(sipp_unittest PUBLIC "-DGTEST")
target_include_directories(sipp_unittest SYSTEM PUBLIC
  ${PROJECT_SOURCE_DIR}/gtest/googletest
  ${PROJECT_SOURCE_DIR}/gtest/googlemock
  ${PROJECT_SOURCE_DIR}/gtest/googletest/include
  ${PROJECT_SOURCE_DIR}/gtest/googlemock/include
)

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

if(BUILD_STATIC)
  set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
endif(BUILD_STATIC)

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
if(CURSES_LIBRARY)
  target_link_libraries(sipp dl ${CURSES_LIBRARY} pthread)
  target_link_libraries(sipp_unittest dl ${CURSES_LIBRARY} pthread)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(TINFO_LIBRARY)
      target_link_libraries(sipp ${TINFO_LIBRARY})
      target_link_libraries(sipp_unittest ${TINFO_LIBRARY})
    else()
      if(BUILD_STATIC)
        message(WARNING "libtinfo.a was not found -- please install package if linking fails")
      else()
        message(FATAL_ERROR "libtinfo.so was not found -- please install package")
      endif(BUILD_STATIC)
    endif(TINFO_LIBRARY)
  endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  if(CURSES_LIBRARY_INCLUDE_DIRS OR TINFO_LIBRARY_INCLUDE_DIRS)
    target_include_directories(sipp SYSTEM PUBLIC ${CURSES_LIBRARY_INCLUDE_DIRS} ${TINFO_LIBRARY_INCLUDE_DIRS})
    target_include_directories(sipp_unittest SYSTEM PUBLIC ${CURSES_LIBRARY_INCLUDE_DIRS} ${TINFO_LIBRARY_INCLUDE_DIRS})
  endif()
else()
  message(FATAL_ERROR "libcurses / libncurses was not found; please install devel package")
endif()

find_library(RT_LIBRARY NAMES rt)
if(RT_LIBRARY)
  target_link_libraries(sipp ${RT_LIBRARY})
  target_link_libraries(sipp_unittest ${RT_LIBRARY})
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

if(USE_GSL AND GSL_LIBRARY)
  target_link_libraries(sipp gsl gslcblas)
  target_link_libraries(sipp_unittest gsl gslcblas)
endif(USE_GSL AND GSL_LIBRARY)

if(USE_SSL AND SSL_LIBRARIES)
  target_link_libraries(sipp ${SSL_LIBRARIES})
  target_link_libraries(sipp_unittest ${SSL_LIBRARIES})
  if(SSL_INCLUDE_DIRS)
    target_include_directories(sipp SYSTEM PUBLIC ${SSL_INCLUDE_DIRS})
    target_include_directories(sipp_unittest SYSTEM PUBLIC ${SSL_INCLUDE_DIRS})
  endif(SSL_INCLUDE_DIRS)
endif(USE_SSL AND SSL_LIBRARIES)

if(USE_PCAP)
  target_link_libraries(sipp pcap)
  target_link_libraries(sipp_unittest pcap)
endif(USE_PCAP)

if(USE_SCTP)
  find_library(SCTP_LIBRARY sctp)
  if(SCTP_LIBRARY)
    target_link_libraries(sipp ${SCTP_LIBRARY})
    target_link_libraries(sipp_unittest ${SCTP_LIBRARY})
  endif()
endif()

install(TARGETS sipp DESTINATION bin)
