cmake_minimum_required(VERSION 2.8)

# set the project name
project(SIPp)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

if(EXISTS ./gmock/CMakeLists.txt)
  add_subdirectory(gmock EXCLUDE_FROM_ALL)
endif()

include_directories(
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/gtest/include
  ${PROJECT_SOURCE_DIR}/gmock/include
  ${PROJECT_BINARY_DIR}
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

if(USE_SSL)
  add_definitions("-DUSE_TLS -DUSE_OPENSSL")
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

add_definitions("-DRTP_STREAM")

# add the executable
link_directories("/usr/local/lib")
add_executable(sipp ${all_SRCS} "${PROJECT_SOURCE_DIR}/src/sipp.cpp")
add_executable(sipp_unittest EXCLUDE_FROM_ALL ${all_SRCS} "${PROJECT_SOURCE_DIR}/src/sipp_unittest.cpp")
target_compile_definitions(sipp_unittest PUBLIC "-DGTEST")

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
add_custom_target(
    version
    ${CMAKE_COMMAND} -D SRC=${PROJECT_SOURCE_DIR}/include/version.h.in
                     -D DST=${PROJECT_BINARY_DIR}/version.h
                     -P ${PROJECT_SOURCE_DIR}/include/version.cmake
)
add_dependencies(sipp version)
add_dependencies(sipp_unittest version)

if(BUILD_STATIC)
  set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
endif(BUILD_STATIC)

find_library(CURSES_LIBRARY NAMES ncursesw cursesw ncurses curses)
if(CURSES_LIBRARY)
  target_link_libraries(sipp dl ${CURSES_LIBRARY} pthread)
  target_link_libraries(sipp_unittest dl ${CURSES_LIBRARY} pthread gtest gmock)
else()
  message(FATAL_ERROR "libcurses / libncurses was not found; please install devel package")
endif()

find_library(RT_LIBRARY NAMES rt)
if(RT_LIBRARY)
  target_link_libraries(sipp ${RT_LIBRARY})
  target_link_libraries(sipp_unittest ${RT_LIBRARY})
endif()

if(USE_GSL AND GSL_LIBRARY)
  target_link_libraries(sipp gsl gslcblas)
  target_link_libraries(sipp_unittest gsl gslcblas)
endif(USE_GSL AND GSL_LIBRARY)

if(USE_SSL)
  target_link_libraries(sipp crypto ssl)
  target_link_libraries(sipp_unittest crypto ssl)
endif(USE_SSL)

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
