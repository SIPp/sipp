cmake_minimum_required(VERSION 3.4)

# set the project name
project(SIPp)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS False)
# specify the C++ standard on older CMake (<3.8)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")

add_executable(calc_ck calc_ck.cpp ../src/milenage.c ../src/md5.c ../src/rijndael.c ../src/strings.cpp)
target_include_directories(calc_ck PRIVATE ../include)