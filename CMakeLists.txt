cmake_minimum_required(VERSION 3.24.2)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

set(ANDROID_STL c++_static)
set(ANDROID_ABI armeabi-v7a)

project(hannei)

add_library(hannei SHARED src/hannei.cpp)

include_directories(hannei PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/Dobby/include)

add_subdirectory(Dobby)
target_link_libraries(hannei dobby)

install(TARGETS hannei LIBRARY DESTINATION ${CMAKE_CURRENT_SOURCE_DIR})
