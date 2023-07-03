#
# Create CMake DEBUG/RELEASE Configuration in the "debug/release" folder:     
#   > cmake -DCMAKE_BUILD_TYPE=Debug -B build/debug
#   > cmake -DCMAKE_BUILD_TYPE=Release -B build/release
#
# Execute CMake configuration to run the build:         
#   > cmake --build build/debug
#   > cmake --build build/release
#

cmake_minimum_required(VERSION 3.0)

# Set language configuration, compiler and compiler flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set(CMAKE_CXX_COMPILER "/usr/bin/clang++")
add_compile_options("-Wall" "-Wpedantic" "-Wextra" "-fexceptions")

# Define Project name, version and the used language (will set the ${PROJECT_NAME} variable)
project(reServ  VERSION 0.1 
                DESCRIPTION "WebSocket Relay Server"
                LANGUAGES CXX)
 
# Set the compiled output paths for executables and libraries
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/x64/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/x64/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/x64/bin)

# Add the executable files (all .cpp files that need to be compiled and linked)
file(GLOB_RECURSE SOURCES src/*.cpp)
add_executable(${PROJECT_NAME} ${SOURCES})
