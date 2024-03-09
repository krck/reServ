cmake_minimum_required(VERSION 3.0)

# Set language configuration, compiler and compiler flags
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED true)
set(CMAKE_CXX_COMPILER "/usr/bin/g++")
add_compile_options("-Wall" "-Wpedantic" "-Wextra" "-fexceptions")

# Explicitly set the "-g" debug flags for the different build types
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
string(REPLACE "-g" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

# Define Project name, version and the used language (will set the ${PROJECT_NAME} variable)
project(reServ  VERSION 0.1 
                DESCRIPTION "WebSocket Relay Server"
                LANGUAGES CXX)

# Set the compiled output paths for executables and libraries
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/x64/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/x64/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/x64/bin)

# Find OpenSSL
find_package(OpenSSL REQUIRED)
# If the package OpenSSL has been found, several variables will be set. Most important ones are:
#  OPENSSL_INCLUDE_DIR - the OpenSSL include directory
#  OPENSSL_LIBRARIES - Link these to use OpenSSL

# Specify the directories to be added to the compiler include paths
include_directories(${OPENSSL_INCLUDE_DIR})
    #include_directories(${CMAKE_SOURCE_DIR}/lib/openssl/include)

# Specify the directories to be added to the linker search paths for precompiled/pre-build libraries
    #link_directories(${CMAKE_SOURCE_DIR}/lib/openssl)

# Specify the directories with their own build-systems (the subdirectory must contain a CMakeLists.txt file)
add_subdirectory(${CMAKE_SOURCE_DIR}/lib/catch2)

# Add the executable files (all .cpp files that need to be compiled and linked)
file(GLOB_RECURSE SOURCES src/*.cpp)
add_executable(${PROJECT_NAME} ${SOURCES})
file(GLOB_RECURSE TEST_SOURCES test/*.cpp)
add_executable(tests ${TEST_SOURCES})

# Now that the target is defined, link the libraries to it
target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
target_link_libraries(tests PRIVATE Catch2::Catch2WithMain)
