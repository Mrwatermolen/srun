cmake_minimum_required(VERSION 3.20)

project(SRUN VERSION 0.0.1 LANGUAGES CXX)

set(SRUN_MAIN_PROJECT OFF)
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(SRUN_MAIN_PROJECT ON)
endif()

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

option(SRUN_SSL_ENABLED "Enable SSL support" OFF)

find_package(nlohmann_json REQUIRED)
find_package(ASIO)

set(SRUN_EXTERNAL_LIB nlohmann_json::nlohmann_json)

if(ASIO_FOUND)
    set(SRUN_EXTERNAL_LIB ${SRUN_EXTERNAL_LIB} asio::asio)
endif()

if(SRUN_SSL_ENABLED)
    message(STATUS "SSL support enabled")
    find_package(OpenSSL REQUIRED)
    add_definitions(-DSRUN_SSL_ENABLED)
    set(SRUN_EXTERNAL_LIB ${SRUN_EXTERNAL_LIB} OpenSSL::SSL OpenSSL::Crypto)
endif()

add_subdirectory(third_party)

set(SRUN_EXTERNAL_LIB ${SRUN_EXTERNAL_LIB} stbrumme_hash_library)

link_libraries(${SRUN_EXTERNAL_LIB})

include_directories(${PROJECT_SOURCE_DIR}/include ${PROJECT_SOURCE_DIR}/src/include)

add_subdirectory(src)
