cmake_minimum_required(VERSION 3.20)

project(SRUN VERSION 0.0.0 LANGUAGES CXX)

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

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)
link_libraries(${OPENSSL_LIBRARIES} nlohmann_json::nlohmann_json)

include_directories(${PROJECT_SOURCE_DIR}/include)

add_subdirectory(src)
