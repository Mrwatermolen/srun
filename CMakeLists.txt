cmake_minimum_required(VERSION 3.20)

project(SRUN VERSION 0.0.2 LANGUAGES CXX)

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

set(SRUN_EXTERNAL_LIB nlohmann_json::nlohmann_json)

if(ASIO_FOUND)
    set(SRUN_EXTERNAL_LIB ${SRUN_EXTERNAL_LIB} asio::asio)
endif()

set(SRUN_SSL_ENABLED ON)

if(SRUN_SSL_ENABLED)
    message(STATUS "SSL support enabled")
    find_package(OpenSSL REQUIRED)
    add_definitions(-DSRUN_SSL_ENABLED)
    set(SRUN_EXTERNAL_LIB ${SRUN_EXTERNAL_LIB} OpenSSL::SSL OpenSSL::Crypto)
endif()

add_subdirectory(third_party)
set(SRUN_PUBLIC_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/include)
link_libraries(${SRUN_EXTERNAL_LIB})
include_directories(${SRUN_PUBLIC_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/third_party/hash_library/include)

add_subdirectory(src)

option(SRUN_ENABLED_INSTALL_LIB "Enable installation of library" OFF)
option(SRUN_ENABLED_INSTALL_BIN "Enable installation of binary" ON)
set(SRUN_INSTALL_TARGETS "")

if(SRUN_ENABLED_INSTALL_LIB)
    message(STATUS "Enabling installation of library")
    set(SRUN_INSTALL_TARGETS ${SRUN_INSTALL_TARGETS} srun)
endif()

if(SRUN_ENABLED_INSTALL_BIN)
    message(STATUS "Enabling installation of binary")
    set(SRUN_INSTALL_TARGETS ${SRUN_INSTALL_TARGETS} srun_cli)
endif()

install(TARGETS ${SRUN_INSTALL_TARGETS}
    EXPORT srun-targets
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

include(CMakePackageConfigHelpers)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/srun-config.cmake
    INSTALL_DESTINATION lib/cmake/srun
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/srun-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

export(EXPORT srun-targets
    FILE ${CMAKE_BINARY_DIR}/srun-targets.cmake
    NAMESPACE srun::
)

if(SRUN_ENABLED_INSTALL_LIB)

    install(EXPORT srun-targets
        FILE srun-targets.cmake
        NAMESPACE srun::
        DESTINATION lib/cmake/srun
    )

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/srun-config.cmake ${CMAKE_CURRENT_BINARY_DIR}/srun-config-version.cmake
        DESTINATION lib/cmake/srun
    )

    install(DIRECTORY ${SRUN_PUBLIC_INCLUDE_DIRS}/srun
        DESTINATION include
    )
        
endif()
