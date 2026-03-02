cmake_minimum_required(VERSION 3.16)
project(secret_com VERSION 1.0.0 LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)

# Warnings (Google style)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(
    -Wall -Wextra -Wpedantic -Wshadow
    -Wno-unused-parameter
  )
elseif(MSVC)
  add_compile_options(/W4 /permissive-)
endif()

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
option(SECRETCOM_BUILD_EXAMPLES "Build example programs"     ON)
option(SECRETCOM_BUILD_TESTS    "Build unit tests"           OFF)
option(SECRETCOM_USE_MBEDTLS    "Link against mbedTLS"       ON)
option(SECRETCOM_SERIAL_SUPPORT "Include serial transport"   ON)
option(SECRETCOM_TCP_SUPPORT    "Include TCP transport"      ON)

# ---------------------------------------------------------------------------
# mbedTLS via CMake FetchContent (if not already installed)
# ---------------------------------------------------------------------------
if(SECRETCOM_USE_MBEDTLS)
  include(FetchContent)
  FetchContent_Declare(
    mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG        v3.6.0
    GIT_SHALLOW    TRUE
  )
  set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
  set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(mbedtls)
endif()

# ---------------------------------------------------------------------------
# Library target: secret_com
# ---------------------------------------------------------------------------
set(SECRETCOM_SOURCES
  src/auth_client.cc
  src/auth_server.cc
  src/protocol/message_framer.cc
)

if(SECRETCOM_SERIAL_SUPPORT)
  list(APPEND SECRETCOM_SOURCES src/transport/serial_transport.cc)
endif()

if(SECRETCOM_TCP_SUPPORT)
  list(APPEND SECRETCOM_SOURCES src/transport/tcp_transport.cc)
endif()

if(SECRETCOM_USE_MBEDTLS)
  list(APPEND SECRETCOM_SOURCES src/crypto/mbedtls_provider.cc)
endif()

add_library(secret_com ${SECRETCOM_SOURCES})
add_library(secret_com::secret_com ALIAS secret_com)

target_include_directories(secret_com
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

if(SECRETCOM_USE_MBEDTLS)
  target_link_libraries(secret_com PUBLIC mbedtls mbedx509 mbedcrypto)
  target_compile_definitions(secret_com PRIVATE SECRETCOM_USE_MBEDTLS=1)
endif()

if(WIN32)
  target_link_libraries(secret_com PRIVATE ws2_32)
endif()

# Threads
find_package(Threads REQUIRED)
target_link_libraries(secret_com PUBLIC Threads::Threads)

# ---------------------------------------------------------------------------
# C API wrapper target (thin shim; compiled separately for a stable ABI)
# ---------------------------------------------------------------------------
add_library(secret_com_c src/secret_com_c_api.cc)
add_library(secret_com::c_api ALIAS secret_com_c)
target_link_libraries(secret_com_c PUBLIC secret_com)
target_include_directories(secret_com_c
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
if(SECRETCOM_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(SECRETCOM_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Install rules
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS secret_com secret_com_c
  EXPORT  SecretComTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT SecretComTargets
  FILE      SecretComTargets.cmake
  NAMESPACE secret_com::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/secret_com
)
