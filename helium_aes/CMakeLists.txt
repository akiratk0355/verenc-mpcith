cmake_minimum_required (VERSION 3.12)
project (helium_signatures C CXX)

cmake_policy(SET CMP0069 NEW) # using CheckIPOSupported

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17) 

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)


if( ipo_supported )
    message(STATUS "IPO / LTO enabled")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION True)
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

set(BUILD_TESTS OFF CACHE BOOL "Build unit tests.")
set(HASH "keccak" CACHE STRING "Choose which Hash function to use. Supported values: \"keccak\", \"blake3\"")

add_compile_options("-Wall")
add_compile_options("-Wextra")
add_compile_options("-march=native")

# Helpful options during debugging; makes link times much slower though and benchmarks become innacurate
#add_compile_options("-fsanitize=address")
#add_link_options("-fsanitize=address")

add_subdirectory(field)

set(HELIUM_SRCS
  aes.cpp
  instances.cpp
  randomness.c
  signature.cpp
  tape.cpp
  tree.cpp
  pke.c
  )

add_custom_target(
    kyber_build ALL
    COMMAND make -j8
    BYPRODUCTS ../kyber-avx2/libkyber512_avx2.a
    WORKING_DIRECTORY ../kyber-avx2
 )

add_library(kyber_lib STATIC IMPORTED)
set_property(TARGET kyber_lib PROPERTY IMPORTED_LOCATION "../kyber-avx2/libkyber512_avx2.a")

add_library(helium_static STATIC ${HELIUM_SRCS})
target_link_libraries(helium_static PUBLIC field ${HASH} kyber_lib) 

if(HASH STREQUAL "blake3")
  add_subdirectory(blake3)
  target_compile_definitions(helium_static PRIVATE HASH_BLAKE3)
elseif(HASH STREQUAL "keccak")
  add_subdirectory(keccak)
  target_compile_definitions(helium_static PRIVATE HASH_KECCAK)
else()
message(FATAL_ERROR "need to choose a valid hash")
endif()

#also includes the non-transposed matrices, can be useful for debugging
#target_compile_definitions(helium_static PUBLIC INCLUDE_STANDARD_MATRICES)

add_library(bench_utils STATIC tools/bench_utils.cpp tools/bench_timing.cpp)
add_executable(bench tools/bench.cpp)
add_executable(bench_free tools/bench_free.cpp)
target_link_libraries(bench helium_static bench_utils kyber_lib)
target_link_libraries(bench_free helium_static bench_utils kyber_lib)

if(BUILD_TESTS)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
Include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.7)

FetchContent_MakeAvailable(Catch2)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${Catch2_SOURCE_DIR}/contrib/")


include(CTest)
include(Catch)

function(add_test test_name)
  add_executable(${test_name} tests/${test_name}.cpp)
  target_link_libraries(${test_name} Catch2::Catch2 helium_static)
  catch_discover_tests(${test_name})
endfunction()

#add_test(helium_test)
add_test(signature_test)
add_test(tree_test)
add_test(aes_test)
add_test(pke_test)
endif()