cmake_minimum_required(VERSION 3.21)
project(ygg-miner VERSION 0.2.0 LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(YGG_MINER_NATIVE "Optimize for the host CPU (-march=native)" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(OpenMP REQUIRED COMPONENTS C)

add_executable(ygg-miner main.c)
set_target_properties(ygg-miner PROPERTIES
	C_STANDARD 23
	C_STANDARD_REQUIRED ON
	C_EXTENSIONS ON)
target_compile_options(ygg-miner PRIVATE -Wall -Wextra -Wpedantic)
if(YGG_MINER_NATIVE)
	target_compile_options(ygg-miner PRIVATE -march=native)
endif()
target_link_libraries(ygg-miner PRIVATE PkgConfig::SODIUM OpenMP::OpenMP_C m)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported LANGUAGES C)
if(ipo_supported)
	set_target_properties(ygg-miner PROPERTIES INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
endif()

install(TARGETS ygg-miner)
