cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(arch_mips CXX C)
set(CMAKE_CXX_STANDARD 20)
set(HEADLESS 1)

# Locate Qt installation for linking
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

find_path(
    BN_API_PATH
    NAMES binaryninjaapi.h
    # List of paths to search for the clone of the api
    HINTS subprojects/binaryninja-api $ENV{BN_API_PATH}
    REQUIRED
)

# Build the binary ninja api
set(BN_API_BUILD_EXAMPLES OFF)
add_subdirectory(${BN_API_PATH} api)

set(SOURCES arch_mips.cpp
            il.cpp 
            mips/mips.c
)

add_library(arch_mips SHARED ${SOURCES})

target_include_directories(arch_mips
	PRIVATE ${PROJECT_SOURCE_DIR}
	PRIVATE ${PROJECT_SOURCE_DIR}/mips)

target_link_libraries(arch_mips binaryninjaapi)

set_target_properties(arch_mips PROPERTIES
    CXX_STANDARD 20
	CXX_VISIBILITY_PRESET hidden
	CXX_STANDARD_REQUIRED ON
	C_STANDARD 99
	C_STANDARD_REQUIRED ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
	POSITION_INDEPENDENT_CODE ON)
