# See https://docs.binary.ninja/dev/plugins.html?h=api_#project-setup
cmake_minimum_required(VERSION 3.15 FATAL_ERROR)
project(poke_plugin CXX C)
set(CMAKE_CXX_STANDARD 20)
set(HEADLESS 0)

# Locate Qt installation for linking
find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)

find_path(
    BN_API_PATH
    NAMES binaryninjaapi.h
    # List of paths to search for the clone of the api
    HINTS subprojects/binaryninjaapi $ENV{BN_API_PATH}
    REQUIRED
)

set(BN_API_BUILD_EXAMPLES OFF)
add_subdirectory(${BN_API_PATH} api)

set(SOURCES src/poke_plugin.cpp)

add_library(poke_plugin SHARED $(SOURCES))
target_link_libraries(poke_plugin PUBLIC binaryninjaapi binaryninjaui Qt6::Core Qt6::Gui Qt6::Widgets)
