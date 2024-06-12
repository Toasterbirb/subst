cmake_minimum_required(VERSION 3.12)

project(subst)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
endif(CCACHE_FOUND)

# Compile vendored source code
add_subdirectory(vendor/clipp)
include_directories(vendor/clipp/include)

include_directories(./include)
file(GLOB SRC_FILES ./src/*.cpp)
add_executable(${PROJECT_NAME} ${SRC_FILES})
target_link_libraries(${PROJECT_NAME} clipp capstone)

# Build tests
add_executable(pass_check ./tests/pass_check.c)
target_compile_options(pass_check PUBLIC -O0)
set(TEST_FILES ./tests/test.sh ./tests/pass_check.sbt)
file(COPY ${TEST_FILES} DESTINATION ./)
add_custom_target(test DEPENDS pass_check ${PROJECT_NAME} COMMAND ./test.sh)

install(TARGETS ${PROJECT_NAME})
