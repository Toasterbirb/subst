cmake_minimum_required(VERSION 3.12)
enable_language(C ASM_NASM)

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
set(CMAKE_ASM_FLAGS "-felf64 -O0")
set(TEST_BINS
	t_return
	t_branch_inv
)

add_executable(t_return ./tests/return.asm)
add_executable(t_branch_inv ./tests/branch_inv.asm)

FILE(GLOB TEST_FILES ./tests/*.sbst ./tests/*.sh)
file(COPY ${TEST_FILES} DESTINATION ./)
add_custom_target(test DEPENDS ${TEST_BINS} ${PROJECT_NAME} COMMAND ./test.sh)

install(TARGETS ${PROJECT_NAME})
