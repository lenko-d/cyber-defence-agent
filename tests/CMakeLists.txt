# CMake configuration for CDA test suite
cmake_minimum_required(VERSION 3.16)
project(CDA_TESTS)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable testing
enable_testing()

# Find required packages
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/agent
    ${GTEST_INCLUDE_DIRS}
)

# Link directories
link_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/../build
)

# Test executables
add_executable(test_agent test_agent.cpp ../src/agent/Agent.cpp ../src/agent/Monitor.cpp ../src/agent/Detector.cpp ../src/agent/PacketInspector.cpp ../src/agent/UpdateManager.cpp)
add_executable(test_packet_inspector test_packet_inspector.cpp ../src/agent/PacketInspector.cpp)
add_executable(test_detector test_detector.cpp ../src/agent/Detector.cpp ../src/agent/UpdateManager.cpp)

# Link libraries
target_link_libraries(test_agent
    GTest::gtest GTest::gtest_main
    ${CMAKE_THREAD_LIBS_INIT}
    crypto pcap curl archive
)

target_link_libraries(test_packet_inspector
    GTest::gtest GTest::gtest_main
    ${CMAKE_THREAD_LIBS_INIT}
    pcap crypto curl archive
)

target_link_libraries(test_detector
    GTest::gtest GTest::gtest_main
    ${CMAKE_THREAD_LIBS_INIT}
    crypto curl archive
)

# Add tests to CTest
add_test(NAME AgentTests COMMAND test_agent)
add_test(NAME PacketInspectorTests COMMAND test_packet_inspector)
add_test(NAME DetectorTests COMMAND test_detector)

# Set test properties
set_tests_properties(AgentTests PROPERTIES
    TIMEOUT 60
    LABELS "unit"
)

set_tests_properties(PacketInspectorTests PROPERTIES
    TIMEOUT 60
    LABELS "unit;network"
)

set_tests_properties(DetectorTests PROPERTIES
    TIMEOUT 60
    LABELS "unit;detection"
)

# Custom target to run all tests
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS test_agent test_packet_inspector test_detector
    COMMENT "Running all CDA tests"
)

# Custom target for test coverage (if gcov is available)
find_program(GCOV_PATH gcov)
if(GCOV_PATH)
    add_custom_target(coverage
        COMMAND ${CMAKE_CTEST_COMMAND}
        COMMAND gcovr -r ${CMAKE_SOURCE_DIR} --html --html-details -o coverage.html
        DEPENDS run_tests
        COMMENT "Generating test coverage report"
    )
endif()

# Installation rules for tests
install(TARGETS test_agent test_packet_inspector test_detector
    RUNTIME DESTINATION tests
)

# Test data directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test_data)

# Copy test data files if they exist
file(GLOB TEST_DATA_FILES "${CMAKE_CURRENT_SOURCE_DIR}/test_data/*")
if(TEST_DATA_FILES)
    file(COPY ${TEST_DATA_FILES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/test_data)
endif()

# Generate test summary
add_custom_command(
    TARGET run_tests POST_BUILD
    COMMAND echo "Test execution completed"
    COMMAND date
    VERBATIM
)

# Compiler warnings and flags
if(MSVC)
    # MSVC specific flags
    target_compile_options(test_agent PRIVATE /W4 /WX)
    target_compile_options(test_packet_inspector PRIVATE /W4 /WX)
    target_compile_options(test_detector PRIVATE /W4 /WX)
else()
    # GCC/Clang flags
    target_compile_options(test_agent PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(test_packet_inspector PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(test_detector PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Debug build configuration
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(test_agent PRIVATE DEBUG_BUILD)
    target_compile_definitions(test_packet_inspector PRIVATE DEBUG_BUILD)
    target_compile_definitions(test_detector PRIVATE DEBUG_BUILD)
endif()

# Address sanitizer for memory error detection
option(ENABLE_SANITIZER "Enable address sanitizer" OFF)
if(ENABLE_SANITIZER)
    target_compile_options(test_agent PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(test_agent PRIVATE -fsanitize=address)

    target_compile_options(test_packet_inspector PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(test_packet_inspector PRIVATE -fsanitize=address)

    target_compile_options(test_detector PRIVATE -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(test_detector PRIVATE -fsanitize=address)
endif()

# Thread sanitizer for race condition detection
option(ENABLE_THREAD_SANITIZER "Enable thread sanitizer" OFF)
if(ENABLE_THREAD_SANITIZER)
    target_compile_options(test_agent PRIVATE -fsanitize=thread)
    target_link_options(test_agent PRIVATE -fsanitize=thread)

    target_compile_options(test_packet_inspector PRIVATE -fsanitize=thread)
    target_link_options(test_packet_inspector PRIVATE -fsanitize=thread)

    target_compile_options(test_detector PRIVATE -fsanitize=thread)
    target_link_options(test_detector PRIVATE -fsanitize=thread)
endif()

# Valgrind integration for memory checking
find_program(VALGRIND_PATH valgrind)
if(VALGRIND_PATH)
    add_custom_target(memcheck
        COMMAND ${VALGRIND_PATH} --tool=memcheck --leak-check=full --show-leak-kinds=all
                --track-origins=yes --verbose --log-file=valgrind.log
                $<TARGET_FILE:test_agent>
        COMMAND ${VALGRIND_PATH} --tool=memcheck --leak-check=full --show-leak-kinds=all
                --track-origins=yes --verbose --log-file=valgrind-packet.log
                $<TARGET_FILE:test_packet_inspector>
        COMMAND ${VALGRIND_PATH} --tool=memcheck --leak-check=full --show-leak-kinds=all
                --track-origins=yes --verbose --log-file=valgrind-detector.log
                $<TARGET_FILE:test_detector>
        DEPENDS test_agent test_packet_inspector test_detector
        COMMENT "Running memory checks with Valgrind"
    )
endif()

# Performance testing
add_custom_target(perf_test
    COMMAND perf record -g $<TARGET_FILE:test_agent>
    COMMAND perf report --stdio > perf_report.txt
    DEPENDS test_agent
    COMMENT "Running performance analysis"
)

# Benchmarking
find_package(benchmark QUIET)
if(benchmark_FOUND)
    add_executable(benchmark_agent benchmark_agent.cpp)
    target_link_libraries(benchmark_agent benchmark::benchmark ${CMAKE_THREAD_LIBS_INIT})
    add_custom_target(benchmark
        COMMAND $<TARGET_FILE:benchmark_agent>
        DEPENDS benchmark_agent
        COMMENT "Running performance benchmarks"
    )
endif()

# Test configuration file
# configure_file(
#     ${CMAKE_CURRENT_SOURCE_DIR}/test_config.ini.in
#     ${CMAKE_CURRENT_BINARY_DIR}/test_config.ini
#     @ONLY
# )

# Environment setup for tests
set(TEST_ENVIRONMENT
    "GTEST_OUTPUT=xml:test_results.xml"
    "ASAN_OPTIONS=detect_leaks=1"
    "TSAN_OPTIONS=second_deadlock_stack=1"
)

set_tests_properties(AgentTests PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")
set_tests_properties(PacketInspectorTests PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")
set_tests_properties(DetectorTests PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

# Test labels for selective running
set_property(TEST AgentTests PROPERTY LABELS "core;unit")
set_property(TEST PacketInspectorTests PROPERTY LABELS "network;unit;integration")
set_property(TEST DetectorTests PROPERTY LABELS "detection;unit")

# Fixtures for test setup/cleanup
add_test(NAME SetupTestEnvironment COMMAND ${CMAKE_COMMAND} -E make_directory test_output)
add_test(NAME CleanupTestEnvironment COMMAND ${CMAKE_COMMAND} -E remove_directory test_output)

set_tests_properties(SetupTestEnvironment PROPERTIES FIXTURES_SETUP TestEnvironment)
set_tests_properties(CleanupTestEnvironment PROPERTIES FIXTURES_CLEANUP TestEnvironment)

set_tests_properties(AgentTests PROPERTIES FIXTURES_REQUIRED TestEnvironment)
set_tests_properties(PacketInspectorTests PROPERTIES FIXTURES_REQUIRED TestEnvironment)
set_tests_properties(DetectorTests PROPERTIES FIXTURES_REQUIRED TestEnvironment)

# Summary
message(STATUS "CDA Test Suite Configuration:")
message(STATUS "  - Unit Tests: ${CMAKE_CURRENT_SOURCE_DIR}")
message(STATUS "  - Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  - Google Test: ${GTEST_FOUND}")
message(STATUS "  - Address Sanitizer: ${ENABLE_SANITIZER}")
message(STATUS "  - Thread Sanitizer: ${ENABLE_THREAD_SANITIZER}")
message(STATUS "  - Valgrind: ${VALGRIND_PATH}")
message(STATUS "  - Benchmark: ${benchmark_FOUND}")
