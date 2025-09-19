cmake_minimum_required(VERSION 3.16)
project(CDA VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(Threads REQUIRED)

# Include directories
include_directories(include)

# Source files
file(GLOB_RECURSE AGENT_SOURCES "src/agent/*.cpp")
file(GLOB_RECURSE BACKEND_SOURCES "src/backend/*.cpp")
file(GLOB_RECURSE CONTROL_SOURCES "src/control_center/*.cpp")

# Create executable
add_executable(cda_agent ${AGENT_SOURCES} ${BACKEND_SOURCES} ${CONTROL_SOURCES})

# Link libraries
target_link_libraries(aica_agent Threads::Threads crypto pcap curl archive)

# Installation targets
install(TARGETS cda_agent
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Install header files
install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Install configuration files
install(DIRECTORY config/
    DESTINATION etc/cda
    OPTIONAL
)

# Enable testing
enable_testing()
