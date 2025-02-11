cmake_minimum_required(VERSION 3.10)

# Set vcpkg toolchain file before project() command
set(CMAKE_TOOLCHAIN_FILE "C:/Program Files/vcpkg/scripts/buildsystems/vcpkg.cmake"
    CACHE STRING "")

project(KRXDNSChecker)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find CURL package
find_package(CURL CONFIG REQUIRED)

# Add executable with source file in src directory
add_executable(KRXDNSChecker src/main.cpp)

# Copy dns_servers.txt to output directory
configure_file(${CMAKE_SOURCE_DIR}/dns_servers.txt ${CMAKE_BINARY_DIR}/dns_servers.txt COPYONLY)

# Windows-specific configuration
if(WIN32)
    # Add Windows-specific libraries
    target_link_libraries(KRXDNSChecker
        winhttp
        dnsapi
        iphlpapi
        ws2_32
        CURL::libcurl
    )
    
    # Request administrator privileges in the manifest
    if(MSVC)
        set_target_properties(KRXDNSChecker PROPERTIES
            WIN32_EXECUTABLE FALSE
            LINK_FLAGS "/manifestuac:\"level='requireAdministrator' uiAccess='false'\""
        )
    endif()
endif() 