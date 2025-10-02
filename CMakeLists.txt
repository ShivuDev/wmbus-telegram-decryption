cmake_minimum_required(VERSION 3.12)
project(WMBusDecryption)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add executable
add_executable(wmbus_decrypt main.cpp)

# Link libraries
target_link_libraries(wmbus_decrypt OpenSSL::SSL OpenSSL::Crypto)

# Set compiler flags
target_compile_options(wmbus_decrypt PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -O2>
)

# For ESP32 (optional)
if(DEFINED ESP_PLATFORM)
    # ESP32 specific configuration
    target_link_libraries(wmbus_decrypt mbedtls mbedcrypto mbedx509)
    target_compile_definitions(wmbus_decrypt PRIVATE ESP32_BUILD)
endif()
