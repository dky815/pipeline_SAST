# Set the minimum version of CMake required
cmake_minimum_required(VERSION 3.10)

# Set your project name and version
project(MyEncryptedFileSystem VERSION 1.0)
#project(MyEncryptionTests VERSION 1.0)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include OpenSSL into the project
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Define the executable
add_executable(MyEncryptedFileSystem main.cpp)
#add_executable(MyEncryptionTests encryption.cpp)

# If your project has more .cpp files, add them to the executable
# For example, if "user.cpp" or "encrypted_filesystem.cpp" implementations exist:
# add_executable(MyEncryptedFileSystem main.cpp user.cpp encrypted_filesystem.cpp)

# Include directories for header files, if they're in separate directories
# include_directories(${CMAKE_SOURCE_DIR}/include)

# Link against libraries if needed (e.g., OpenSSL)
target_link_libraries(MyEncryptedFileSystem OpenSSL::SSL OpenSSL::Crypto)
#target_link_libraries(MyEncryptionTests OpenSSL::SSL OpenSSL::Crypto)


# If you use filesystem library and your compiler is gcc version less than 9, you might need to link stdc++fs
# Check for compiler and add link library conditionally
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(MyEncryptedFileSystem stdc++fs)
    #target_link_libraries(MyEncryptionTests stdc++fs)
endif()
