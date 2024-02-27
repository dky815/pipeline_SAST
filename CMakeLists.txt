cmake_minimum_required(VERSION 3.22)
project(fileserver)

set(CMAKE_CXX_STANDARD 17)

# Modify this line based on your system installation path
# set( OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
find_package(OpenSSL REQUIRED)
if ( OPENSSL_FOUND )
    message(STATUS "OpenSSL Found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL Libraries: ${OPENSSL_LIBRARIES}")
endif()

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}
    encryption
    features
    helpers
    authentication
    )

set(HEADERS
    encryption/encryption.h
    encryption/randomizer_function.h
    
    features/features.h
    features/features_helpers.h
    
    helpers/helper_functions.h
    helpers/json.hpp
    
    authentication/authentication.h
    )

add_executable(${PROJECT_NAME} main.cpp ${HEADERS})

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRS})

target_link_libraries(
    ${PROJECT_NAME}
        OpenSSL::SSL 
        OpenSSL::Crypto
    )
