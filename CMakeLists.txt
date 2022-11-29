cmake_minimum_required(VERSION 3.0)
project(cryptobench)
set(CMAKE_CXX_STANDARD 14)

add_executable(main main.cpp)
find_package(OpenSSL REQUIRED)
target_link_libraries(main PRIVATE OpenSSL::Crypto)
find_package(cryptopp CONFIG REQUIRED)
target_link_libraries(main PRIVATE cryptopp::cryptopp)
