cmake_minimum_required(VERSION 3.28)
project(traffic_test)

set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
find_package(fmt CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(libtins CONFIG REQUIRED)

include_directories(include)

add_executable(traffic_test
        src/main.cpp
        src/capture_module.cpp
        src/control_module.cpp
        src/filter_module.cpp
)

target_link_libraries(traffic_test PRIVATE ${PCAP_LIBRARIES} fmt::fmt spdlog::spdlog tins)

find_package(Boost REQUIRED COMPONENTS regex)
target_link_libraries(traffic_test PRIVATE Boost::regex)

# add_executable(tests
#         tests/test_packet.cc)
# target_link_libraries(tests PRIVATE GTest::gtest GTest::gtest_main  fmt::fmt spdlog::spdlog)
# add_test(NAME tests COMMAND tests)