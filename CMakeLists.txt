cmake_minimum_required(VERSION 3.0)
project(random-src)
find_package(Threads REQUIRED)
include_directories(include)
aux_source_directory(src SRC)
add_executable(random-src ${SRC})
target_link_libraries(random-src Threads::Threads netfilter_conntrack netfilter_queue)
install(TARGETS random-src DESTINATION bin)
