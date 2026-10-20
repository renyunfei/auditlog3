cmake_minimum_required(VERSION 3.5)
project(auditlog C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
add_compile_options(-Wall -Wextra -D_GNU_SOURCE)

find_path(UBOX_INCLUDE_DIR libubox/uloop.h)
find_library(UBOX_LIBRARY ubox)
find_library(BLOBMSG_JSON_LIBRARY blobmsg_json)
if(NOT UBOX_INCLUDE_DIR OR NOT UBOX_LIBRARY)
  message(FATAL_ERROR "libubox not found")
endif()
include_directories(${UBOX_INCLUDE_DIR} src)

add_library(auditclient STATIC src/audit_client.c)
target_link_libraries(auditclient ${UBOX_LIBRARY})

add_executable(auditd src/main.c src/audit_server.c src/audit_store.c)
target_link_libraries(auditd ${UBOX_LIBRARY})

add_executable(audit-write tools/audit_write.c)
target_link_libraries(audit-write auditclient)

add_executable(audit-read tools/audit_read.c)
target_link_libraries(audit-read auditclient)

install(TARGETS auditd audit-write audit-read RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
  add_executable(audit-tests tests/audit_test.c src/audit_server.c src/audit_store.c)
  target_link_libraries(audit-tests auditclient)
  foreach(check malformed pagination sockets store)
    add_test(NAME audit-${check} COMMAND audit-tests ${check})
    set_tests_properties(audit-${check} PROPERTIES TIMEOUT 10)
  endforeach()
endif()
