cmake_minimum_required(VERSION 2.8)
project(minimalist-pcproxy C)

set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -std=c99")

add_definitions(-D_GNU_SOURCE -Wall -Wextra)

if(${APPLE})
  # Xcode 4.* target breaks because it doesn't add 'system-ish' include paths
  include_directories(/usr/local/include /opt/local/include)
  link_directories(/usr/local/lib /opt/local/lib)
endif(${APPLE})

add_executable(minimalist-pcproxy main.c)
target_link_libraries(minimalist-pcproxy ubox)

# Installation rules
install(TARGETS minimalist-pcproxy DESTINATION sbin/)

# Packaging rules
set(CPACK_PACKAGE_VERSION "1")
set(CPACK_PACKAGE_CONTACT "Markus Stenberg <fingon@iki.fi>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "minimalist-pcproxy")
set(CPACK_GENERATOR "DEB;RPM;STGZ")
set(CPACK_STRIP_FILES true)

SET(CPACK_DEBIAN_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}")

include(CPack)
