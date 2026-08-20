# Install script for directory: /workspace/mruby-ktls/deps/s2n-tls

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES "/workspace/mruby-ktls/deps/s2n-tls/api/s2n.h")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/s2n/unstable" TYPE FILE FILES
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/allow_ip_in_cn.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/async_offload.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/cert_authorities.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/cleanup.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/crl.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/custom_x509_extensions.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/events.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/fingerprint.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/ktls.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/npn.h"
    "/workspace/mruby-ktls/deps/s2n-tls/api/unstable/renegotiate.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/workspace/mruby-ktls/build-probe/s2n/lib/libs2n.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/s2n/cmake/static/s2n-targets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/s2n/cmake/static/s2n-targets.cmake"
         "/workspace/mruby-ktls/build-probe/s2n/CMakeFiles/Export/56b70b0ce463e9873ed1bdbd7d044117/s2n-targets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/s2n/cmake/static/s2n-targets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/s2n/cmake/static/s2n-targets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/s2n/cmake/static" TYPE FILE FILES "/workspace/mruby-ktls/build-probe/s2n/CMakeFiles/Export/56b70b0ce463e9873ed1bdbd7d044117/s2n-targets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/s2n/cmake/static" TYPE FILE FILES "/workspace/mruby-ktls/build-probe/s2n/CMakeFiles/Export/56b70b0ce463e9873ed1bdbd7d044117/s2n-targets-release.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/s2n/cmake" TYPE FILE FILES "/workspace/mruby-ktls/build-probe/s2n/s2n-config.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Development" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/s2n/cmake/modules" TYPE FILE FILES "/workspace/mruby-ktls/deps/s2n-tls/cmake/modules/Findcrypto.cmake")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/workspace/mruby-ktls/build-probe/s2n/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
