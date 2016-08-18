cmake_minimum_required(VERSION 3.0.0)

project(qore-ldap-module VERSION 1.1.1 LANGUAGES C CXX)

include(CheckCXXCompilerFlag)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
find_package(Qore REQUIRED)
find_package(OpenLDAP REQUIRED)

# Check for C++11.
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

check_cxx_compiler_flag(-fvisibility=hidden HAVE_GCC_VISIBILITY)

configure_file(${CMAKE_SOURCE_DIR}/cmake/config.h.cmake config.h)

set(CPP_SRC src/openldap-module.cpp)
set(QPP_SRC src/QC_LdapClient.qpp)
set(module_name openldap)

qore_wrap_qpp(QPP_CPP_SRC ${QPP_SRC})

add_library(${module_name} SHARED ${QPP_CPP_SRC} ${CPP_SRC})
target_include_directories(${module_name} PUBLIC ${OpenLDAP_INCLUDE_DIR} ${CMAKE_SOURCE_DIR}/src)

qore_binary_module(${module_name} ${PROJECT_VERSION} ${OpenLDAP_LIB_R})

qore_dist($PROJECT_VERSION})

qore_config_info()
