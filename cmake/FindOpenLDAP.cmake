# This file has been put in the public domain
# by it's author Niclas Rosenvik

include(CheckCSourceCompiles)
include(CMakePushCheckState)
include(FindPackageHandleStandardArgs)

find_path(OpenLDAP_INCLUDE_DIR ldap.h)
find_library(OpenLDAP_LIB_R NAMES ldap_r ldap)

#make sure it's openldap we have by compiling a test program
cmake_push_check_state(RESET)
set(CMAKE_REQUIRED_INCLUDES ${OpenLDAP_INCLUDE_DIR})
set(CMAKE_REQUIRED_LIBRARIES ${OpenLDAP_LIB_R})
check_c_source_compiles("
#include <ldap.h>
int main(void){
int ret;
LDAP* ldp;
ret = ldap_initialize(&ldp, \"ldaps://localhost:389\");
return 0;
}" OpenLDAP_COMPILES)
cmake_pop_check_state()

find_package_handle_standard_args(OpenLDAP DEFAULT_MSG OpenLDAP_INCLUDE_DIR OpenLDAP_LIB_R OpenLDAP_COMPILES)
