#
# Copyright 2009- ECMWF.
#
# This software is licensed under the terms of the Apache Licence version 2.0
# which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
# In applying this licence, ECMWF does not waive the privileges and immunities
# granted to it by virtue of its status as an intergovernmental organisation
# nor does it submit to any jurisdiction.
#

# FindJwtCpp
# ----------
#
# Find the (header-only) jwt-cpp include dir, used for in-server OIDC/JWT
# verification. Mirrors FindHttplib.cmake / FindJson.cmake.
#
#   JWTCPP_FOUND            - True if library is found
#   JWTCPP_INCLUDE_DIRS     - Include directories to be used
#
# The following IMPORTED target is defined:
#
#   jwt-cpp::jwt-cpp        - Generic target for the library
#

if (NOT DEFINED JWTCPP_DIR)
  message(FATAL_ERROR "Unable to find JwtCpp. Please provide JWTCPP_DIR property.")
endif ()

find_path(JWTCPP_INCLUDE_DIRS
  NAMES jwt-cpp/jwt.h
  PATHS ${JWTCPP_DIR}/include)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(JwtCpp
  REQUIRED_VARS
  JWTCPP_INCLUDE_DIRS)

set(NAME "jwt-cpp")

add_library(${NAME} INTERFACE IMPORTED GLOBAL)

set_target_properties(${NAME}
  PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${JWTCPP_INCLUDE_DIRS}")

add_library(jwt-cpp::jwt-cpp ALIAS jwt-cpp)
