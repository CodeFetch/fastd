# Defines the following variables:
#  LIBURING_FOUND
#  LIBURING_INCLUDE_DIR
#  LIBURING_LIBRARIES
#  LIBURING_CFLAGS_OTHER
#  LIBURING_LDFLAGS_OTHER


if(LINUX AND NOT ANDROID)

pkg_check_modules(_LIBURING liburing)

find_path(LIBURING_INCLUDE_DIR NAMES liburing.h HINTS ${_LIBURING_INCLUDE_DIRS} NO_CMAKE_FIND_ROOT_PATH)
find_path(LIBURING_INCLUDE_DIR NAMES liburing.h HINTS ${_LIBURING_INCLUDE_DIRS})

find_library(LIBURING_LIBRARIES NAMES uring HINTS ${_LLIBURING_LIBRARY_DIRS} NO_CMAKE_FIND_ROOT_PATH)
find_library(LIBURING_LIBRARIES NAMES uring HINTS ${_LIBURING_LIBRARY_DIRS})

set(LIBURING_CFLAGS_OTHER "${_LIBURING_CFLAGS_OTHER}" CACHE STRING "Additional compiler flags for liburing")
set(LIBURING_LDFLAGS_OTHER "${_LIBURING_LDFLAGS_OTHER}" CACHE STRING "Additional linker flags for liburing")

find_package_handle_standard_args(LIBURING REQUIRED_VARS LIBURING_LIBRARIES LIBURING_INCLUDE_DIR)
mark_as_advanced(LIBURING_INCLUDE_DIR LIBURING_LIBRARIES LIBURING_CFLAGS_OTHER LIBURING_LDFLAGS_OTHER)

endif(LINUX AND NOT ANDROID)
