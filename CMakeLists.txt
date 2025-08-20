# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.19)

project ("prj")

# Set output
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# specify the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Use static link MSVCRT and disable RTTI
if(MSVC)
  cmake_policy(SET CMP0091 NEW)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
  set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")

  set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
  foreach(CompilerFlag ${CompilerFlags})
    string(REPLACE "/GR" "/GR-" ${CompilerFlag} "${${CompilerFlag}}")
  endforeach()
  add_compile_definitions(_HAS_STATIC_RTTI=0) # The Clang MSVC driver fails to define _HAS_STATIC_RTTI to 0, which is used by the MSVC standard library to enable no-RTTI code.
else()
    set(CMAKE_CUSTOM_COMPILE_FLAGS "-fPIC -no-pie -fno-exceptions -ffunction-sections -fdata-sections -fno-unwind-tables -fno-asynchronous-unwind-tables -fvisibility=hidden -static")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CMAKE_CUSTOM_COMPILE_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CMAKE_CUSTOM_COMPILE_FLAGS} -fno-rtti -fno-threadsafe-statics -fvisibility-inlines-hidden")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -s -Wl,--gc-sections,--print-gc-sections -ffile-prefix-map=${CMAKE_SOURCE_DIR}=")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s -Wl,--gc-sections,--print-gc-sections -ffile-prefix-map=${CMAKE_SOURCE_DIR}=")
endif(MSVC)

# Include sub-projects.
add_subdirectory ("src")

# Print compiler flags
if(MSVC)
set(CompilerFlags
        CMAKE_CXX_FLAGS
        CMAKE_CXX_FLAGS_DEBUG
        CMAKE_CXX_FLAGS_RELEASE
        CMAKE_C_FLAGS
        CMAKE_C_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELEASE
        )
foreach(CompilerFlag ${CompilerFlags})
  message("INFO: ${CompilerFlag}= ${${CompilerFlag}}")
endforeach()
endif(MSVC)

string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
string(TIMESTAMP CURRENT_SOURCE_DATE_EPOCH UTC)
message(STATUS "Summary of build options:
    SOURCE_DATE_EPOCH : ${CURRENT_SOURCE_DATE_EPOCH}
    Install prefix    : ${CMAKE_INSTALL_PREFIX}
    Target system     : ${CMAKE_SYSTEM_NAME}
    Toolchain         : ${CMAKE_TOOLCHAIN_FILE}
    ModulePath        : ${CMAKE_MODULE_PATH}
    PrefixPath        : ${CMAKE_PREFIX_PATH}
    FindRootPath      : ${CMAKE_FIND_ROOT_PATH}
    Compiler:
      Build type      : ${CMAKE_BUILD_TYPE}
      C compiler      : ${CMAKE_C_COMPILER}
      CFLAGS          : ${CMAKE_C_FLAGS_${_build_type}} ${CMAKE_C_FLAGS}
      C++ compiler    : ${CMAKE_CXX_COMPILER}
      CXXFLAGS        : ${CMAKE_CXX_FLAGS_${_build_type}} ${CMAKE_CXX_FLAGS}
      WARNCFLAGS      : ${WARNCFLAGS}
      CXX1XCXXFLAGS   : ${CXX1XCXXFLAGS}
")
