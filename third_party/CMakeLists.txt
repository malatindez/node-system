set(LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party")

set(SPDLOG_DIR "${LIB_DIR}/spdlog")
set(BOOST_DIR "${LIB_DIR}/boost-cmake")
set(GTEST_DIR "${LIB_DIR}/google/google_test")

# spdlog
add_subdirectory("${SPDLOG_DIR}" EXCLUDE_FROM_ALL)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

set(Boost_USE_STATIC_LIBS ON)
add_subdirectory("${BOOST_DIR}")

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory("${GTEST_DIR}" EXCLUDE_FROM_ALL)

set_target_properties(gtest PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${BINARY_OUTPUT_DIR})
set_target_properties(gtest PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BINARY_OUTPUT_DIR})

set_target_properties(gtest_main PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${BINARY_OUTPUT_DIR})
set_target_properties(gtest_main PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BINARY_OUTPUT_DIR})

function(target_add_gtest TARGET)
  enable_testing()
  include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})
  include_directories(${INCLUDES})
  target_link_libraries("${TARGET}" PUBLIC gtest gtest_main)
endfunction(target_add_gtest)

function(target_add_spdlog TARGET)
  target_include_directories("${TARGET}" PRIVATE "${SPDLOG_DIR}/include")
endfunction(target_add_spdlog)

function(target_add_openssl TARGET)
  if(OPENSSL_FOUND)
    target_include_directories("${TARGET}" PRIVATE "${OPENSSL_INCLUDE_DIR}")
    target_link_libraries("${TARGET}" PUBLIC OpenSSL::Crypto)
  else()
    message(FATAL_ERROR "OpenSSL not found")
  endif()
endfunction(target_add_openssl)

function(target_add_boost TARGET)
  target_include_directories("${TARGET}" PUBLIC Boost::boost)
  target_include_directories("${TARGET}" PUBLIC Boost::system)
  target_include_directories("${TARGET}" PUBLIC Boost::filesystem)
  target_include_directories("${TARGET}" PUBLIC Boost::program_options)
  target_include_directories("${TARGET}" PUBLIC Boost::serialization)
  target_link_libraries("${TARGET}" PUBLIC Boost::boost)
  target_link_libraries("${TARGET}" PUBLIC Boost::system)
  target_link_libraries("${TARGET}" PUBLIC Boost::filesystem)
  target_link_libraries("${TARGET}" PUBLIC Boost::program_options)
  target_link_libraries("${TARGET}" PUBLIC Boost::serialization)
endfunction(target_add_boost)

function(target_add_libraries TARGET)
  if("${ARGN}" MATCHES "[oO][pP][eE][nN][sS][sS][lL]")
    target_add_openssl(${TARGET})
  endif()

  if("${ARGN}" MATCHES "[sS][pP][dD][lL][oO][gG]")
    target_add_spdlog(${TARGET})
  endif()

  if("${ARGN}" MATCHES "[bB][oO][oO][sS][tT]")
    target_add_boost(${TARGET})
  endif()

  if("${ARGN}" MATCHES "[gG][tT][eE][sS][tT]")
    target_add_gtest(${TARGET})
  endif()

  
endfunction(target_add_libraries)
IF (WIN32)
function(update_sources_msvc SOURCES)
  foreach(_source IN ITEMS ${SOURCES})
    if(IS_ABSOLUTE "${_source}")
      file(RELATIVE_PATH _source_rel "${CMAKE_CURRENT_SOURCE_DIR}" "${_source}")
    else()
      set(_source_rel "${_source}")
    endif()

    get_filename_component(_source_path "${_source_rel}" PATH)
    string(REPLACE "/" "\\" _source_path_msvc "${_source_path}")
    source_group("${_source_path_msvc}" FILES "${_source}")
  endforeach()
endfunction(update_sources_msvc)
ELSE()
ENDIF()