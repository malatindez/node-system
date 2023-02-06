set(LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party")

set(OPENSSL_DIR "${LIB_DIR}/openssl")
set(SPDLOG_DIR "${LIB_DIR}/spdlog")

# spdlog
add_subdirectory("${SPDLOG_DIR}" EXCLUDE_FROM_ALL)

function(target_add_spdlog TARGET)
  target_include_directories("${TARGET}" PRIVATE "${SPDLOG_DIR}/include")
endfunction(target_add_spdlog)


function(target_add_openssl TARGET)
  target_include_directories("${TARGET}" PRIVATE "${OPENSSL_DIR}/include")
  target_link_libraries("${TARGET}" "${OPENSSL_DIR}/lib/libssl.lib")
  target_link_libraries("${TARGET}" "${OPENSSL_DIR}/lib/libcrypto.lib")
endfunction(target_add_openssl)

function(target_add_libraries TARGET)
  if("${ARGN}" MATCHES "[oO][pP][eE][nN][sS][sS][lL]")
    target_add_openssl(${TARGET})
  endif()

  if("${ARGN}" MATCHES "[sS][pP][dD][lL][oO][gG]")
    target_add_spdlog(${TARGET})
  endif()
  
endfunction(target_add_libraries)

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