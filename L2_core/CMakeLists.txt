set(CPP_SOURCES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/L2_core")

set(CMAKE_CXX_STANDARD 20)
file(GLOB_RECURSE CPP_SOURCES ${CPP_SOURCES_DIR} *.*)
list(FILTER CPP_SOURCES INCLUDE REGEX ${CPP_SOURCES_DIR}/*)
set(L2_CORE_NODE_SOURCES ${CPP_SOURCES})
set(PROJECT_NAME L2_core_node)

IF (WIN32)
foreach(_source IN ITEMS ${L2_CORE_NODE_SOURCES})
  if(IS_ABSOLUTE "${_source}")
    file(RELATIVE_PATH _source_rel "${CMAKE_CURRENT_SOURCE_DIR}" "${_source}")
  else()
    set(_source_rel "${_source}")
  endif()

  get_filename_component(_source_path "${_source_rel}" PATH)
  string(REPLACE "/" "\\" _source_path_msvc "${_source_path}")
  source_group("${_source_path_msvc}" FILES "${_source}")
endforeach()

ENDIF()
add_executable(${PROJECT_NAME} ${L2_CORE_NODE_SOURCES} ${NODE_SYSTEM_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${L2_CORE_NODE_SOURCES_DIR})
target_include_directories(${PROJECT_NAME} PRIVATE ${NODE_SYSTEM_SOURCES_DIR})
set(CMAKE_CXX_FLAGS_DEBUG_INIT "${CMAKE_CXX_FLAGS_DEBUG_INIT}" "Zl")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /INCREMENTAL /EDITANDCONTINUE")

# target_link_libraries(${PROJECT_NAME} node_system)
target_add_libraries(${PROJECT_NAME} "openssl" "spdlog" "boost")
#target_precompile_headers(${PROJECT_NAME} PRIVATE "${NODE_SYSTEM_SOURCES_DIR}/include/library-pch.hpp")

set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)
file(WRITE "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.vcxproj.user" "\
<?xml version=\"1.0\" encoding=\"utf-8\"?> \ 
<Project ToolsVersion=\"Current\" xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\"> \ 
  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Debug|x64'\"> \ 
    <LocalDebuggerWorkingDirectory>$(ProjectDir)..\\runtime_directory\\</LocalDebuggerWorkingDirectory> \ 
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor> \ 
  </PropertyGroup> \ 
  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='MinSizeRel|x64'\"> \ 
    <LocalDebuggerWorkingDirectory>$(ProjectDir)..\\runtime_directory\\</LocalDebuggerWorkingDirectory> \ 
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor> \ 
  </PropertyGroup> \ 
  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='Release|x64'\"> \ 
    <LocalDebuggerWorkingDirectory>$(ProjectDir)..\\runtime_directory\\</LocalDebuggerWorkingDirectory> \ 
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor> \ 
  </PropertyGroup> \ 
  <PropertyGroup Condition=\"'$(Configuration)|$(Platform)'=='RelWithDebInfo|x64'\"> \ 
    <LocalDebuggerWorkingDirectory>$(ProjectDir)..\\runtime_directory\\</LocalDebuggerWorkingDirectory> \ 
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor> \ 
  </PropertyGroup> \ 
</Project> \ 
")

set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BINARY_OUTPUT_DIR})

# copy the executable to the runtime directory
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD 
  COMMAND "${CMAKE_COMMAND}" -E copy 
     "$<TARGET_FILE:${PROJECT_NAME}>"
     "${CMAKE_CURRENT_SOURCE_DIR}/runtime_directory/$<TARGET_FILE_NAME:${PROJECT_NAME}>" 
  COMMENT "Copying the executable to output directory"
)