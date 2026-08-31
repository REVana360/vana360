set(required_variables
    REVANA_SOURCE_DIR
    REVANA_GIT_EXECUTABLE
    REVANA_HEADER_TEMPLATE
    REVANA_JSON_TEMPLATE
    REVANA_BUILD_INFO_HEADER
    REVANA_BUILD_INFO_JSON
    REVANA_BUILD_INFO_STAMP
    REVANA_VERSION
    REVANA_SDK_COMMIT
    REVANA_SDK_API_VERSION
    REVANA_PLATFORM
    REVANA_ARCHITECTURE
    REVANA_CONFIGURATION
    REVANA_COMPILER
    REVANA_GRAPHICS_BACKEND
    REVANA_INPUT_PROFILE)
foreach(variable IN LISTS required_variables)
    if(NOT DEFINED ${variable} OR "${${variable}}" STREQUAL "")
        message(FATAL_ERROR "Missing build info input: ${variable}")
    endif()
endforeach()

execute_process(
    COMMAND "${REVANA_GIT_EXECUTABLE}" -C "${REVANA_SOURCE_DIR}"
            rev-parse --verify HEAD
    OUTPUT_VARIABLE REVANA_TITLE_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE title_commit_result)
string(LENGTH "${REVANA_TITLE_COMMIT}" title_commit_length)
if(NOT title_commit_result EQUAL 0 OR
   NOT REVANA_TITLE_COMMIT MATCHES "^[0-9a-f]+$" OR
   NOT title_commit_length EQUAL 40)
    message(FATAL_ERROR "Vana360 title commit is unavailable")
endif()

execute_process(
    COMMAND "${REVANA_GIT_EXECUTABLE}" -C "${REVANA_SOURCE_DIR}"
            status --porcelain=v1 --untracked-files=normal
    OUTPUT_VARIABLE worktree_status
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE worktree_status_result)
if(NOT worktree_status_result EQUAL 0)
    message(FATAL_ERROR "Vana360 worktree state is unavailable")
endif()

if(worktree_status STREQUAL "")
    set(REVANA_DIRTY_JSON false)
    set(REVANA_SOURCE_STATE clean)
else()
    set(REVANA_DIRTY_JSON true)
    set(REVANA_SOURCE_STATE dirty)
endif()

set(REVANA_BUILD_INFO_SUMMARY
    "vana360 v${REVANA_VERSION} title=${REVANA_TITLE_COMMIT}-${REVANA_SOURCE_STATE} sdk=${REVANA_SDK_COMMIT} api=${REVANA_SDK_API_VERSION} platform=${REVANA_PLATFORM} arch=${REVANA_ARCHITECTURE} config=${REVANA_CONFIGURATION} compiler=${REVANA_COMPILER} backend=${REVANA_GRAPHICS_BACKEND} input=${REVANA_INPUT_PROFILE}")

get_filename_component(build_info_header_dir "${REVANA_BUILD_INFO_HEADER}" DIRECTORY)
get_filename_component(build_info_json_dir "${REVANA_BUILD_INFO_JSON}" DIRECTORY)
file(MAKE_DIRECTORY "${build_info_header_dir}" "${build_info_json_dir}")
configure_file("${REVANA_HEADER_TEMPLATE}" "${REVANA_BUILD_INFO_HEADER}" @ONLY)
configure_file("${REVANA_JSON_TEMPLATE}" "${REVANA_BUILD_INFO_JSON}" @ONLY)
file(TOUCH "${REVANA_BUILD_INFO_STAMP}")
