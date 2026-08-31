include_guard(GLOBAL)

function(revana_add_build_info target)
    find_package(Git REQUIRED)

    set(lock_path "${CMAKE_CURRENT_SOURCE_DIR}/rexglue-sdk.lock.json")
    file(READ "${lock_path}" lock_json)
    string(JSON sdk_repository GET "${lock_json}" repository)
    string(JSON sdk_branch GET "${lock_json}" branch)
    string(JSON sdk_commit GET "${lock_json}" commit)
    string(LENGTH "${sdk_commit}" sdk_commit_length)
    if(NOT sdk_repository STREQUAL
       "https://github.com/REVana360/vana360-sdk" OR
       NOT sdk_branch STREQUAL "main" OR
       NOT sdk_commit MATCHES "^[0-9a-f]+$" OR
       NOT sdk_commit_length EQUAL 40)
        message(FATAL_ERROR "Invalid ReXGlue SDK lock")
    endif()

    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${REVANA_REXSDK_DIR}"
                rev-parse --verify HEAD
        OUTPUT_VARIABLE sdk_checkout_commit
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE sdk_checkout_result)
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${REVANA_REXSDK_DIR}"
                status --porcelain=v1 --untracked-files=normal
        OUTPUT_VARIABLE sdk_checkout_status
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE sdk_status_result)
    if(NOT sdk_checkout_result EQUAL 0 OR
       NOT sdk_status_result EQUAL 0 OR
       NOT sdk_checkout_commit STREQUAL sdk_commit OR
       NOT sdk_checkout_status STREQUAL "")
        message(FATAL_ERROR
            "ReXGlue SDK checkout does not match the accepted clean lock")
    endif()

    if(REXSDK_DIR)
        file(REAL_PATH "${REXSDK_DIR}" loaded_sdk_dir)
        file(REAL_PATH "${REVANA_REXSDK_DIR}" accepted_sdk_dir)
        if(NOT loaded_sdk_dir STREQUAL accepted_sdk_dir)
            message(FATAL_ERROR
                "Loaded ReXGlue SDK source does not match the accepted lock")
        endif()
        file(READ "${accepted_sdk_dir}/CMakeLists.txt" sdk_cmake)
        string(REGEX MATCH
            "project\\(ReXGlue[ \t\r\n]+VERSION[ \t\r\n]+([0-9]+\\.[0-9]+\\.[0-9]+)"
            sdk_project_version "${sdk_cmake}")
        if(NOT sdk_project_version)
            message(FATAL_ERROR "ReXGlue SDK API version is unavailable")
        endif()
        set(sdk_api_version "${CMAKE_MATCH_1}")
    elseif(DEFINED REXGLUE_VERSION_STRING)
        set(sdk_version "${REXGLUE_VERSION_STRING}")
        if(NOT sdk_version MATCHES
           "^([0-9]+\\.[0-9]+\\.[0-9]+)")
            message(FATAL_ERROR "ReXGlue SDK API version is unavailable")
        endif()
        set(sdk_api_version "${CMAKE_MATCH_1}")
        string(SUBSTRING "${sdk_commit}" 0 7 sdk_short_commit)
        if(NOT sdk_version MATCHES
           "(^|[^0-9a-f])g${sdk_short_commit}([^0-9a-f]|$)")
            message(FATAL_ERROR
                "Loaded ReXGlue SDK package does not match the accepted lock")
        endif()
    else()
        message(FATAL_ERROR "ReXGlue SDK version is unavailable")
    endif()

    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/docs/supported-disc.md"
         supported_disc)
    string(REGEX MATCH
        "\\| Profile ID \\| `([a-z0-9-]+)` \\|"
        profile_row "${supported_disc}")
    if(NOT profile_row)
        message(FATAL_ERROR "Supported input profile ID is unavailable")
    endif()
    set(input_profile "${CMAKE_MATCH_1}")

    if(WIN32)
        set(platform "windows")
    elseif(APPLE)
        set(platform "macos")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(platform "linux")
    else()
        message(FATAL_ERROR "Unsupported Vana360 build platform")
    endif()

    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" processor)
    if(processor MATCHES "^(amd64|x86_64)$")
        set(architecture "x64")
    elseif(processor MATCHES "^(arm64|aarch64)$")
        set(architecture "arm64")
    else()
        message(FATAL_ERROR "Unsupported Vana360 build architecture")
    endif()

    if(NOT CMAKE_BUILD_TYPE)
        message(FATAL_ERROR "Vana360 title builds require CMAKE_BUILD_TYPE")
    endif()
    set(compiler "${CMAKE_CXX_COMPILER_ID}-${CMAKE_CXX_COMPILER_VERSION}")

    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}"
                rev-parse --absolute-git-dir
        OUTPUT_VARIABLE git_dir
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE git_dir_result)
    if(NOT git_dir_result EQUAL 0)
        message(FATAL_ERROR "Vana360 Git directory is unavailable")
    endif()

    set(git_dependencies "${git_dir}/HEAD" "${git_dir}/index")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}"
                symbolic-ref --quiet HEAD
        OUTPUT_VARIABLE head_ref
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE head_ref_result)
    if(head_ref_result EQUAL 0)
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}"
                    rev-parse --git-path "${head_ref}"
            OUTPUT_VARIABLE head_ref_path
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE head_ref_path_result)
        if(NOT head_ref_path_result EQUAL 0)
            message(FATAL_ERROR "Vana360 Git reference is unavailable")
        endif()
        list(APPEND git_dependencies "${head_ref_path}")
    endif()
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}"
                rev-parse --git-path packed-refs
        OUTPUT_VARIABLE packed_refs
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE packed_refs_result)
    if(packed_refs_result EQUAL 0 AND EXISTS "${packed_refs}")
        list(APPEND git_dependencies "${packed_refs}")
    endif()

    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${CMAKE_CURRENT_SOURCE_DIR}"
                ls-files --cached --others --exclude-standard
        OUTPUT_VARIABLE build_info_input_text
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE build_info_inputs_result)
    if(NOT build_info_inputs_result EQUAL 0)
        message(FATAL_ERROR "Vana360 build info inputs are unavailable")
    endif()
    string(REPLACE "\r\n" "\n" build_info_input_text
           "${build_info_input_text}")
    string(REPLACE "\n" ";" build_info_input_paths
           "${build_info_input_text}")
    set(build_info_inputs "")
    set(build_info_directories "${CMAKE_CURRENT_SOURCE_DIR}")
    foreach(relative_path IN LISTS build_info_input_paths)
        if(relative_path MATCHES ";")
            message(FATAL_ERROR "Unsupported semicolon in repository path")
        endif()
        list(APPEND build_info_inputs
             "${CMAKE_CURRENT_SOURCE_DIR}/${relative_path}")
        get_filename_component(relative_directory "${relative_path}" DIRECTORY)
        if(relative_directory)
            list(APPEND build_info_directories
                 "${CMAKE_CURRENT_SOURCE_DIR}/${relative_directory}")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES build_info_directories)

    set(output_dir "${CMAKE_CURRENT_BINARY_DIR}/generated/build_info")
    set(build_info_header "${output_dir}/build_info.h")
    set(build_info_json "${CMAKE_CURRENT_BINARY_DIR}/revana-build-info.json")
    set(build_info_stamp "${output_dir}/build_info.stamp")
    set(generator_script
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/write_build_info.cmake")
    set(header_template
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_info.h.in")
    set(json_template
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_info.json.in")

    add_custom_command(
        OUTPUT "${build_info_stamp}"
        BYPRODUCTS "${build_info_header}" "${build_info_json}"
        COMMAND "${CMAKE_COMMAND}"
            "-DREVANA_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DREVANA_GIT_EXECUTABLE=${GIT_EXECUTABLE}"
            "-DREVANA_HEADER_TEMPLATE=${header_template}"
            "-DREVANA_JSON_TEMPLATE=${json_template}"
            "-DREVANA_BUILD_INFO_HEADER=${build_info_header}"
            "-DREVANA_BUILD_INFO_JSON=${build_info_json}"
            "-DREVANA_BUILD_INFO_STAMP=${build_info_stamp}"
            "-DREVANA_VERSION=${PROJECT_VERSION}"
            "-DREVANA_SDK_COMMIT=${sdk_commit}"
            "-DREVANA_SDK_API_VERSION=${sdk_api_version}"
            "-DREVANA_PLATFORM=${platform}"
            "-DREVANA_ARCHITECTURE=${architecture}"
            "-DREVANA_CONFIGURATION=${CMAKE_BUILD_TYPE}"
            "-DREVANA_COMPILER=${compiler}"
            "-DREVANA_GRAPHICS_BACKEND=xenos"
            "-DREVANA_INPUT_PROFILE=${input_profile}"
            -P "${generator_script}"
        DEPENDS
            "${generator_script}"
            "${header_template}"
            "${json_template}"
            "${lock_path}"
            "${CMAKE_CURRENT_SOURCE_DIR}/docs/supported-disc.md"
            ${git_dependencies}
            ${build_info_inputs}
            ${build_info_directories}
        COMMENT "Generating Vana360 build info"
        VERBATIM)

    add_custom_target(${target}_build_info DEPENDS "${build_info_stamp}")
    add_dependencies(${target} ${target}_build_info)
    set_source_files_properties("${build_info_header}" PROPERTIES GENERATED TRUE)
    target_sources(${target} PRIVATE "${build_info_header}")
    target_include_directories(${target} PRIVATE "${output_dir}")
endfunction()
