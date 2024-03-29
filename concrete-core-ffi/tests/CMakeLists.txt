project(concrete-core-ffi-tests)

cmake_minimum_required(VERSION 3.16)

set(CONCRETE_CORE_FFI_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/")

include_directories(${CONCRETE_CORE_FFI_RELEASE})
add_library(Concrete STATIC IMPORTED)
set_target_properties(Concrete PROPERTIES IMPORTED_LOCATION ${CONCRETE_CORE_FFI_RELEASE}/libconcrete_core_ffi.a)

if(APPLE)
    find_library(SECURITY_FRAMEWORK Security)
    if (NOT SECURITY_FRAMEWORK)
        message(FATAL_ERROR "Security framework not found")
    endif()
endif()

file(GLOB TEST_CASES test_*.c)
foreach (testsourcefile ${TEST_CASES})
    get_filename_component(testname ${testsourcefile} NAME_WLE)
    get_filename_component(groupname ${testsourcefile} DIRECTORY)
    add_executable(${testname} ${testsourcefile} utils.c)
    add_test(
            NAME ${testname}
            COMMAND ${testname}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/Testing
    )
    target_include_directories(${testname} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${testname} LINK_PUBLIC Concrete m pthread dl)
    if(APPLE)
        target_link_libraries(${testname} LINK_PUBLIC ${SECURITY_FRAMEWORK})
    endif()
    target_compile_options(${testname} PRIVATE -Werror)
    # Enabled asserts even in release mode
    add_definitions(-UNDEBUG)
endforeach (testsourcefile ${TEST_CASES})

