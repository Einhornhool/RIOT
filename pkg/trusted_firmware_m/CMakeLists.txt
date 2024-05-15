cmake_minimum_required(VERSION 3.21)

add_library(tfm_ns STATIC)

if (NOT DEFINED CONFIG_SPE_PATH OR NOT EXISTS ${CONFIG_SPE_PATH})
    message(FATAL_ERROR "CONFIG_SPE_PATH = ${CONFIG_SPE_PATH} is not defined or incorrect. Please provide full path to TF-M build artifacts using -DCONFIG_SPE_PATH=")
endif()

list(APPEND CMAKE_MODULE_PATH ${CONFIG_SPE_PATH}/cmake)
# A platform specific MCPU and architecture flags for NS side
include(${CONFIG_SPE_PATH}/platform/cpuarch.cmake)
# Include common configs exported from TF-M
include(${CONFIG_SPE_PATH}/cmake/spe_config.cmake)

# Select toolchain file if it is not specified via command line or the absolutate path
# is unavailable.
if (NOT DEFINED TFM_TOOLCHAIN_FILE)
    set(TFM_TOOLCHAIN_FILE    ${CONFIG_SPE_PATH}/cmake/toolchain_ns_GNUARM.cmake)
endif()

if(NOT EXISTS ${TFM_TOOLCHAIN_FILE})
    message(FATAL_ERROR "TFM_TOOLCHAIN_FILE ${TFM_TOOLCHAIN_FILE} doesn't exist."
                        "If it's relative path then please change to absolute path.")
endif()

include(${TFM_TOOLCHAIN_FILE})

set(CMAKE_TRY_COMPILE_TARGET_TYPE "STATIC_LIBRARY")

project(api_ns C)
tfm_toolchain_reload_compiler()

add_subdirectory(${CONFIG_SPE_PATH} ${CMAKE_BINARY_DIR}/spe)

target_link_libraries(tfm_ns
    PRIVATE
        tfm_api_ns
        tfm_api_ns_tz
        ${CONFIG_SPE_PATH}/interface/lib/s_veneers.o
)
