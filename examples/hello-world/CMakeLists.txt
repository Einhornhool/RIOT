cmake_minimum_required(VERSION 3.14)
project(nrfsdk LANGUAGES C ASM)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/../cmake")
include("nrf5")

add_executable(${CMAKE_PROJECT_NAME}
  "${NRF5_SDK_PATH}/examples/peripheral/blinky/main.c"
)

nrf5_target(${CMAKE_PROJECT_NAME})
target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC
  nrf5_nrfx_common
  nrf5_delay
  nrf5_boards
  nrf5_app_util_platform
  nrf5_app_error
  nrf5_atfifo
  nrf5_atomic
  nrf5_balloc
  nrf5_cli
  nrf5_config
  nrf5_crypto
  nrf5_crypto_cc310_backend
  nrf5_delay
  nrf5_drv_rng
  nrf5_drv_twi
  nrf5_drv_uart
  nrf5_ext_cc310_bl_fwd
  nrf5_ext_cc310_fwd
  nrf5_ext_cifra_aes128_eax_fwd
  nrf5_ext_fprintf
  nrf5_ext_mbedtls_fwd
  nrf5_ext_micro_ecc_fwd
  nrf5_ext_oberon_fwd
  nrf5_ext_optiga_fwd
  nrf5_fds
  nrf5_fstorage
  nrf5_log
  nrf5_log_fwd
  nrf5_mdk
  nrf5_mem_manager
  nrf5_memobj
  nrf5_mtx
  nrf5_nrfx_common
  nrf5_nrfx_hal
  nrf5_nrfx_rng
  nrf5_pwr_mgmt
  nrf5_queue
  nrf5_ringbuf
  nrf5_sdh
  nrf5_section
  nrf5_sha256_fwd
  nrf5_soc
  nrf5_stack_info
  nrf5_strerror
)