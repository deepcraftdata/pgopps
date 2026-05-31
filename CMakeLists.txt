cmake_minimum_required(VERSION 3.16)
project(pgopps VERSION 0.1.2 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler warnings
add_compile_options(-Wall -Wextra -Wpedantic -Wshadow)

# Debug vs Release
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# ---- libpq ----------------------------------------------------------------
find_package(PostgreSQL REQUIRED)

# ---- Sources ---------------------------------------------------------------
set(SOURCES
    src/main.c
    src/connection.c
    src/cloud.c
    src/info.c
    src/score.c
    src/utils.c
    src/report.c
    src/checks/registry.c
    src/checks/performance.c
    src/checks/security.c
    src/checks/encryption.c
    src/checks/audit_logging.c
    src/checks/data_integrity.c
    src/checks/maintenance.c
    src/checks/configuration.c
    src/checks/replication_ha.c
    src/checks/backup_recovery.c
)

add_executable(pgopps ${SOURCES})

target_include_directories(pgopps PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${PostgreSQL_INCLUDE_DIRS}
)

target_link_libraries(pgopps PRIVATE ${PostgreSQL_LIBRARIES})

# ---- Install ---------------------------------------------------------------
install(TARGETS pgopps DESTINATION bin)
