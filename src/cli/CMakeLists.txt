aux_source_directory(. SRUN_CLI_SOURCES)
add_executable(srun_cli ${SRUN_CLI_SOURCES})
target_link_libraries(srun_cli PRIVATE srun ${SRUN_EXTERNAL_LIB})
target_include_directories(srun_cli PRIVATE ${SRUN_PRIVATE_INCLUDE_DIR})
