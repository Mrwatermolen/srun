add_subdirectory(core)
add_subdirectory(net)
add_executable(srun main.cpp)
target_link_libraries(srun PRIVATE srun_net srun_core)
