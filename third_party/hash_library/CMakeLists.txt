aux_source_directory(. STBRUMME_HASH_LIBRARY_SRC)
add_library(srun_stbrumme_hash OBJECT ${STBRUMME_HASH_LIBRARY_SRC})
target_include_directories(srun_stbrumme_hash PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
