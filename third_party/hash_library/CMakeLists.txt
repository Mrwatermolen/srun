aux_source_directory(. STBRUMME_HASH_LIBRARY_SRC)
add_library(stbrumme_hash_library ${STBRUMME_HASH_LIBRARY_SRC})
target_include_directories(stbrumme_hash_library PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
