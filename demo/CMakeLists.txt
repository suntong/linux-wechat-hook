cmake_minimum_required(VERSION 3.5)

# Enable ASM
enable_language(ASM)

# Source files (C++ and Assembly)
set(VIRUS_FILES ./virus.cpp)
set(WECHAT_HOOK_FILES
    ./wechat_hook.cpp
    ./hook_trampoline.S
)

# Compiler flags for C++
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -O2 -fPIC -fno-omit-frame-pointer")

# Create shared library
add_library(X SHARED ${WECHAT_HOOK_FILES})

# Link libraries
target_link_libraries(X lmcbase)
target_link_libraries(X target)

#add_executable(virus ${VIRUS_FILES})
#target_link_libraries(virus lmcbase)
#target_link_libraries(virus infector)
#target_link_libraries(virus target)
#target_link_libraries(virus xed)

#install(FILES ${PROJECT_BINARY_DIR}/demo/virus PERMISSIONS OWNER_EXECUTE 
#              OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE WORLD_READ 
#              WORLD_WRITE DESTINATION ${PROJECT_BINARY_DIR}/install/demo/)
