SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS_DEBUG} -O0 -g")

SET(LAMBCHOP_HEADERS lambchop.h unix_syscalls.h mach_syscalls.h)
SET(LAMBCHOP_SOURCES ${LAMBCHOP_HEADERS}
                     main.c
                     logger.c
                     mach-o/dump.c
                     mach-o/load.c
                     file.c
                     vm.c
                     syscall.S
                     trace.c)

SET(LAMBCHOP_EXECUTABLE lambchop_executable)
SET(LAMBCHOP_EXECUTABLE_OUTPUT lambchop)
ADD_EXECUTABLE(${LAMBCHOP_EXECUTABLE} ${LAMBCHOP_SOURCES})
SET_TARGET_PROPERTIES(${LAMBCHOP_EXECUTABLE} PROPERTIES OUTPUT_NAME ${LAMBCHOP_EXECUTABLE_OUTPUT})
TARGET_LINK_LIBRARIES(${LAMBCHOP_EXECUTABLE} pthread x86i)
