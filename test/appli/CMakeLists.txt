
set(SOURCES app.c)
add_executable(app ${SOURCES})
target_link_libraries(app soem)
install(TARGETS app DESTINATION bin)
