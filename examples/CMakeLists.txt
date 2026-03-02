cmake_minimum_required(VERSION 3.16)

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------

# Client-side demo (runs on the device requesting authorization)
add_executable(client_demo client_demo.cc)
target_link_libraries(client_demo PRIVATE secret_com::secret_com)

# Server-side demo (runs on the ESC authorization device)
add_executable(server_demo server_demo.cc)
target_link_libraries(server_demo PRIVATE secret_com::secret_com)

# C API demo
add_executable(c_api_demo c_api_demo.c)
target_link_libraries(c_api_demo PRIVATE secret_com::c_api)
