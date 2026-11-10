cmake_minimum_required(VERSION 3.22.1)
project(pufw_insights LANGUAGES CXX)
# A PIE executable in the APK native-library directory; never loaded into the app.
add_executable(pufw_insights insights.cpp)
set_target_properties(pufw_insights PROPERTIES OUTPUT_NAME libpufw_insights.so)
target_compile_features(pufw_insights PRIVATE cxx_std_17)
target_compile_options(pufw_insights PRIVATE -Wall -Wextra -Werror -fstack-protector-strong -fPIE)
# Keep debug paths (and the derived ELF build IDs) independent of checkout/SDK location.
target_compile_options(pufw_insights PRIVATE
    "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=."
    "-ffile-prefix-map=${CMAKE_ANDROID_NDK}=/android-ndk"
    -fdebug-compilation-dir=.)
target_link_options(pufw_insights PRIVATE -pie -Wl,-z,relro,-z,now,-z,max-page-size=16384)
