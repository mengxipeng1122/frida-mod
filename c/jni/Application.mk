
APP_PLATFORM=android-21
APP_ABI=armeabi-v7a arm64-v8a

# APP_STL := stlport_shared  --> does not seem to contain C++11 features

# Enable c++11 extentions in source code
APP_CPPFLAGS += -std=c++1z
