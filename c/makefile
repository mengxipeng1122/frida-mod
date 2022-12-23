
ifndef NDKPATH
    $(error NDKPATH not set)
endif

all: bins/exe_linux_x64 bins/lib_linux_x64.so bins/libfrida_linux_x64.so  \
     bins/exe_linux_x86 bins/lib_linux_x86.so bins/libfrida_linux_x86.so  \
     bins/win64.dll  bins/frida_win64.dll bins/win64.exe \
     build_android

bins/win64.exe:main.cc 
	x86_64-w64-mingw32-gcc -o $@  $^ 

bins/win64.dll:mod_win.cc bins/frida_win64.dll
	x86_64-w64-mingw32-gcc -o $@  $^ --shared -fPIC 

bins/frida_win64.dll:frida_funs.c
	x86_64-w64-mingw32-gcc -o $@  $^ --shared -fPIC 


bins/win32.exe:main.cc 
	i686-w64-mingw32-gcc -o $@  $^ 

bins/win32.dll:mod_win.cc bins/frida_win32.dll
	i686-w64-mingw32-gcc -o $@  $^ --shared -fPIC 

bins/frida_win32.dll:frida_funs.c
	i686-w64-mingw32-gcc -o $@  $^ --shared -fPIC 


bins/exe_linux_x86:main.cc 
	gcc -o $@  $^  -m32

bins/lib_linux_x86.so:mod_linux.cc bins/libfrida_linux_x86.so
	gcc -o $@  $^  --shared -fPIC -m32

bins/libfrida_linux_x86.so:frida_funs.c
	gcc -o $@  $^  --shared -fPIC -m32

bins/exe_linux_x64:main.cc 
	gcc -o $@  $^ 

bins/lib_linux_x64.so:mod_linux.cc bins/libfrida_linux_x64.so
	gcc -o $@  $^  --shared -fPIC

bins/libfrida_linux_x64.so:frida_funs.c
	gcc -o $@  $^  --shared -fPIC

build_android:
	(cd  jni; ${NDKPATH}/ndk-build V=1)

clean:
	rm -fr bins/*
	(cd  jni; ${NDKPATH}/ndk-build clean)

