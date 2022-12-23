
ifndef NDKPATH
    $(error NDKPATH not set)
endif

all: bins/exe_linux_x64 bins/lib_linux_x64.so bins/libfrida_linux_x64.so  \
     bins/exe_linux_x86 bins/lib_linux_x86.so bins/libfrida_linux_x86.so  \
     build_android


bins/exe_linux_x86:main.cc bins/lib_linux_x86.so
	gcc -o $@  $^  -m32

bins/lib_linux_x86.so:mod.cc bins/libfrida_linux_x86.so
	gcc -o $@  $^  --shared -fPIC -m32

bins/libfrida_linux_x86.so:frida_funs.c
	gcc -o $@  $^  --shared -fPIC -m32

bins/exe_linux_x64:main.cc bins/lib_linux_x64.so
	gcc -o $@  $^ 

bins/lib_linux_x64.so:mod.cc bins/libfrida_linux_x64.so
	gcc -o $@  $^  --shared -fPIC

bins/libfrida_linux_x64.so:frida_funs.c
	gcc -o $@  $^  --shared -fPIC

build_android:
	(cd  jni; ${NDKPATH}/ndk-build V=1)

clean:
	rm -fr bins/*
	(cd  jni; ${NDKPATH}/ndk-build clean)

