

ifndef WIN_HOST_IP
    $(error WIN_HOST_IP not set)
endif


build_win32:
	make -C c bins/win32.dll
	make -C c bins/win32.exe
	./utils/modinfo2ts.py -m load -b c/bins/win32.dll -o modinfos/libwin32.ts c/mod_win.cc
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build
	-cp c/bins/win32.exe /mnt/d/work/workspace



build_win64:
	make -C c bins/win64.dll
	make -C c bins/win64.exe
	./utils/modinfo2ts.py -m load -b c/bins/win64.dll -o modinfos/libwin64.ts c/mod_win.cc
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build
	-cp c/bins/win64.exe /mnt/d/work/workspace


build_arm32:
	make -C c build_android
	./utils/modinfo2ts.py -m load -b c/libs/armeabi-v7a/libmod.so -o modinfos/libarm32.ts c/mod.cc
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build
	adb push c/libs/armeabi-v7a/exe_arm /data/local/tmp/exe_arm32
	adb shell chmod +x /data/local/tmp/exe_arm32

build_arm64:
	make -C c build_android
	./utils/modinfo2ts.py -m load -b c/libs/arm64-v8a/libmod.so -o modinfos/libarm64.ts c/mod_linux.cc
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build
	adb push c/libs/arm64-v8a/exe_arm /data/local/tmp/exe_arm64
	adb shell chmod +x /data/local/tmp/exe_arm64



build_linux_x86:
	make -C c bins/lib_linux_x86.so
	make -C c bins/exe_linux_x86
	./utils/modinfo2ts.py -m load -b c/bins/lib_linux_x86.so -o modinfos/liblinux_x86.ts c/mod_linux.cc
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build


build_linux_x64:
	make -C c bins/lib_linux_x64.so
	make -C c bins/exe_linux_x64
	./utils/modinfo2ts.py -m load -b c/bins/lib_linux_x64.so -o modinfos/liblinux_x64.ts c/mod_linux.cc
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build

run_linux_x64:build_linux_x64
	-killall -9 exe_linux_x64
	frida -f c/bins/exe_linux_x64 -l _agent.js -o /tmp/log.txt

run_linux_x86:build_linux_x86
	-killall -9 exe_linux_x86; sleep 1;
	# need to start frida-server-linux-x86  and run command 'sudo sysctl kernel.yama.ptrace_scope=0'
	./c/bins/exe_linux_x86  &
	frida -H 127.0.0.1 -n exe_linux_x86 -l _agent.js -o /tmp/log.txt

run_arm64:build_arm64
	frida -U -n exe_arm64 -l _agent.js -o /tmp/log.txt

run_arm32:build_arm32
	frida -U -n exe_arm32 -l _agent.js -o /tmp/log.txt

run_win64:build_win64
	frida -H ${WIN_HOST_IP} -n win64.exe -l _agent.js -o /tmp/log.txt

run_win32:build_win32
	frida -H ${WIN_HOST_IP} -n win32.exe -l _agent.js -o /tmp/log.txt

clean:
	make -C c clean
	rm -f modinfos/lib*.ts _agent.js
    


	
