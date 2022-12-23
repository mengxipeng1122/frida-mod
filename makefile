build_arm64:
	make -C c build_android
	./utils/modinfo2ts.py -m load -b c/libs/arm64-v8a/libmod.so -o modinfos/libarm64.ts c/mod.cc
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build
	adb push c/libs/arm64-v8a/exe_arm /data/local/tmp/exe_arm64
	adb shell chmod +x /data/local/tmp/exe_arm64



build_linux_x86:
	make -C c bins/lib_linux_x86.so
	make -C c bins/exe_linux_x86
	./utils/modinfo2ts.py -m load -b c/bins/lib_linux_x86.so -o modinfos/liblinux_x86.ts c/mod.cc
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build


build_linux_x64:
	make -C c bins/lib_linux_x64.so
	make -C c bins/exe_linux_x64
	./utils/modinfo2ts.py -m load -b c/bins/lib_linux_x64.so -o modinfos/liblinux_x64.ts c/mod.cc
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



clean:
	make -C c clean
	rm -f modinfos/lib*.ts _agent.js
    


	
