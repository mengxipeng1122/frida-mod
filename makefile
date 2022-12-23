



build_linux_x64:
	make -C c exe_linux_x64
	./utils/modinfo2ts.py -m get -o modinfos/libc.ts source/libc.h
	npm run build

run_linux_x64:build_linux_x64
	-killall -9 exe_linux_x64
	frida -f c/bins/exe_linux_x64 -l _agent.js -o /tmp/log.txt

	
