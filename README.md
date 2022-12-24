# Frida-mod
This project is trying to make load of a module easily, we can write the module in C/C++, hook and unhook function in the loaded module, and call the function directly. It also procide the functionality to access functions in a exsting module. I  tested this project on linux/x86, linux/x64, android/arm32, android/ar64, windows/x86 and windows/x64. Note, it has a issue on windows/x64.
## Build
### Requirement
We need a linux machine to compile this project. We should install the following software 
1. Compilers
    - gcc/g++;
    - [NDK](https://developer.android.com/ndk/downloads) (for android compiling); 
    - x86_64-w64-mingw32-gcc, i686-x64-mingw32-gcc (for windows coompiling)
    - llvm , for parsing of c/c++ code
```bash
# how to install llvm 14 
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 14

sudo ln -s /usr/lib/llvm-14/lib/libclang-14.so.1 /usr/lib/llvm-14/lib/libclang.so
export LD_LIBRARY_PATH=/usr/lib/llvm-14/lib
export DYLD_LIBRARY_PATH=/usr/lib/llvm-14/lib
```
2. Python packages
    - [lief](https://lief-project.github.io/download/)
    - jinja2
    - PyClang. For installing PyClang, [this page](http://www.jeh-tech.com/python/pyclang.html) really helps me out. 

###  Build instructions
```bash
// download code 
git clone https://github.com/mengxipeng1122/frida-mod.git
cd frida-mod
export NDKPATH=<The path to your NDK>
export WIN_HOST_IP=<IP address of your windows machine>
make # this will compile all codes
```

## Test
The main test code is in the file [index.ts](https://github.com/mengxipeng1122/frida-mod/blob/master/index.ts). It primaryly does the followsing things:
- Call function `sprintf` in exsiting module;
- Load a module we writed in C++, and call function `add` in this module;
### Linux x64
```bash
make run_linux_x64
```
### Linux x86
```bash
# need to run frida-server-<version>-linux-x86 first, 
#  and run command `sudo sysctl kernel.yama.ptrace_scope=0`
make run_linux_x86
```
### Android arm64
For android testing, you need a rooted Android device, and connect this device to you PC via USB. And start frida-server on it.
```bash
adb push c/libs/arm64-v8a/exe_arm /data/local/tmp/exe_arm64
adb shell chmod +x /data/local/tmp/exe_arm64
# and run `exe_arm64` on your android device
make run_arm64
```
### Android arm32
```bash
adb push c/libs/armeabi-v7a/exe_arm /data/local/tmp/exe_arm32
adb shell chmod +x /data/local/tmp/exe_arm32
# and run `exe_arm32` on your android device
make run_arm32
```
### windows x64
```bash
# confirm your linux macine can connect to your windows machine via local netowrk.
# cp file `c/bins/win64.exe` to your windows machine
# start frida-sever on your windows machine,  with command `frida-server -l 0.0.0.0`
# start `win64.exe` on your windows machine.
make run_win64
```
### windows x32
```bash
# confirm your linux macine can connect to your windows machine via local netowrk.
# cp file `c/bins/win32.exe` to your windows machine
# start frida-sever on your windows machine,  with command `frida-server -l 0.0.0.0`
# start `win32.exe` on your windows machine.
make run_win32
```
