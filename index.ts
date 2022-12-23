import { MODINFO_BASETYPE } from './modinfos/modinfobase';

import { mod as libcmodinfo } from './modinfos/libc'
import { mod as liblinux_x64info  } from './modinfos/liblinux_x64'
import { mod as liblinux_x86info  } from './modinfos/liblinux_x86'
import { mod as libarm64info  } from './modinfos/libarm64'
import { mod as libarm32info  } from './modinfos/libarm32'

const _frida_puts = new NativeCallback(function(s:NativePointer){
    console.log(s.readUtf8String());
},'void',['pointer']);

let testLibcSprintf = (modname:string)=>{
    let libc  = libcmodinfo.get(modname);
    let buff = Memory.alloc(Process.pageSize);
    libc.functions.sprintf.call(buff, Memory.allocUtf8String("%s %d"), Memory.allocUtf8String('1 + 2 ='), ptr(1+2));
    let resStr = buff.readUtf8String();
    console.log('result', resStr);
}

let testlibAdd = (lib:MODINFO_BASETYPE) =>{
    console.log(lib.name);
    // 
    let a = 2;
    let b = 3;
    lib.functions.add.hook();
    let res = lib.functions.add.call(a,b);
    lib.functions.add.unhook();
    console.log('res', res);
    if(lib.unload!=undefined) lib.unload();
}

const test_linux_x64 = ()=>{
    {
        testLibcSprintf('libc-2.31.so')
    }
    {
        let lib = liblinux_x64info.load([],{

            _frida_puts                 : _frida_puts,

            _ITM_registerTMCloneTable   : ptr(0),
            _ITM_deregisterTMCloneTable : ptr(0),
            __gmon_start__              : ptr(0),
        });
        testlibAdd(lib);
    }
}

const test_linux_x86 = ()=>{
    {
        testLibcSprintf('libc-2.31.so')
    }
    {
        let lib = liblinux_x86info.load([],{

            _frida_puts                 : _frida_puts,

            _ITM_registerTMCloneTable   : ptr(0),
            _ITM_deregisterTMCloneTable : ptr(0),
            __gmon_start__              : ptr(0),
        });
        testlibAdd(lib);
    }
}

const test_arm64 = ()=>{
    {
        testLibcSprintf('libc.so')
    }
    {
        let lib = libarm64info.load([],{

            _frida_puts                 : _frida_puts,

            _ITM_registerTMCloneTable   : ptr(0),
            _ITM_deregisterTMCloneTable : ptr(0),
            __gmon_start__              : ptr(0),
        });
        testlibAdd(lib);
    }
}

const test_arm32 = ()=>{
    {
        testLibcSprintf('libc.so')
    }
    {
        let lib = libarm32info.load([],{

            _frida_puts                 : _frida_puts,

            _ITM_registerTMCloneTable   : ptr(0),
            _ITM_deregisterTMCloneTable : ptr(0),
            __gmon_start__              : ptr(0),
            __cxa_call_unexpected       : ptr(0),
            __cxa_begin_cleanup         : ptr(0),
            __cxa_type_match            : ptr(0),
        });
        testlibAdd(lib);
    }
}




console.log("##################################################")

if (Process.arch=='x64' && Process.platform=='linux'){
    test_linux_x64();
}
else if (Process.arch=='ia32' && Process.platform=='linux') {
    test_linux_x86();
}
else if (Process.arch=='arm64' && Process.platform=='linux') {
    test_arm64();
}
else if (Process.arch=='arm' && Process.platform=='linux') {
    test_arm32();
}
else{
    throw 'unhandle test'
}

