
import { mod as libcmodinfo } from './modinfos/libc'

let testLibcSprintf = (modname:string)=>{
    let libc  = libcmodinfo.get(modname);
    let buff = Memory.alloc(Process.pageSize);
    libc.functions.sprintf.call(buff, Memory.allocUtf8String("%s %d"), Memory.allocUtf8String('1 + 2 ='), ptr(1+2));
    let resStr = buff.readUtf8String();
    console.log('result', resStr);

}

const test_linux_x64 = ()=>{
    testLibcSprintf('libc-2.31.so')
}


console.log("##################################################")

if (Process.arch=='x64' && Process.platform=='linux'){
    test_linux_x64();
}

