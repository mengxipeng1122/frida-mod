

let hookLevel=0;

export let increaseHookLevel =()=>{ hookLevel ++; }
export let decreaseHookLevel =()=>{ hookLevel --; }
export let getHookLevelIndentStr = ()=>{ let s =""; for(let t =0;t<hookLevel;t++) s+= hookShowIndentStr; return s;}

export const hookShowIndentStr = '  ';

export type HOOKID = null | InvocationListener;

export type MODINFO_BASETYPE = {

    unload? : ()=>void;

    name    : string, 

    base    : NativePointer,

    cave?   : NativePointer,

    symbols : {[key:string]:NativePointer},

    hookids : {[key:string]:null | InvocationListener},

    functions : {[key:string]:{

        hook:Function,

        unhook:Function,

        call:Function,

    }},

    variables : {},

};

//////////////////////////////////////////////////
// base data type access functions
export let p2U32        = (p:NativePointer):number =>{ return p.toUInt32(); }
export let p2S32        = (p:NativePointer):number =>{ return p.toInt32();  }
export let p2Pointer    = (p:NativePointer):NativePointer =>{ return p;     }

export let getU8        = (p:NativePointer):number =>{ return p.readU8();   }
export let getU16       = (p:NativePointer):number =>{ return p.readU16();  }
export let getU32       = (p:NativePointer):number =>{ return p.readU32();  }

export let getS8        = (p:NativePointer):number =>{ return p.readS8();   }
export let getS16       = (p:NativePointer):number =>{ return p.readS16();  }
export let getS32       = (p:NativePointer):number =>{ return p.readS32();  }
export let getPointer   = (p:NativePointer):NativePointer =>{ return p.readPointer();}

export let getString =  (p:NativePointer):string =>{ 
    if(p.isNull())return '';
    try{
        let s =  p.readUtf8String();
        if(s==null) throw Error(`can not read string from ${p}`);
        return s;
    }
    catch(error){
        console.log('read utf8string failed');
        return "";
    }
}

export let setU8   = (p:NativePointer,v:number) =>{ p.writeU8(v);}
export let setU16  = (p:NativePointer,v:number) =>{ p.writeU16(v);}
export let setU32  = (p:NativePointer,v:number) =>{ p.writeU32(v);}

export let setS8   = (p:NativePointer,v:number) =>{ p.writeS8(v);}
export let setS16  = (p:NativePointer,v:number) =>{ p.writeS16(v);}
export let setS32  = (p:NativePointer,v:number) =>{ p.writeS32(v);}
export let setPointer  = (p:NativePointer, v:NativePointer) =>{ p.writePointer(v);}

export let setString =  (p:NativePointer,v:string) =>{ 
    p.writeUtf8String(v)
}

export let getStringWithPointer =  (p:NativePointer):string =>{ 
    if(p.isNull())return '';
    let pp = p.readPointer();
    if(pp.isNull()) return '';
    try{
        let s =  pp.readUtf8String();
        if(s==null) throw Error(`can not read string from ${p}`);
        return s;
    }
    catch(e){
        console.log(e)
        return ''
    }
};

export let resolveSymbol = (name:string, libs?:(MODINFO_BASETYPE|string)[], syms?:{[key:string]:NativePointer}):NativePointer=>{
    if(syms!=undefined){
        if(Object.keys(syms).indexOf(name)>=0){
            return syms[name];
        }
    }
    if(libs!=undefined) {
        for(let t = 0; t<libs.length; t++){
            const lib = libs[t];
            if(typeof(lib)=='string'){
                let ret:NativePointer|null = null;
                Process.getModuleByName(lib)
                    .enumerateExports()
                    .forEach(e=>{
                        if(ret != null) return;
                        if(e.name == name){ ret = e.address; }
                    })
                if(ret!=null) return ret;
                Process.getModuleByName(lib)
                    .enumerateSymbols()
                    .forEach(e=>{
                        if(ret != null) return;
                        if(e.name == name){ ret = e.address; }
                    })
                if(ret!=null) return ret;
                ret = Module.findExportByName(lib,name);
                if(ret!=null) return ret;
            }
            else{
                let e = Module.findExportByName(lib.name, name);
                if(e!=null) return e;
                if(name in lib.symbols) return lib.symbols[name];
            }
        }
    }
    {
        let e = Module.findExportByName(null, name);
        if(e!=null) return e;
    }
    throw Error(`can not resolve symbol ${name}`);
}

export let readFileData = (fpath:string, sz:number, offset?:number):ArrayBuffer =>{
    offset = offset ?? 0;
    let platform = Process.platform;
    if (platform=='linux'){
        let fopen = new NativeFunction(Module.getExportByName(null,'fopen' ),'pointer', ['pointer','pointer']);
        let fseek = new NativeFunction(Module.getExportByName(null,'fseek' ),'int'    , ['pointer','long','int']);
        let fclose= new NativeFunction(Module.getExportByName(null,'fclose'),'int',     ['pointer',]);
        let fread = new NativeFunction(Module.getExportByName(null,'fread' ),'size_t',  ['pointer','size_t','size_t','pointer']);
        let buf = Memory.alloc(sz);
        let SEEK_SET = 0;
        let SEEK_CUR = 1;
        let SEEK_END = 2;

        let fp = fopen(Memory.allocUtf8String(fpath), Memory.allocUtf8String('rb'));
        if(fp.isNull()){ throw new Error(`open ${fpath} failed`); }
        fseek(fp, offset, SEEK_SET);
        let read = fread(buf, 1, sz, fp);
        if(read.toNumber()!=sz){ console.log(`error at read file ${fpath}, ${read}/${sz}`); }
        let ab = buf.readByteArray(sz);
        if(ab==null){throw new Error(`read byte array failed when read file ${fpath}`);}
        fclose(fp);
        return ab;
    }
    else{
        throw new Error(`unhandled platform ${platform}`);
    }
}
