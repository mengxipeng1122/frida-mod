

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
export let p2U32        = (p:NativePointer):number =>{ return p.toUInt32();}
export let p2S32        = (p:NativePointer):number =>{ return p.toInt32();}
export let p2Pointer    = (p:NativePointer):NativePointer =>{ return p;}

export let getU8   = (p:NativePointer):number =>{ return p.readU8();}
export let getU16  = (p:NativePointer):number =>{ return p.readU16();}
export let getU32  = (p:NativePointer):number =>{ return p.readU32();}

export let getS8   = (p:NativePointer):number =>{ return p.readS8();}
export let getS16  = (p:NativePointer):number =>{ return p.readS16();}
export let getS32  = (p:NativePointer):number =>{ return p.readS32();}
export let getPointer  = (p:NativePointer):NativePointer =>{ return p.readPointer();}

export let getString =  (p:NativePointer):string =>{ 
    if(p.isNull())return '';
    let s =  p.readUtf8String();
    if(s==null) throw Error(`can not read string from ${p}`);
    return s;
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
                let e = Module.findExportByName(lib, name);
                if(e!=null) return e;
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
