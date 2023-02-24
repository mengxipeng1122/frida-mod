#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this python script try to compile c source code to a object file and output for using of frida
# only support 32bit, ARM/thumb so far

import os
import lief
import json
import argparse
from jinja2 import Template
from utils import *

from clang.cindex import Index, CursorKind, TypeKind

MAX_VARS=10

def fixFunctionName(n):
    n = n.replace(' ','_')
    n = n.replace('!','_')
    n = n.replace('~','_')
    n = n.replace('=','_')
    n = n.replace(':','_')
    n = n.replace('[]','')
    return n;

def fixArugmentName(n):
    n = n.replace(':','_')
    return n;

def preprocessType(t):
    t=t.replace('const','')
    t=t.strip();
    return t;

def type2Frida(t):
    t = preprocessType(t)
    if t =='int'            : return "int";
    if t =='bool'           : return "int";
    if t =='unsigned long'  : return "uint";
    if t =='void'           : return "void";
    if t =='unsigned int'   : return "uint";
    if t =='long'           : return "int";
    if t =='long long'      : return "int";
    if t =='double'         : return "pointer";
    if t.find('*')>=0       : return 'pointer';
    #print(f'unhandled type {t}')
    return 'pointer'

def type2TypeScriptForCall(t):
    t = type2Frida(t)
    if t =="int"           : return 'number';
    if t =="uint"          : return 'number';
    if t =="void"          : return 'void';  
    if t =="pointer"       : return 'NativePointer';
    raise Exception(f'unhandled type {t}')


def args2GetFun(t):
    t = preprocessType(t)
    if t == 'char *'        : return 'getString';
    if t == 'unsigned char' : return 'p2U32';
    if t == 'unsigned short': return 'p2U32';
    if t == 'unsigned int'  : return 'p2U32';
    if t == 'char'          : return 'p2S32';
    if t == 'short'         : return 'p2S32';
    if t == 'int'           : return 'p2S32';
    return None;

def type2GetFunForCall(t):
    t = preprocessType(t)
    if t == 'char *'        : return 'getStringWithPointer';
    if t == 'unsigned char' : return 'getU8';
    if t == 'unsigned short': return 'getU16';
    if t == 'unsigned int'  : return 'getU32';
    if t == 'char'          : return 'getS8';
    if t == 'short'         : return 'getS16';
    if t == 'int'           : return 'getS32';
    return 'getPointer';


def type2TypeScript(t):
    t = preprocessType(t)
    if t =="int"           : return 'number';
    if t =="uint"          : return 'number';
    if t =="void"          : return 'void';  
    if t =="pointer"       : return 'NativePointer';
    if t =='char *'        : return 'string';
    if t =='unsigned char' : return 'number';
    if t =='unsigned short': return 'number';
    if t =='unsigned int'  : return 'number';
    if t =='char'          : return 'number';
    if t =='short'         : return 'number';
    if t =='int'           : return 'number';
    #print(f'unhandled type {t}')
    return 'NativePointer'

def getFunSaveArgsCode  (info):
    ret = []
    for t, arg in enumerate(info['arguments']):
        if arg['name']!='':
            ret.append(f'this.{arg["name"]} = args[{t}];')
        else:
            ret.append(f'this.args{t} = args[{t}];')
    if info["is_variadic"]: 
        for t in range(MAX_VARS):
            ret.append(f'this.targs{t} = args[{t+len(info["arguments"])}];')
    return ret;

def getFunShowArgsCode  (info):
    ret = []
    for t, arg in enumerate(info['arguments']):
        name = arg['name']
        getFun = args2GetFun(arg['type'])
        getValCode = ""
        if name!='':
            c = f'"{name} =","[", this.{name},"]"'
            if getFun!=None: c+=f',{getFun}(this.{name})'
        else:
            c = f'"args{t} =","[", this.args{t},"]"'
            if getFun!=None: c+=f',{getFun}(this.args{t})'
        ret.append(c);
    if info["is_variadic"]: 
        for t in range(MAX_VARS):
            ret.append(f'"targs[t] =", this.targs{t}');
    return ret;

def getFunThisNames     (info):
    ret = []
    for t, arg in enumerate(info['arguments']):
        name = arg['name']
        if name!='':
            ret.append(f'this.{name}')
        else:
            ret.append(f'this.args{t}')
    if info["is_variadic"]: 
        for t in range(MAX_VARS):
            ret.append(f'this.targs{t}');
    return ret;

def getFridaArgumentList(info):
    ret = [ f'{type2Frida(arg["type"])}' for arg in info['arguments']]
    if info["is_variadic"]: 
        for t in range(MAX_VARS):
            ret.append("'pointer'")
    return ret;

def getFunTSArgs        (info):
    ret = []
    for t, arg in enumerate(info['arguments']):
        if arg['name'] != '':
            ret.append(f' {arg["name"]}:{type2TypeScriptForCall(arg["type"])}')
        else:
            ret.append(f' arg{t}:{type2TypeScriptForCall(arg["type"])}')
    if info["is_variadic"]: ret.append('...args:NativePointer[]')
    return ret;

def getFunCArgs         (info):
    ret = [ f'{arg["type"]} {arg["name"]}' for arg in info['arguments']]
    if info["is_variadic"]: ret.append('...')
    return ret;

def getFunFridaNames    (info):
    ret = []
    for t, arg in enumerate(info['arguments']):
        if arg['name'] != '':
            ret.append(f' {arg["name"]}')
        else:
            ret.append(f' arg{t}')
    if info["is_variadic"]: 
        for t in range(MAX_VARS):
            ret.append(f'targs[{t}]')
    return ret;

def getFunFridaArgs     (info):
    ret = [ f"'{type2Frida(arg['type'])}'" for arg in info['arguments']]
    if info["is_variadic"]: 
        for t in range(MAX_VARS):
            ret.append(f"'pointer'");
    return ret;

def iterateTu(a,cb, level=0):
    cb(a) 
    for aa in a.get_children():
        iterateTu(aa, cb, level+1);

def updateAllFunctions(tu, funcs={}):
    def handleFunction(a):
        if     a.kind == CursorKind.FUNCTION_DECL  \
            or a.kind == a.kind == CursorKind.CXX_METHOD:
            res_type = a.result_type.get_canonical().spelling;
            symbolName = a.mangled_name
            funName = a.lexical_parent.spelling+'_'+a.spelling if a.kind == CursorKind.CXX_METHOD else a.spelling;
            info = {
                "is_variadic"   : a.type.is_function_variadic() if a.type.kind == TypeKind.FUNCTIONPROTO else False,
                "arguments"     : [],
                "funName"       : fixFunctionName(funName),
            }
            info['return'] = {
                'type': res_type,
                'langs': {
                    'ts'    : type2TypeScriptForCall(res_type),
                    'frida' : type2Frida(res_type),
                 }
            }
            info['is_void'         ] = res_type == 'void';
            args  = [('void *', 'pthis')] if a.kind == CursorKind.CXX_METHOD and not a.is_static_method() else []
            #if symbolName .find('CheckInput')>=0: print(args, a.kind == CursorKind)
            for aa in a.get_arguments():
                args.append( ( aa.type.get_canonical().spelling, aa.spelling) )
            for typ, name in args:
                info['arguments'].append({
                    'name' : fixArugmentName(name), 
                    'type' : typ,
                    'langs': {
                        'ts'    : type2TypeScript(typ),
                        'frida' : type2Frida(typ),
                     }
                 })
            info['ts_args'         ] = getFunTSArgs        (info)
            info['frida_names'     ] = getFunFridaNames    (info)
            info['c_args'          ] = getFunCArgs         (info)
            info['frida_args'      ] = getFunFridaArgs     (info)
            info['save_args_code'  ] = getFunSaveArgsCode  (info)
            info['show_args_code'  ] = getFunShowArgsCode  (info)
            info['this_names'      ] = getFunThisNames     (info)
            funcs[symbolName]= info
    iterateTu(tu.cursor, handleFunction);
    return(funcs)

def updateAllStructs(tu, strs={}):
    for a in tu.cursor.get_children():
        if a.kind == CursorKind.STRUCT_DECL:
            info = {
                "fields": [ ],
            }
            for  aa in a.get_children():
                if aa.kind ==  CursorKind.DESTRUCTOR: continue
                if aa.kind ==  CursorKind.CONSTRUCTOR: continue
                typ = aa.type.get_canonical().spelling;
                info['fields'].append({
                    'type' : typ,
                    'name' : fixArugmentName( aa.spelling ),
                    'langs': {
                        'ts'    : type2TypeScript(typ),
                        'frida' : type2Frida(typ),
                     },
                     'offset': aa.get_field_offsetof()//8,
                     'getFun': type2GetFunForCall(typ),
                })
            strs[a.spelling] = info
    return strs

def updateAllVariables(tu, vs={}):
    def handleVariable(a):
        if a.kind == CursorKind.VAR_DECL:
            info = {
                'type' : a.type.get_canonical().spelling,
            }
            vs[a.spelling] = info
    iterateTu(tu.cursor, handleVariable);
    return vs

def getFunctionPrototype(k,v):
    args = ','.join([f' {t["type"]} {t["name"]}' for t in v['argument']])
    if v['is_variadic']:
        args+= ', ...'
    code = f'{v["return_type"]} {k}({args});'
    return code;

def getReloctionTypeName(t):
    if t==2    : return 'R_ARM_ABS32'
    if t==3    : return 'R_ARM_REL32'
    if t==6    : return 'R_386_GLOB_DAT'
    if t==7    : return 'R_386_JUMP_SLOT'
    if t==8    : return 'R_386_RELATIVE'
    if t==21   : return 'R_ARM_GLOB_DAT'
    if t==22   : return 'R_ARM_JUMP_SLOT'
    if t==23   : return 'R_ARM_RELATIVE'
    if t==257  : return 'R_AARCH64_ABS64'
    if t==1025 : return 'R_AARCH64_GLOB_DA'
    if t==1026 : return 'R_AARCH64_JUMP_SL'
    if t==1027 : return 'R_AARCH64_RELATIVE'
    raise Exception(f'unhandled reclocation type {t}')
    
def handleELF(info, binary, no_content=False):
    #  loads
    load_size = 0;
    load_segments = [seg for seg in binary.segments if seg.type == lief.ELF.SEGMENT_TYPES.LOAD ]
    for seg in load_segments:
        virtual_address = seg.virtual_address;
        virtual_size    = seg.virtual_size;
        alignment       = seg.alignment;
        file_offset     = seg.file_offset;
        size            = len(seg.content);
        content         = list(seg.content);
        l ={
            'virtual_address'   : virtual_address , 
            'virtual_size'      : virtual_size    ,
            'alignment'         : alignment       ,
            'file_offset'       : file_offset     ,
            'size'              : size            ,
            }
        if not no_content:
            l['content_ts']           = ','.join([hex(b) for b in content]);
        info['loads'].append(l)
        sz = getAlignNum(virtual_address+virtual_size, alignment)
        load_size = max(sz, load_size)
    info['load_size'] = load_size;            
    if(len(load_segments)>0):
        text_segment = load_segments[0]
        info['cave_offset'] = text_segment.virtual_address + text_segment.virtual_size

    # symbols
    for k, v in info['functions'].items():
        if not binary.has_symbol(k):continue
        sym = binary.get_symbol(k)
        #if not sym.exported:continue
        if sym.value==0: continue
        if sym.type==lief.ELF.SYMBOL_TYPES.NOTYPE: continue
        info['symbols'][k] = {'offset':sym.value}
    for k, v in info['variables'].items():
        if not binary.has_symbol(k):continue
        sym = binary.get_symbol(k)
        #if not sym.exported:continue
        if sym.type==lief.ELF.SYMBOL_TYPES.NOTYPE: continue
        if sym.value==0: continue
        info['symbols'][k] = {'offset':sym.value}

    ########################################
    # patches
    # relocations
    info['patches'] = []
    for k, rel in enumerate(binary.relocations):
        typ         = rel.type;
        address     = rel.address
        sym_name    = rel.symbol.name
        if      typ == int(lief.ELF.RELOCATION_ARM.RELATIVE     )  \
           or   typ == int(lief.ELF.RELOCATION_i386.RELATIVE    )  \
           or   typ == int(lief.ELF.RELOCATION_AARCH64.RELATIVE )  \
           or   typ == int(lief.ELF.RELOCATION_X86_64.R64       )  :
            code = f'base.add({hex(address)}).writePointer(base.add({hex(address)}).readPointer().add(base));'

        elif typ == int(lief.ELF.RELOCATION_ARM.GLOB_DAT        ) \
          or typ == int(lief.ELF.RELOCATION_AARCH64.JUMP_SLOT   ) \
          or typ == int(lief.ELF.RELOCATION_AARCH64.ABS64       ) \
          or typ == int(lief.ELF.RELOCATION_AARCH64.GLOB_DAT    ) \
          or typ == int(lief.ELF.RELOCATION_ARM.JUMP_SLOT       ) \
          or typ == int(lief.ELF.RELOCATION_ARM.ABS32           ) \
          or typ == int(lief.ELF.RELOCATION_ARM.REL32           ) \
          or typ == int(lief.ELF.RELOCATION_i386.JUMP_SLOT      ) \
          or typ == int(lief.ELF.RELOCATION_i386.GLOB_DAT       ) :
            # try to found symbol
            foundSym = sym_name in info['symbols'];
            if not foundSym:
                if binary.has_symbol(sym_name):
                    sym = binary.get_symbol(sym_name)
                    if sym.type!=lief.ELF.SYMBOL_TYPES.NOTYPE \
                       and sym.value!=0:
                       info['symbols'][sym_name] = {'offset':sym.value}
                       foundSym = True;
            if foundSym: 
                offset = info['symbols'][sym_name]['offset']
                code = f'base.add({hex(address)}).writePointer(base.add({hex(offset)}));'
            else:
                code = f"base.add({hex(address)}).writePointer(resolveSymbol('{sym_name}', libs, syms));"
        else:
            raise Exception(f'unhandled relocation type {typ}')
        info['patches'].append(code)

    # init codes
    inits=[]
    # ctors
    for t, f in enumerate(binary.ctor_functions):
        b = f.address
        code = f"new NativeFunction(base.add({hex(b)}), 'void', [])();"
        inits.append(code)
    info['inits'] = inits

    # deinit codes
    deinits=[]
    # ctors
    for t, f in enumerate(binary.dtor_functions):
        b = f.address
        code = f"new NativeFunction(base.add({hex(b)}), 'void', [])();"
        deinits.append(code)
    info['deinits'] = deinits


    return info;

def handlePE(info, binary, no_content=False):
    #  loads
    imagebase = binary.optional_header.imagebase;
    sizeof_image = binary.optional_header.sizeof_image;
    load_size = sizeof_image
    for section in binary.sections:
        #print(section.name, section.virtual_address, section.virtual_size)
        virtual_address = section.virtual_address;
        virtual_size    = section.virtual_size;
        alignment       = 0x100; #TODO
        file_offset     = section.offset;
        size            = len (section.content);
        content         = list(section.content);
        l ={
            'virtual_address'   : virtual_address , 
            'virtual_size'      : virtual_size    ,
            'alignment'         : alignment       ,
            'file_offset'       : file_offset     ,
            'size'              : size            ,
            }
        if not no_content:
            l['content_ts']           = ','.join([hex(b) for b in content]);
        info['loads'].append(l)
    info['load_size'] = load_size;            
    #TODO
    info['cave_offset'] = 0;

    ########################################
    #patches
    patches=[]
    # base relocation
    for t, reloc in enumerate(binary.relocations):
        virtual_address = reloc.virtual_address;
        for tt, entry in enumerate(reloc.entries):
            typ = entry.type
            address = entry.address;
            #print(t, tt, typ)
            if typ == lief.PE.RELOCATIONS_BASE_TYPES.ABSOLUTE: pass
            elif typ == lief.PE.RELOCATIONS_BASE_TYPES.DIR64: pass
            elif typ == lief.PE.RELOCATIONS_BASE_TYPES.HIGHLOW:
                code = f'base.add({hex(address)}).writePointer(base.add({hex(address)}).readPointer().add(base.sub({hex(imagebase)})));'
                patches.append(code)
            else:
                #print(t,tt, entry, int(lief.PE.RELOCATIONS_BASE_TYPES.HIGHLOW), typ)
                raise Exception(f'unhandled PE relocation type {typ}' )

    # imports
    for t, imp in enumerate(binary.imports):
        for tt,  entry in enumerate(imp.entries):
            #print(dir(entry))
            #print(t, tt, entry, entry.name, entry.value, entry.iat_address, entry.iat_value, entry.ordinal if entry.is_ordinal else "erro")
            address = entry.iat_address;
            sym_name = entry.name;
            code = f"base.add({hex(address)}).writePointer(resolveSymbol('{sym_name}', libs, syms));"
            patches.append(code)

    info['patches'] = patches

    ########################################
    #  init code 
    # ctors
    #for entry in binary.dynamic_entries:
    #    if(entry.tag == lief.ELF.DYNAMIC_TAGS.INIT_ARRAY): 
    #        ctors_offset=entry.value
    #        info['ctors'] = [b for b in entry.array if b!=0]

    # symbols
    for k, v in info['functions'].items():
        if not binary.has_symbol(k):continue
        sym = binary.get_symbol(k)
        #if not sym.exported:continue
        if sym.value==0: continue
        info['symbols'][k] = {'offset':sym.value}
    for k, v in info['variables'].items():
        if not binary.has_symbol(k):continue
        sym = binary.get_symbol(k)
        #if not sym.exported:continue
        if sym.type==lief.ELF.SYMBOL_TYPES.NOTYPE: continue
        if sym.value==0: continue
        info['symbols'][k] = {'offset':sym.value}
    return info;

def main():
    parser = argparse.ArgumentParser(description="A utility for convert a module to a typescript module ")
    parser.add_argument('-b', "--binary", type=str)
    parser.add_argument('-I', "--info", type=str)
    parser.add_argument('-o', '--output', default='/tmp/tt.ts')
    parser.add_argument('-n', '--name',type=str, help='set module name' )
    parser.add_argument('-m', '--mode', default='get', nargs='?', choices=['get', 'load',], help='modes (default: %(default)s)')
    parser.add_argument('--no-content', action='store_true', default=False)
    parser.add_argument('-F', '--flags', nargs='*', type=str, default=[])
    parser.add_argument("source", type=str, nargs='+', help='source files');

    args = parser.parse_args()
    print(args)

    info = {
        'MAX_VARS' : MAX_VARS,

        'mode' : args.mode,

        'name':"",

        'symbols':{
            #  '<name>' : {'offset': <offset>,  },
         },

        'binary'        : None,

        'functions'     : {},
        
        'structs'       : {},

        'variables'     : {},

        'load_size'     : 0,

        'loads'         : [],

        'relocations'   : [],

        'ctors'         : [],
    }

    if args.binary!=None: info['name'] = os.path.basename(args.binary);
    if args.name!=None  : info['name'] = args.name
    if args.info!=None:
        jsoninfo = json.load(open(args.info));
        if 'symbols' in jsoninfo and isinstance(jsoninfo['symbols'], dict):
            info['symbols'].update(jsoninfo['symbols'])

    ##################################################
    # parse the source file 
    index = Index.create()
    for src in args.source:
        print(f'parsing {src} ... ')
        tu = index.parse(src, [f'-{b}' for b in args.flags])
        if not tu: parser.error(f"unable to load input {args.source}")
        updateAllFunctions(tu,  info['functions'])
        updateAllStructs(tu,    info['structs'  ])
        updateAllVariables(tu,  info['variables']);

    ##################################################
    # extract info from so file 
    if args.binary!=None:
        binary =  lief.parse(open(args.binary,'rb'))
        info['binary'] = binary
        if binary.format == lief.EXE_FORMATS.PE:
            info = handlePE(info, binary, args.no_content);
        elif binary.format == lief.EXE_FORMATS.ELF:
            info = handleELF(info, binary, args.no_content);

    else:
        for k, v in info['functions'].items():
            if k not in info['symbols']: info['symbols'][k] = {};
        for k, v in info['variables'].items():
            if k not in info['symbols']: info['symbols'][k] = {};

    # handle same function game
    funMap = {} # key == function name, value == list of symbol names
    for k,v in info['functions'].items():
        funName = v['funName']
        if funName not in funMap:
            funMap[funName] = [k]
        else:
            funMap[funName].append(k)
    for k,v in funMap.items():
        if len(v)>1:
            for t,symbolName in enumerate(v):
                info['functions'][symbolName]['funName']=f'{k}_{t}'
     
    # write output file
    #for k, v in info['functions'].items():
    #    if k.find('CheckInput')>=0: print(k,v)
    #json.dump(info, open('/tmp/info.json','w'))
    module_path = os.path.dirname(os.path.abspath(__file__))
    templateFn = os.path.join(module_path, 'modinfo2ts.jinja')
    t = Template(open(templateFn).read())
    s = t.render( info = info);
    open(args.output,'w').write(s)

if __name__ == '__main__':
    main()

