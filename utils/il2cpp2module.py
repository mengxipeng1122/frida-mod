#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import json
import os
from jinja2 import Template
import re

MAX_VARS = 10

def getFridaType(typ):
    if typ.find('*')>0  : return 'pointer'
    if typ=='void'      : return 'void'
    return 'uint'

def getTSType(typ):
    if typ.find('*')>0  : return 'NativePointer'
    if typ=='void'      : return 'void'
    return 'number'

def parseSignature(signature):
    function_name = signature.split('(')[0].split()[-1]
    # Extract return type
    return_type = ' '.join(signature.split('(')[0].split()[:-1])

    # Extract argument types and names
    args_str = signature.split('(')[-1].split(')')[0].split(',')
    args=[]
    for arg_str  in args_str:
        arg_type = ' '.join(arg_str.strip().split()[:-1])
        arg_name = arg_str.strip().split()[-1]
        args.append({
            'type'      : arg_type,
            'frida_type': getFridaType(arg_type),
            'ts_type'   : getTSType(arg_type),
            'name'      : arg_name,
        })
    if len(args)>0 and args[-1]['name']=='method': args=args[:-1]
    if len(args)>0 and args[0]['name']=='__this' and not args[0]['type'].endswith('*'): 
        args[0]['type'] += ' *'
    return {
        'name'          :function_name,
        'retType'       :return_type,
        'args'          :args,
    }

def args2GetFun(t):
    if t == 'uint' : return 'p2U32';
    return None;

def getFunSaveArgsCode  (info, is_variadic=False):
    ret = []
    for t, arg in enumerate(info):
        if arg['name']!='':
            ret.append(f'this.{arg["name"]} = args[{t}];')
        else:
            ret.append(f'this.args{t} = args[{t}];')
    if is_variadic: 
        for t in range(MAX_VARS):
            ret.append(f'this.targs{t} = args[{t+len(info)}];')
    return ret;

def getFunShowArgsCode  (info, is_variadic=False):
    ret = []
    for t, arg in enumerate(info):
        name = arg['name']
        getFun = args2GetFun(arg['frida_type'])
        getValCode = ""
        if name!='':
            c = f'"{name} =","[", this.{name},"]"'
            if getFun!=None: c+=f',{getFun}(this.{name})'
        else:
            c = f'"args{t} =","[", this.args{t},"]"'
            if getFun!=None: c+=f',{getFun}(this.args{t})'
        ret.append(c);
    if is_variadic:
        for t in range(MAX_VARS):
            ret.append(f'"targs[t] =", this.targs{t}');
    return ret;

def getFunThisNames     (info, is_variadic=False):
    ret = []
    for t, arg in enumerate(info):
        name = arg['name']
        if name!='':
            ret.append(f'this.{name}')
        else:
            ret.append(f'this.args{t}')
    if is_variadic:
        for t in range(MAX_VARS):
            ret.append(f'this.targs{t}');
    return ret;


def getFunctionsInfo(jsonfn, fun_list=None):
    funcions=[]
    for item in json.load(open(jsonfn))['ScriptMethod']:
        Signature       = item['Signature'      ]
        TypeSignature   = item['TypeSignature'  ]
        Address         = item['Address'        ]
        Name            = item['Name'           ]

        if fun_list:
            found=False
            for f in fun_list:
                if  Name.find(f)>=0:
                    found=True
            if not found : continue

        signInfo = parseSignature(Signature)
        funcions.append({
            'name'              :f'{signInfo["name"]}_{hex(Address)}',
            'address'           : hex(Address),
            'signature'         : Signature,
            'frida_names'       : [   t["name"]                  for t in signInfo['args']],
            'this_names'        : getFunThisNames(signInfo['args']),
            'ts_args'           : [f'{t["name"]}:{t["ts_type"]}' for t in signInfo['args']],
            'frida_args'        : [f"\'{t['frida_type']}\'" for t in signInfo['args']],
            'c_args'            : [f'{t["type"]} {t["name"]}' for t in signInfo['args']],
            'ts_ret'            : getTSType(signInfo['retType']),
            'frida_ret'         : getFridaType(signInfo['retType']),
            'c_ret'             : signInfo['retType'],
            'is_void'           : signInfo['retType']=='void',
            'save_args_code'    : getFunSaveArgsCode  (signInfo['args']),
            'show_args_code'    : getFunShowArgsCode  (signInfo['args']),
        })
    return funcions

def main():
    parser = argparse.ArgumentParser(description='Convert libil2cpp.so to TS module')
    parser.add_argument('outputfn', type=str, help='output TS module file')
    parser.add_argument('-J', '--script-json', type=str, help='path to the script.json', required=True)
    parser.add_argument('-C', '--comments', action='store_false', default=True)
    parser.add_argument('-H', '--header-file' )
    parser.add_argument('--fun', '-f', nargs='+', default=[], action='append')

    args = parser.parse_args()
    fun_list = sum(args.fun, [])

    print(args)
    comments = args.comments
    if len(fun_list) > 0: comments=False

    info ={
        'MAX_VARS' : MAX_VARS,
        'comments' : comments,
        'name'     : 'libil2cpp.so',
        'functions': getFunctionsInfo(args.script_json, fun_list),
    }

    module_path = os.path.dirname(os.path.abspath(__file__))
    templateFn = os.path.join(module_path, 'il2cpp2ts.jinja')
    t = Template(open(templateFn).read())
    s = t.render( info = info);
    open(args.outputfn,'w').write(s)

    if args.header_file:
        templateFn = os.path.join(module_path, 'il2cpp2h.jinja')
        t = Template(open(templateFn).read())
        s = t.render( info = info);
        open(args.header_file,'w').write(s)



if __name__ == '__main__':
    main()
