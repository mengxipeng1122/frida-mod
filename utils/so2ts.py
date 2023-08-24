#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this python script try to convert a object file to a module for frida

import os
import lief
import argparse
from jinja2 import Template
from utils import *

def handle_ELF(info, binary, no_content=False):
    """
    Handles ELF information and returns the updated 'info' dictionary.
    Args:
        info (dict): Dictionary containing ELF information.
        binary: The ELF binary object.
        no_content (bool, optional): Flag to indicate whether to include content in the 'info' dictionary. Defaults to False.
    Returns:
        dict: Updated 'info' dictionary.
    """
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
            l['content_ts']   = ','.join([hex(b) for b in content]);
        info['loads'].append(l)
        sz = getAlignNum(virtual_address+virtual_size, alignment)
        load_size = max(sz, load_size)
    info['load_size'] = hex(load_size);

    if(len(load_segments)>0):
        text_segment = load_segments[0]
        info['cave_offset'] = text_segment.virtual_address + text_segment.virtual_size

    # symbols
    for sym in binary.exported_symbols:
        k = sym.name
        if sym.value==0: continue
        if sym.type==lief.ELF.SYMBOL_TYPES.NOTYPE: continue
        info['symbols'][k] = {'offset':hex(sym.value)}
    # relocations
    info['patches'] = []
    for k, rel in enumerate(binary.relocations):
        typ         = rel.type;
        address     = rel.address
        sym_name    = rel.symbol.name
        if typ in [
            int(lief.ELF.RELOCATION_ARM.RELATIVE     ) ,
            int(lief.ELF.RELOCATION_i386.RELATIVE    ) ,
            int(lief.ELF.RELOCATION_AARCH64.RELATIVE ) ,
            int(lief.ELF.RELOCATION_X86_64.R64       ) ,
        ]:
            code = f'base.add({hex(address)}).writePointer(base.add({hex(address)}).readPointer().add(base));'

        elif typ in [
            int(lief.ELF.RELOCATION_ARM.GLOB_DAT        ) ,
            int(lief.ELF.RELOCATION_AARCH64.JUMP_SLOT   ) ,
            int(lief.ELF.RELOCATION_AARCH64.ABS64       ) ,
            int(lief.ELF.RELOCATION_AARCH64.GLOB_DAT    ) ,
            int(lief.ELF.RELOCATION_ARM.JUMP_SLOT       ) ,
            int(lief.ELF.RELOCATION_ARM.ABS32           ) ,
            int(lief.ELF.RELOCATION_ARM.REL32           ) ,
            int(lief.ELF.RELOCATION_i386.JUMP_SLOT      ) ,
            int(lief.ELF.RELOCATION_i386.GLOB_DAT       ) ,
        ]:
            # try to found symbol
            found_sym = sym_name in info['symbols'];
            if not found_sym:
                if binary.has_symbol(sym_name):
                    sym = binary.get_symbol(sym_name)
                    if sym.type!=lief.ELF.SYMBOL_TYPES.NOTYPE \
                       and sym.value!=0:
                       info['symbols'][sym_name] = {'offset':hex(sym.value)}
                       found_sym = True;
            if found_sym: 
                offset  = info['symbols'][sym_name]['offset']
                address = address if isinstance(address, str) else hex(address)
                code    = f'base.add({address}).writePointer(base.add({offset}));'
            else:
                code    = f"base.add({hex(address)}).writePointer(resolveSymbol('{sym_name}', libs, syms));"
        else:
            raise Exception(f'unhandled relocation type {typ}')
        info['patches'].append(code)

    # init codes
    info['inits'] = [hex(f.address) for f in binary.ctor_functions]

    # deinit codes
    info['deinits'] = [hex(f.address) for f in binary.dtor_functions]

    return info;

def handle_PE(info, binary, no_content=False):
    """
    Handles PE file format.
    Args:
        info (dict): Dictionary to store information about the PE file.
        binary (lief.PE.Binary): PE binary object.
        no_content (bool, optional): Flag to indicate whether to include the content of each section. Defaults to False.
    Returns:
        dict: Updated info dictionary.
    """
    #  loads
    image_base      = binary.optional_header.imagebase;
    sizeof_image    = binary.optional_header.sizeof_image;
    load_size       = sizeof_image
    for section in binary.sections:
        virtual_address = section.virtual_address;
        virtual_size    = section.virtual_size;
        alignment       = 0x100; 
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
    info['load_size'] = hex(load_size);
    #TODO
    info['cave_offset'] = 0;

    ########################################
    #patches
    patches=[]
    # base relocation
    for t, reloc in enumerate(binary.relocations):
        virtual_address = reloc.virtual_address;
        for tt, entry in enumerate(reloc.entries):
            typ     = entry.type
            address = entry.address;
            if typ == lief.PE.RELOCATIONS_BASE_TYPES.ABSOLUTE: pass
            elif typ == lief.PE.RELOCATIONS_BASE_TYPES.DIR64: pass
            elif typ == lief.PE.RELOCATIONS_BASE_TYPES.HIGHLOW:
                code = f'base.add({hex(address)}).writePointer(base.add({hex(address)}).readPointer().add(base.sub({hex(image_base)})));'
                patches.append(code)
            else:
                raise Exception(f'unhandled PE relocation type {typ}' )

    # imports
    for t, imp in enumerate(binary.imports):
        for tt,  entry in enumerate(imp.entries):
            address     = entry.iat_address;
            sym_name    = entry.name;
            code        = f"base.add({hex(address)}).writePointer(resolveSymbol('{sym_name}', libs, syms));"
            patches.append(code)
    info['patches'] = patches

    return info;

def main():
    """
    A utility for converting a module to a TypeScript module
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="A utility for converting a module to a TypeScript module")
    parser.add_argument('-b', "--binary", type=str, required=True, help='path to the binary file')
    parser.add_argument('-o', '--output', default='/tmp/tt.ts', help='path to the output file')
    parser.add_argument('-n', '--name', type=str, help='set module name')
    parser.add_argument('--no-content', action='store_true', default=False, help='flag to exclude content')

    args = parser.parse_args()

    # Print command line arguments
    print(args)

    # Initialize info dictionary
    info = {
        'no_content'    : args.no_content,
        'mode'          : 'load',
        'name'          : args.name or os.path.basename(args.binary),
        'symbols'       : {},
        'binary'        : None,
        'load_size'     : hex(0),
        'loads'         : [],
        'relocations'   : [],
    }

    # Parse the binary file
    binary = lief.parse(args.binary)
    info['binary'] = binary

    # Handle different binary formats
    if binary.format == lief.EXE_FORMATS.PE:
        info = handle_PE(info, binary, args.no_content)
    elif binary.format == lief.EXE_FORMATS.ELF:
        info = handle_ELF(info, binary, args.no_content)

    # Get the path of the current module
    module_path = os.path.dirname(os.path.abspath(__file__))

    # Read the template file
    templateFn = os.path.join(module_path, 'so2ts.jinja')
    t = Template(open(templateFn).read())

    # Render the template with the info dictionary
    s = t.render(info=info)

    # Write the rendered template to the output file
    open(args.output, 'w').write(s)

if __name__ == '__main__':
    main()

