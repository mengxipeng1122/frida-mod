#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this python script try to convert a object file to a module for frida

import os
import struct
import lief
import argparse
from jinja2 import Template
from utils import *

def handle_obj(info, binary, no_content=False):
    """
    Handles obj file format.
    Args:
        info (dict): Dictionary to store information about the PE file.
        binary (lief.PE.Binary): PE binary object.
        no_content (bool, optional): Flag to indicate whether to include the content of each section. Defaults to False.
    Returns:
        dict: Updated info dictionary.
    """
    sections = binary.sections
    #  loads
    # filter only loadable sections
    load_size = 0;
    load_addr = 0;
    loadable_sections = [sec for sec in sections if sec.has(lief.ELF.SECTION_FLAGS.ALLOC)]

    section_names = {}
    # print section names
    for section in loadable_sections:
        size            = len(section.content);
        content         = list(section.content);
        load_addr = getAlignNum(load_addr, section.alignment)
        section_names[section.name] = load_addr
        l ={
            'virtual_address'   : load_addr             , 
            'virtual_size'      : section.size          ,
            'name'              : section.name          ,
            'alignment'         : section.alignment     , 
            'file_offset'       : section.file_offset   ,
            'size'              : size                  ,
            }
        if not no_content:
            l['content_ts']   = ','.join([hex(b) for b in content]);
        load_addr += section.size
        info['loads'].append(l)
    load_size = getAlignNum(load_addr, 0x10)
    info['load_size'] = hex(load_size);

    # symbols
    for sym in binary.symbols:  
        k = sym.name
        # Check if the symbol is a function and is global
        if sym.type != lief.ELF.SYMBOL_TYPES.FUNC: continue
        if sym.binding != lief.ELF.SYMBOL_BINDINGS.GLOBAL: continue
        section_addr = section_names[sym.section.name]
        info['symbols'][k] = {'offset':hex(sym.value+section_addr)}

    # relocations
    info['patches'] = []
    for k, rel in enumerate(binary.relocations):
        if rel.section.name in [
            '.eh_frame',
        ]:
            continue
        typ             = rel.type;
        address         = rel.address
        sym_name        = rel.symbol.name
        section         = rel.section
        section_addr    = section_names[rel.section.name]
        c               = struct.unpack('i', rel.section.content[address:address+4])[0]
        if typ in [
            int(lief.ELF.RELOCATION_i386.PC32           ) ,
            int(lief.ELF.RELOCATION_i386.PLT32          ) ,
        ]:
            if sym_name in info['symbols']:
                sym_offset = info['symbols'][sym_name]['offset']
                code    = f"base.add({hex(section_addr)}).add({hex(address)}).writePointer(ptr({sym_offset}-{hex(address)}+({c})));"
            else:
                code    = f"base.add({hex(section_addr)}).add({hex(address)}).writePointer(resolveSymbol('{sym_name}', libs, syms).sub(base.add({hex(address)})).add({c}));"

        elif typ in [
            int(lief.ELF.RELOCATION_i386.GOTPC          ) ,
        ]:
            if rel.symbol.name == '_GLOBAL_OFFSET_TABLE_':
                code    = f"base.add({hex(section_addr)}).add({hex(address)}).writePointer(ptr({c}-{hex(address)}))"
            else:
                code    = f""

        elif typ in [
            int(lief.ELF.RELOCATION_i386.GOTOFF         ) ,
        ]:
            sym_section_addr = section_names[rel.symbol.section.name]
            code    = f"base.add({hex(section_addr)}).add({hex(address)}).writePointer(ptr({c}+{sym_section_addr}));"


        else:
            raise Exception(f'unhandled relocation type {typ}')
        info['patches'].append(code)

    return info;

def main():
    """
    A utility for converting a module to a TypeScript module
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="A utility for converting a object file to a TypeScript module")
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
    info = handle_obj(info, binary, args.no_content)

    # Get the path of the current module
    module_path = os.path.dirname(os.path.abspath(__file__))

    # Read the template file
    templateFn = os.path.join(module_path, 'obj2ts.jinja')
    t = Template(open(templateFn).read())

    # Render the template with the info dictionary
    s = t.render(info=info)

    # Write the rendered template to the output file
    open(args.output, 'w').write(s)

if __name__ == '__main__':
    main()

