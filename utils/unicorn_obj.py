#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct
from hexdump import *
from capstone import *
from keystone import *
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
import lief
import argparse
from utils import *

def disembly_instructions(uc, md, address, size):
    CODE = uc.mem_read(address, size)
    for i in md.disasm(CODE, address):  # disassemble the code at address 0x1000
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)) 

def get_uc_string(uc, addres, maxlen=0x30):
    bs=uc.mem_read(addres, maxlen).split(b'\0',1)[0];
    hexdump(bs)
    return bs.decode('utf-8')

def init_uc_by_binary(binary, base=0x10000000):
    # Check if it's ELF
    if not isinstance(binary, lief.ELF.Binary):
        raise ValueError("Not an ELF binary")


    if binary.header.machine_type == lief.ELF.ARCH.i386:
        print('i386')
        architecture = UC_ARCH_X86
        mode = UC_MODE_32
        md = Cs(CS_ARCH_X86, CS_MODE_32) 
        ks = Ks(KS_ARCH_X86, KS_MODE_32)

    elif binary.header.machine_type == lief.ELF.ARCH.x86_64:
        print('x86_64')
        architecture = UC_ARCH_X86
        mode = UC_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        ks = Ks(KS_ARCH_X86, KS_MODE_64)

    elif binary.header.machine_type == lief.ELF.ARCH.ARM:
        print('ARM')
        architecture = UC_ARCH_ARM
        mode = UC_MODE_ARM
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)

    elif binary.header.machine_type == lief.ELF.ARCH.ARM64:
        print('ARM64')
        architecture = UC_ARCH_ARM64
        mode = UC_MODE_ARM
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        ks = Ks(KS_ARCH_ARM64, KS_MODE_ARM)

    else:
        raise ValueError("Unsupported machine type")

    uc = unicorn.Uc(architecture, mode)
    # calculate the total load size
    load_sz=0;
    info = {'sections' : {}, "symbols":{}}
    for section in binary.sections:
        if section.flags & lief.ELF.SECTION_FLAGS.ALLOC:
            info['sections'][section.name] = {
                'address' : base+load_sz,
            }
            load_sz = getAlignNum(load_sz+section.size, section.alignment)

    info['loadsz']=load_sz
    uc.mem_map(base, getAlignNum(load_sz, 0x1000))
    for section in binary.sections:
        if section.flags & lief.ELF.SECTION_FLAGS.ALLOC:
            bs = bytes(section.content)
            addr= info['sections'][section.name]['address']
            uc.mem_write(addr,bs)

    # iterate over all symbols
    for symbol in binary.symbols:
        section = symbol.section
        if section:
            addr = info['sections'][section.name]['address']+symbol.value
            info['symbols'][symbol.name] = {
                'address':addr,
                'size':symbol.size,
            }

    if False:
        print('all sections')
        for k,v in info['sections'].items():
            print(k,hex(v['address']))
        print('all symbols')
        for k,v in info['symbols'].items():
            print(k, hex(v))
    return uc, md, ks, info

def handle_relocation_x86(uc, info, binary):
    # handle relocation
    for relocation in binary.relocations:
        print(f'  Offset: {relocation.address}, Type: {relocation.type}, Symbol: {relocation.symbol.name}, addpend: {relocation.addend}')
        section = relocation.section
        section_addr =info['sections'][section.name]['address']  
        reloc_addr = section_addr + relocation.address;
        c = struct.unpack('i',uc.mem_read(reloc_addr,4))[0]
        print('relocatino address', hex(reloc_addr))
        if relocation.type in [
            int(lief.ELF.RELOCATION_i386.PC32),
            int(lief.ELF.RELOCATION_i386.PLT32),
        ]:
            sym_section_addr = info['symbols'][relocation.symbol.name]['address']
            uc.mem_write(reloc_addr, struct.pack('i', sym_section_addr-reloc_addr+c))
        elif relocation.type in [
            int(lief.ELF.RELOCATION_i386.GOTPC),
        ]:
            if relocation.symbol.name == '_GLOBAL_OFFSET_TABLE_':
                uc.mem_write(reloc_addr,struct.pack('i',c-reloc_addr))
                pass
        elif relocation.type in [
            int(lief.ELF.RELOCATION_i386.GOTOFF),
        ]:
            sym_addr = info['symbols'][relocation.symbol.name]
            sym_section_addr = info['sections'][relocation.symbol.section.name]['address']
            reloc_section_addr = info['sections'][relocation.section.name]['address']
            print('relocaltion.section.address', hex(sym_section_addr))
            uc.mem_write(reloc_addr,struct.pack('i', sym_section_addr+c))
        else:
            raise ValueError(f"Unsupported relocation type {relocation.type}")
    return uc


def handle_relocation_x64(uc, info, binary):
    # handle relocation
    for relocation in binary.relocations:
        print(f'  Offset: {relocation.address}, Type: {relocation.type}, Symbol: {relocation.symbol.name}, addpend: {relocation.addend}')
        section = relocation.section
        section_addr =info['sections'][section.name]['address']  
        reloc_addr = section_addr + relocation.address;
        c = struct.unpack('i',uc.mem_read(reloc_addr,4))[0]
        print('relocatino address', hex(reloc_addr))
        if relocation.type in [
            int(lief.ELF.RELOCATION_X86_64.PC32),
        ]:
            sym_addr=info['symbols'][relocation.symbol.name]['address']
            sym_addr+=relocation.addend
            sym_section_addr = info['sections'][relocation.symbol.section.name]['address']
            uc.mem_write(reloc_addr,struct.pack('i', sym_addr-reloc_addr))

        elif relocation.type in [
            int(lief.ELF.RELOCATION_X86_64.PLT32),
        ]:
            sym_addr = info['symbols'][relocation.symbol.name]['address']
            sym_addr += relocation.addend
            uc.mem_write(reloc_addr,struct.pack('i', sym_addr-reloc_addr))


        else:
            raise ValueError(f"Unsupported relocation type {relocation.type}")
    return uc


def handle_relocation_arm32(uc, info, binary):
    # handle relocation
    for relocation in binary.relocations:
        print(f'  Offset: {relocation.address}, Type: {relocation.type}, Symbol: {relocation.symbol.name}, addpend: {relocation.addend}')
        section = relocation.section
        section_addr =info['sections'][section.name]['address']  
        reloc_addr = section_addr + relocation.address;
        c = struct.unpack('i',uc.mem_read(reloc_addr,4))[0]
        print('relocatino address', hex(reloc_addr))
        if relocation.type in [
        ]:
            sym_addr = info['symbols'][relocation.symbol.name]
            sym_section_addr = info['sections'][relocation.symbol.section.name]['address']
            reloc_section_addr = info['sections'][relocation.section.name]['address']
            print('relocaltion.section.address', hex(sym_section_addr))
            uc.mem_write(reloc_addr,struct.pack('i', sym_section_addr+c))
        else:
            raise ValueError(f"Unsupported relocation type {relocation.type}")
    return uc

def handle_relocation_arm64(uc, info, binary):
    # handle relocation
    for relocation in binary.relocations:
        print(f'  Offset: {relocation.address}, Type: {relocation.type}, Symbol: {relocation.symbol.name}, addpend: {relocation.addend}')
        section = relocation.section
        section_addr =info['sections'][section.name]['address']  
        reloc_addr = section_addr + relocation.address;
        c = struct.unpack('i',uc.mem_read(reloc_addr,4))[0]
        print('relocatino address', hex(reloc_addr))
        if relocation.type in [
        ]:
            sym_addr = info['symbols'][relocation.symbol.name]
            sym_section_addr = info['sections'][relocation.symbol.section.name]['address']
            reloc_section_addr = info['sections'][relocation.section.name]['address']
            print('relocaltion.section.address', hex(sym_section_addr))
            uc.mem_write(reloc_addr,struct.pack('i', sym_section_addr+c))
        else:
            raise ValueError(f"Unsupported relocation type {relocation.type}")
    return uc



def enumerate_obj_file(input_file):
    binary = lief.parse(input_file)

    text_base = 0x10000000
    sp_base = 0x20000000
    dummy_funcs_base = 0x30000000

    mu, md, ks, info = init_uc_by_binary(binary, base=text_base)

    mu.mem_map(dummy_funcs_base, 0x10000000)
    dummy_symbols = {
        'printf' : dummy_funcs_base+0x50000,
        'puts' : dummy_funcs_base+0x50010,
    }
    for k, v in dummy_symbols.items():
        info['symbols'][k] = {'address':v, 'size':0}
        encoding, count = ks.asm("ret")
        mu.mem_write(v,bytes(encoding))


    if binary.header.machine_type == lief.ELF.ARCH.i386:
        print('i386')
        handle_relocation_x86(mu, info, binary)

    elif binary.header.machine_type == lief.ELF.ARCH.x86_64:
        print('x86_64')
        handle_relocation_x64(mu, info, binary)

    elif binary.header.machine_type == lief.ELF.ARCH.ARM:
        print('ARM')
        handle_relocation_arm32(mu, info, binary)

    elif binary.header.machine_type == lief.ELF.ARCH.ARM64:
        print('ARM64')
        handle_relocation_arm64(mu, info, binary)

    else:
        raise ValueError("Unsupported machine type")


    # 
    if False:
        print('dump assemble')
        for section in binary.sections:
            if section.name in info['sections']:
                addr = info['sections'][section.name]['address']
                if section.size>0:
                    disembly_instructions(mu, md, addr, section.size)
    
    # The hook handlers
    def hook_code(uc, address, size, user_data):
        print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
        disembly_instructions(uc, md, address, size)
        for k , v in dummy_symbols.items():
            if address == v:
                if binary.header.machine_type == lief.ELF.ARCH.i386:
                    p = uc.reg_read(UC_X86_REG_EAX)
                elif binary.header.machine_type == lief.ELF.ARCH.x86_64:
                    p = uc.reg_read(UC_X86_REG_RAX)
                else:
                    raise ValueError(f"Unsupported machine type {binary.header.machine_type}")
                print('call ', k, hex(p),)
                print( '         =>', get_uc_string(uc,p))



    def hook_block(uc, address, size, user_data):
        print('>>> Block started at 0x%x, size = 0x%x' %(address, size))
     # Add the hooks
    mu.hook_add(UC_HOOK_CODE, hook_code)
    #mu.hook_add(UC_HOOK_BLOCK, hook_block)

    # perpare a stack
    mu.mem_map(sp_base, 0x1000);
    mu.reg_write(UC_X86_REG_ESP, sp_base+0xf00);

    print(info)
    # emulate code in infinite time & unlimited instructions
    ADDRESS=info['symbols']['test0']['address']
    SIZE   =info['symbols']['test0']['size']
    mu.emu_start(ADDRESS, ADDRESS+SIZE-1, count=100);

def main():

    # Create the parser
    parser = argparse.ArgumentParser(description='This is an emulator for a .o file')

    # Add the arguments
    parser.add_argument('input_file', nargs='?', help='Input file name', default='./utils/testcc.o')

    # Execute the parse_args() method
    args = parser.parse_args()

    enumerate_obj_file(args.input_file)


    pass

if __name__ == '__main__':
    main()

