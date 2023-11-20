#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import struct
from hexdump import *
from capstone import *
from capstone.arm64_const import *  # Import the ARM64 constants
from keystone import *
from unicorn import *
from unicorn.arm64_const import *
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

def init_uc_by_binary(binary, dummy_symbols,  base=0x10000000):
    # Check if it's ELF
    if not isinstance(binary, lief.ELF.Binary):
        raise ValueError("Not an ELF binary")

    assert isinstance(binary, lief.ELF.Binary), 'Not an ELF binary'
    assert binary.header.machine_type == lief.ELF.ARCH.AARCH64, 'Not an aarch64 binary'

    print('thumb')
    architecture = UC_ARCH_ARM64
    mode = UC_MODE_ARM
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

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


    # add .plt
    undef_symbols = [symbol for symbol in binary.symbols if symbol.binding == lief.ELF.SYMBOL_BINDINGS.GLOBAL and symbol.type == lief.ELF.SYMBOL_TYPES.NOTYPE]
    plt_syms_count = len(undef_symbols)
    info['sections']['.plt'] = {
        'address' : base+load_sz,
    }
    section_size = plt_syms_count*4;
    section_alignment = 0x10;

    for idx, symbol in enumerate(undef_symbols):
        info['symbols'][symbol.name] = {
            'address' : base+load_sz+idx*4,
            'size' : 4,
        }

    load_sz = getAlignNum(load_sz+section_size, section_alignment)

    info['loadsz']=load_sz
    uc.mem_map(base, getAlignNum(load_sz, 0x1000))
    for section in binary.sections:
        if section.flags & lief.ELF.SECTION_FLAGS.ALLOC:
            bs = bytes(section.content)
            addr= info['sections'][section.name]['address']
            uc.mem_write(addr,bs)

    # write .plt content
    for idx, symbol in enumerate(undef_symbols):
        name = symbol.name
        actual_addr = dummy_symbols[name]
        plt_addr = info['symbols'][name]['address']
        code = f"b {hex(actual_addr)}"
        print(code, hex(plt_addr))
        encoding, count = ks.asm(code, plt_addr )
        uc.mem_write(plt_addr, bytes(encoding))

    # iterate over all symbols
    for symbol in binary.symbols:
        section = symbol.section
        if section:
            if section.name in info['sections']:
                addr = info['sections'][section.name]['address']+symbol.value
                info['symbols'][symbol.name] = {
                    'address':addr,
                    'size':symbol.size,
                }

    if True:
        print('all sections')
        for k,v in info['sections'].items():
            print(k,hex(v['address']))
        print('all symbols')
        for k,v in info['symbols'].items():
            print(k, hex(v['address']))
    return uc, md, ks, info

def handle_relocation(uc, md, ks, info, binary):
    # handle relocation
    for relocation in binary.relocations:
        print(f'  Offset: {relocation.address}, Type: {relocation.type}, Symbol: {relocation.symbol.name}, addpend: {relocation.addend}')
        section = relocation.section
        section_addr =info['sections'][section.name]['address']  
        reloc_addr = section_addr + relocation.address;
        c = struct.unpack('I',uc.mem_read(reloc_addr,4))[0]
        print('relocatino address', hex(reloc_addr))
        if relocation.type in [
            int(lief.ELF.RELOCATION_AARCH64.ADR_PREL_PG_HI21),
        ]:
            sym_section_addr = info['sections'][relocation.symbol.section.name]['address'] + relocation.addend

            md.detail = True
            instructions = list(md.disasm(uc.mem_read(reloc_addr,4), reloc_addr))
            assert len(instructions) == 1
            inst = instructions[0]
            inst =  list(md.disasm(uc.mem_read(reloc_addr,4), reloc_addr))[0]
            ops = list(inst.operands)
            assert ops[-1].type == ARM64_OP_IMM
            I = ( sym_section_addr & 0xfffffc00 ) 
            asm_code = f'{inst.mnemonic}\t{",".join([inst.reg_name(r.value.reg) for r in ops[:-1]])}, #{hex(I)} '
            print(asm_code)
            encoding, count = ks.asm(asm_code, reloc_addr )
            uc.mem_write(reloc_addr, bytes(encoding))

        elif relocation.type in [
            int(lief.ELF.RELOCATION_AARCH64.ADD_ABS_LO12_NC),
        ]:
            md.detail = True
            instructions = list(md.disasm(uc.mem_read(reloc_addr,4), reloc_addr))
            assert len(instructions) == 1
            inst = instructions[0]
            inst =  list(md.disasm(uc.mem_read(reloc_addr,4), reloc_addr))[0]
            ops = list(inst.operands)
            assert ops[-1].type == ARM64_OP_IMM
            I = ( sym_section_addr & 0x3ff)
            asm_code = f'{inst.mnemonic}\t{",".join([inst.reg_name(r.value.reg) for r in ops[:-1]])}, #{hex(I)} '
            print(asm_code)
            encoding, count = ks.asm(asm_code, reloc_addr )
            uc.mem_write(reloc_addr, bytes(encoding))

        elif relocation.type in [
            int(lief.ELF.RELOCATION_AARCH64.CALL26),
        ]:
            name = relocation.symbol.name;
            plt_addr = info['symbols'][name]['address']
            encoding, count = ks.asm(f"bl {hex(plt_addr)}", reloc_addr )
            uc.mem_write(reloc_addr, bytes(encoding))

            pass
        elif relocation.type in [
            int(lief.ELF.RELOCATION_AARCH64.PREL32),
        ]:
            pass


        else:
            raise ValueError(f"Unsupported relocation type {relocation.type}")
    return uc




def enumerate_obj_file(input_file):
    binary = lief.parse(input_file)

    text_base = 0x10000000
    sp_base = 0x20000000
    dummy_funcs_base = 0x0fffa000
    dummy_funcs_size = 0x00001000

    dummy_symbols = {
        'printf' : dummy_funcs_base+0x0000,
        'puts' : dummy_funcs_base+0x0004,
        '__aeabi_unwind_cpp_pr1': dummy_funcs_base+0x0008,
    }

    mu, md, ks, info = init_uc_by_binary(binary, dummy_symbols,  base=text_base)

    mu.mem_map(dummy_funcs_base, dummy_funcs_size)
    #  don't  need to fill instruction

    handle_relocation(mu, md, ks, info, binary)

    # 
    if True:
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
        print(f'     X0: {hex(uc.reg_read(UC_ARM64_REG_X0))}')
        for k , v in dummy_symbols.items():
            # print(k,hex(v))
            if address == v:
                p = uc.reg_read(UC_ARM64_REG_X0)
                print('call ', k, hex(p),)
                print( '         =>', get_uc_string(uc,p))
                uc.reg_write(UC_ARM64_REG_PC, uc.reg_read(UC_ARM64_REG_LR))



    def hook_block(uc, address, size, user_data):
        print('>>> Block started at 0x%x, size = 0x%x' %(address, size))
     # Add the hooks
    mu.hook_add(UC_HOOK_CODE, hook_code)
    #mu.hook_add(UC_HOOK_BLOCK, hook_block)

    # perpare a stack
    mu.mem_map(sp_base, 0x1000);
    mu.reg_write(UC_ARM64_REG_SP, sp_base+0xf00);

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

