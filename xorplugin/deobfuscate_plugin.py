# coding=utf-8
#!/bin/python3
# 这个插件用来去掉Equation的xor系列混淆
# 仅仅支持python 3，只在ida pro 7.7下测试过
# 将本文件放到IDA安装目录的plugins目录下，然后启动ida，在ida View中把光标放在解码函数开始，就可以在 Edit->Plugings->Xor Batch Deobfuscation
# 也可以使用快捷键Ctrl+Shift+D进行反混淆

import sys
try:
    import idaapi
    import idc
    import idautils
    import flare_emu
    # import hexdump
except ImportError:
    print("[FlareDeobfacatePlugin] Dependencies missing, Please check ida python and flare_emu is installed")
    sys.exit()

VERSION = "0.1.0"


def deobfuscate_function():
    # for xref in idautils.XrefsTo(idc.get_screen_ea(), 0):
               # print(xref.type, idautils.XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
    eh = flare_emu.EmuHelper()

    info = idaapi.get_inf_structure()
    if info.is_64bit():
        dx = "rdx"
        ax = "rax"
    else:
        dx = "edx"
        ax = "eax"


    ea = idc.get_screen_ea()
    for xref in idautils.XrefsTo(ea, 0):
        addr_call = xref.frm
        addr_before = idc.prev_head(addr_call) # 前一个指令
        addr_before = idc.prev_head(addr_before) # 前一个指令
        addr_after = idc.next_head(addr_call) # 后一个指令
        # 校验前一个指令是在传参，符合 mov eax, xxx
        if idc.print_insn_mnem(addr_before) == "mov" and idc.print_operand(addr_before, 0) == dx:
            #print("0x{:x} => 0x{:x}".format(addr_before, addr_call))
            eh.emulateRange(addr_before, endAddr=addr_after, skipCalls=False)
            ret = eh.getRegVal( ax )
            print( "decrypted at 0x%x: %s" %( addr_call ,eh.getEmuString(ret) ))
            # 设置注释
            idc.set_cmt(addr_call, "decrypted: " + eh.getEmuString(ret).decode(), 0)

    print ("Deobfuscated")


class XorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Equation 字符串反混淆"
    help = "一个小工具，用于反混淆Equation的字符串混淆"
    wanted_name = "Xor Batch Deobfuscation"
    # wanted_hotkey = "Ctrl+Shift+D"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        deobfuscate_function()


def PLUGIN_ENTRY():
    return XorPlugin()
