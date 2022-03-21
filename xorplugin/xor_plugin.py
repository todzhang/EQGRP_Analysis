# coding=utf-8
#!/bin/python3
# 这个插件用来去掉Equation的xor47混淆
# 仅仅支持python 3，只在ida pro 7.7下测试过
# 将本文件放到IDA安装目录的plugins目录下，然后启动ida，在ida View中把光标放在要解码的字符串地址上，就可以在 Edit->Plugings->Xor47 Deobfuscation
# 也可以使用快捷键Shift+D进行反混淆

import sys
try:
    import idaapi
    import idc
    import idautils
except ImportError:
    print("[XorPlugin] Dependencies missing, Please check ida python is installed")
    sys.exit()

VERSION = "0.1.0"


def get_size(addr):
  size = 0
  while(idaapi.get_byte(addr+size) != 0):
    size +=1
  return size

def get_string(addr, size):
  out = ""
  for offset in range(addr, (addr + size)):
      out += chr(idaapi.get_byte(offset))
  return out

def decrypt(key,cipher,size):
    decrypted_string = ""
    i = 1
    sum = ord(cipher[0])
    for i in range(1, size):
        c = (sum ^ ord(cipher[i]) ^ key) % 0x100
        sum += ord(cipher[i])
        decrypted_string = decrypted_string + chr(i ^ c)
    return str(decrypted_string)

def my_debugged_function():
    # Set breakpoint here!
    ea = idc.get_screen_ea()
    size = get_size(ea)
    key = 0x47

    print ("Addr: 0x%x  | Key: 0x%x | Size: %d" %  (ea,key, size))

    decrypted_string = decrypt(key, get_string(ea, size),size)
    print ("Deobfuscated: %s" % (decrypted_string))


class XorPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC
    comment = "Equation 字符串反混淆"
    help = "一个小工具，用于反混淆Equation的字符串混淆"
    wanted_name = "Xor47 Deobfuscation"
    wanted_hotkey = "Shift+D"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def term(self):
        pass

    def run(self, arg):
        my_debugged_function()


def PLUGIN_ENTRY():
    return XorPlugin()
