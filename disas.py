from capstone import *
from elftools.elf.elffile import ELFFile

path=r'C:\Users\evern\Documents\hackathon\grimoire'
with open(path,'rb') as f:
    elff=ELFFile(f)
    text=elff.get_section_by_name('.text')
    data=text.data()
    base=text['sh_addr']

md=Cs(CS_ARCH_X86, CS_MODE_64)
md.detail=True

# map symbol addresses
syms={}
for s in elff.iter_section('.symtab'):
    if s.name and s['st_value']:
        syms[s['st_value']]=s.name

for ins in md.disasm(data, base):
    name = syms.get(ins.address,'')
    mark='  <---- %s'%name if name else ''
    print("%08x: %-10s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
