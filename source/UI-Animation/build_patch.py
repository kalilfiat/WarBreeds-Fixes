"""Adds two gates for identified decorative UI paths; leaves manual cycle selection intact."""
from pathlib import Path
import hashlib
import json
import struct

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parents[1]
BASE_SHA = '3eab1217cc2801c13cd9d637af4cfe12e10d91f734d4587f04c02db7fee21d8c'
def sha(d): return hashlib.sha256(d).hexdigest()
def align(n,m): return (n+m-1)//m*m

def build(source):
    if sha(source) != BASE_SHA: raise ValueError('Se requiere el ejecutable con 16:9 y cursor/aro verificados.')
    pe=struct.unpack_from('<I',source,60)[0]; opt=pe+24
    count=struct.unpack_from('<H',source,pe+6)[0]
    table=opt+struct.unpack_from('<H',source,pe+20)[0]
    sections=[struct.unpack_from('<IIII',source,table+i*40+8) for i in range(count)]
    base=struct.unpack_from('<I',source,opt+28)[0]
    sa,fa=struct.unpack_from('<II',source,opt+32)
    if base!=0x400000 or table+(count+1)*40>min(s[3] for s in sections): raise ValueError('Cabecera PE no compatible.')
    def off(r): return next(raw+r-start for vs,start,rs,raw in sections if start<=r<start+max(vs,rs))
    rva=align(max(start+max(vs,rs) for vs,start,rs,raw in sections),sa); va=base+rva
    payload=bytearray()
    def add(b,bound=1):
        p=align(len(payload),bound);payload.extend(bytes(p-len(payload)));payload.extend(b);return p
    stubs=[add(bytes(80),16),add(bytes(80),16)]
    irva,_=struct.unpack_from('<II',source,opt+104);p=off(irva);imports=bytearray()
    while source[p:p+20]!=bytes(20): imports.extend(source[p:p+20]);p+=20
    it=add(bytes(len(imports)+40),4);dn=add(b'WBUIAnim.dll\0');fn=add(b'\0\0WBUIAdvance\0',2)
    lookup=add(struct.pack('<II',rva+fn,0),4);iat=add(struct.pack('<II',rva+fn,0),4)
    payload[it:it+len(imports)]=imports
    struct.pack_into('<5I',payload,it+len(imports),rva+lookup,0,0,rva+dn,rva+iat)
    reloc=[];patches=[]
    targets=[(0x487c06,bytes.fromhex('8b4e38668b7e5c'),0x487c0d,0x487d4a),
             (0x486c2d,bytes.fromhex('8b86c8000000'),0x486c33,0x486c59)]
    for channel,(site,before,resume,skip) in enumerate(targets):
        code=bytearray(b'\x9c\x60\x6a'+bytes([channel])+b'\x56\xff\x15')
        reloc.append(stubs[channel]+len(code));code.extend(struct.pack('<I',va+iat))
        code.extend(b'\x85\xc0\x74'+bytes([len(before)+7]))
        code.extend(b'\x61\x9d'+before+b'\xe9')
        code.extend(struct.pack('<i',resume-(va+stubs[channel]+len(code)+4)))
        code.extend(b'\x61\x9d\xe9')
        code.extend(struct.pack('<i',skip-(va+stubs[channel]+len(code)+4)))
        payload[stubs[channel]:stubs[channel]+len(code)]=code
        at=off(site-base)
        if source[at:at+len(before)]!=before:raise ValueError('Firma diferente: '+hex(site))
        after=b'\xe9'+struct.pack('<i',va+stubs[channel]-site-5)+bytes([0x90])*(len(before)-5)
        patches.append({'site':site,'offset':at,'before':before.hex(),'after':after.hex(),'stub':va+stubs[channel],
                        'stub_size':len(code),'channel':channel,'resume':resume,'skip':skip})
    rr,rl=struct.unpack_from('<II',source,opt+136);rt=add(source[off(rr):off(rr)+rl],4)
    entries=[0x3000|p for p in reloc]
    if len(entries)%2:entries.append(0)
    add(struct.pack('<II',rva,8+len(entries)*2)+struct.pack('<'+'H'*len(entries),*entries))
    rl2=len(payload)-rt;out=bytearray(source)
    for p in patches:out[p['offset']:p['offset']+len(bytes.fromhex(p['before']))]=bytes.fromhex(p['after'])
    raw=align(len(out),fa);rs=align(len(payload),fa)
    out.extend(bytes(raw-len(out))+payload+bytes(rs-len(payload)))
    struct.pack_into('<8sIIIIIIHHI',out,table+count*40,b'.wbui\0\0\0',len(payload),rva,rs,raw,0,0,0,0,0xe0000060)
    struct.pack_into('<H',out,pe+6,count+1)
    struct.pack_into('<I',out,opt+56,align(rva+len(payload),sa))
    struct.pack_into('<I',out,opt+4,struct.unpack_from('<I',source,opt+4)[0]+160)
    struct.pack_into('<I',out,opt+8,struct.unpack_from('<I',source,opt+8)[0]+rs-160)
    struct.pack_into('<II',out,opt+104,rva+it,len(imports)+40)
    struct.pack_into('<II',out,opt+136,rva+rt,rl2)
    struct.pack_into('<I',out,opt+64,0)
    return bytes(out),{'new_section_rva':rva,'iat_rva':rva+iat,'patches':patches,'relocations':[rva+p for p in reloc]}

if __name__=='__main__':
    output,code=build((ROOT/'WARBREED.EXE').read_bytes())
    (PACKAGE/'prepared/WARBREED.EXE').write_bytes(output)
    report={'base_sha256':BASE_SHA,'installed_sha256':sha(output),
            'dll_sha256':sha((PACKAGE/'prepared/WBUIAnim.dll').read_bytes()),'code':code}
    (PACKAGE/'build-manifest.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
