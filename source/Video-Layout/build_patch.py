"""Append an isolated movie-layout helper to the existing layered executable."""
from pathlib import Path
import hashlib
import json
import struct

P=Path(__file__).resolve().parent;ROOT=P.parents[1]
BASE='a1942807a86b062413759b2dad5de6460adedb214a83034c2b95454c84cead4b'
def sha(data):return hashlib.sha256(data).hexdigest()
def align(value,bound):return (value+bound-1)//bound*bound

def build(source):
    if sha(source)!=BASE:raise ValueError('Se requiere el ejecutable verificado con UI/cursor/aro/zoom/16:9.')
    pe=struct.unpack_from('<I',source,60)[0];opt=pe+24;count=struct.unpack_from('<H',source,pe+6)[0]
    table=opt+struct.unpack_from('<H',source,pe+20)[0]
    sections=[struct.unpack_from('<IIII',source,table+i*40+8) for i in range(count)]
    base=struct.unpack_from('<I',source,opt+28)[0];sa,fa=struct.unpack_from('<II',source,opt+32)
    if base!=0x400000 or table+(count+1)*40>min(s[3] for s in sections):raise ValueError('Cabecera PE incompatible.')
    def off(r):return next(raw+r-start for vs,start,rs,raw in sections if start<=r<start+max(vs,rs))
    rva=align(max(start+max(vs,rs) for vs,start,rs,raw in sections),sa);va=base+rva;payload=bytearray()
    def add(data,bound=1):
        position=align(len(payload),bound);payload.extend(bytes(position-len(payload)));payload.extend(data);return position
    stub=add(bytes(128),16);scale_stub=add(bytes(80),16);canvas_stub=add(bytes(80),16);restore_stub=add(bytes(80),16)
    irva,_=struct.unpack_from('<II',source,opt+104);at=off(irva);imports=bytearray()
    while source[at:at+20]!=bytes(20):imports.extend(source[at:at+20]);at+=20
    it=add(bytes(len(imports)+40),4);dn=add(b'WBVideo.dll\0');fn=add(b'\0\0WBVideoFit\0',2);sf=add(b'\0\0WBVideoScale\0',2);cf=add(b'\0\0WBVideoCanvas\0',2);rf=add(b'\0\0WBVideoRestore\0',2)
    lookup=add(struct.pack('<IIIII',rva+fn,rva+sf,rva+cf,rva+rf,0),4);iat=add(struct.pack('<IIIII',rva+fn,rva+sf,rva+cf,rva+rf,0),4)
    payload[it:it+len(imports)]=imports
    struct.pack_into('<5I',payload,it+len(imports),rva+lookup,0,0,rva+dn,rva+iat)
    site=0x476b43;before=bytes.fromhex('8b7ddc0fbf4628');normal=0x476b4a;fitted=0x476baa
    code=bytearray(b'\x9c\x60\x8d\x45\xe8\x50\x8d\x45\xdc\x50\x56\xff\x15')
    relocation=stub+len(code);code.extend(struct.pack('<I',va+iat));code.extend(b'\x85\xc0\x74\x00');branch=len(code)-1
    code.extend(b'\x61\x9d\x8b\x4d\xe8\xe9');code.extend(struct.pack('<i',fitted-(va+stub+len(code)+4)))
    fallback=len(code);code[branch]=fallback-(branch+1)
    code.extend(b'\x61\x9d'+before+b'\xe9');code.extend(struct.pack('<i',normal-(va+stub+len(code)+4)))
    payload[stub:stub+len(code)]=code
    scale_site=0x476bc5;scale_before=bytes.fromhex('8b463885c0');scale_resume=0x476bca
    sc=bytearray(b'\x9c\x60\x56\xff\x15');scale_reloc=scale_stub+len(sc);sc.extend(struct.pack('<I',va+iat+4))
    sc.extend(b'\x61\x9d'+scale_before+b'\xe9');sc.extend(struct.pack('<i',scale_resume-(va+scale_stub+len(sc)+4)))
    payload[scale_stub:scale_stub+len(sc)]=sc
    canvas_site=0x476aa4;canvas_resume=0x476aab
    canvas_before=source[off(canvas_site-base):off(canvas_site-base)+7]
    if canvas_before[:3]!=b'\x6a\x00\xe8' or canvas_site+7+struct.unpack('<i',canvas_before[3:])[0]!=0x4c82d0:
        raise ValueError('Firma de inicializacion distinta.')
    cc=bytearray(b'\x9c\x60\x56\xff\x15');canvas_reloc=canvas_stub+len(cc);cc.extend(struct.pack('<I',va+iat+8))
    cc.extend(b'\x61\x9d\x6a\x00\xe8');cc.extend(struct.pack('<i',0x4c82d0-(va+canvas_stub+len(cc)+4)))
    cc.extend(b'\xe9');cc.extend(struct.pack('<i',canvas_resume-(va+canvas_stub+len(cc)+4)))
    payload[canvas_stub:canvas_stub+len(cc)]=cc
    restore_site=0x476d18;restore_resume=0x476d1d;restore_before=bytes.fromhex('66895e3e5f')
    rc=bytearray(b'\x9c\x60\x56\xff\x15');restore_reloc=restore_stub+len(rc);rc.extend(struct.pack('<I',va+iat+12))
    rc.extend(b'\x61\x9d'+restore_before+b'\xe9');rc.extend(struct.pack('<i',restore_resume-(va+restore_stub+len(rc)+4)))
    payload[restore_stub:restore_stub+len(rc)]=rc
    changes=[(site,before,b'\xe9'+struct.pack('<i',va+stub-site-5)+b'\x90\x90'),
             (scale_site,scale_before,b'\xe9'+struct.pack('<i',va+scale_stub-scale_site-5)),
             (canvas_site,canvas_before,b'\xe9'+struct.pack('<i',va+canvas_stub-canvas_site-5)+b'\x90\x90'),
             (restore_site,restore_before,b'\xe9'+struct.pack('<i',va+restore_stub-restore_site-5))]
    rr,rl=struct.unpack_from('<II',source,opt+136);rt=add(source[off(rr):off(rr)+rl],4)
    add(struct.pack('<IIHHHH',rva,16,0x3000|relocation,0x3000|scale_reloc,0x3000|canvas_reloc,0x3000|restore_reloc));out=bytearray(source);patches=[]
    for address,old,new in changes:
        at=off(address-base)
        if source[at:at+len(old)]!=old:raise ValueError('Firma distinta: '+hex(address))
        out[at:at+len(old)]=new;patches.append({'site':address,'offset':at,'before':old.hex(),'after':new.hex()})
    raw=align(len(out),fa);rs=align(len(payload),fa);out.extend(bytes(raw-len(out))+payload+bytes(rs-len(payload)))
    struct.pack_into('<8sIIIIIIHHI',out,table+count*40,b'.wbvideo',len(payload),rva,rs,raw,0,0,0,0,0xe0000060)
    struct.pack_into('<H',out,pe+6,count+1);struct.pack_into('<I',out,opt+56,align(rva+len(payload),sa))
    struct.pack_into('<I',out,opt+4,struct.unpack_from('<I',source,opt+4)[0]+368)
    struct.pack_into('<I',out,opt+8,struct.unpack_from('<I',source,opt+8)[0]+rs-368)
    struct.pack_into('<II',out,opt+104,rva+it,len(imports)+40)
    struct.pack_into('<II',out,opt+136,rva+rt,len(payload)-rt);struct.pack_into('<I',out,opt+64,0)
    return bytes(out),{'patches':patches,'stub_va':va+stub,'stub_size':len(code),'iat_rva':rva+iat,
                      'relocations':[rva+relocation,rva+scale_reloc,rva+canvas_reloc,rva+restore_reloc],'normal_resume':normal,'fitted_resume':fitted,
                      'scale_stub_va':va+scale_stub,'scale_resume':scale_resume,'canvas_stub_va':va+canvas_stub,
                      'canvas_resume':canvas_resume,'restore_stub_va':va+restore_stub,'restore_resume':restore_resume,'new_section_rva':rva}

if __name__=='__main__':
    source=(ROOT/'MODS/Camera-Zoom/prepared/WARBREED.EXE').read_bytes();out,code=build(source)
    (P/'prepared/WARBREED.EXE').write_bytes(out)
    report={'base_sha256':BASE,'installed_sha256':sha(out),'dll_sha256':sha((P/'prepared/WBVideo.dll').read_bytes()),
            'canvas':[3840,2160],'code':code}
    (P/'build-manifest.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
