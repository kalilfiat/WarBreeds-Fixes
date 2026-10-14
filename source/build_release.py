"""Build portable releases from verified sources; never writes installed game files."""
from pathlib import Path
import hashlib, importlib.util, json, struct, shutil, subprocess, zipfile

P=Path(__file__).resolve().parent
ROOT=P.parents[1]
VERSION='1.0.0'
ORIGINAL_SHA='0e0768693a62ba89fcd5f1fd56dfcda68206d32bc6d5b5c285792996115061e3'
def sha(b):return hashlib.sha256(b).hexdigest()
def load(name,location):
    spec=importlib.util.spec_from_file_location(name,location)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def delta(source,target):
    spans=[];start=None;last=None
    for i,b in enumerate(target):
        if i>=len(source) or b!=source[i]:
            if start is None:start=i
            elif i-last>17:spans.append((start,last+1));start=i
            last=i
    if start is not None:spans.append((start,last+1))
    out=bytearray(b'WBFIX001'+struct.pack('<III',len(source),len(target),len(spans)))
    for a,b in spans:out.extend(struct.pack('<II',a,b-a)+target[a:b])
    rebuilt=bytearray(source);rebuilt.extend(bytes(max(0,len(target)-len(rebuilt))));del rebuilt[len(target):]
    for a,b in spans:rebuilt[a:b]=target[a:b]
    assert bytes(rebuilt)==target
    return bytes(out),len(spans)
def write_json(path,value):path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
def build():
    original=next((ROOT/'MODS/Widescreen/backups').glob('*/WARBREED.EXE')).read_bytes()
    assert sha(original)==ORIGINAL_SHA
    modules={key:load('community_'+key,ROOT/'MODS'/directory/'build_patch.py')
             for key,directory in [('animation','Animation-Timing'),('ui','UI-Animation'),('zoom','Camera-Zoom'),('video','Video-Layout')]}
    ws=load('community_ws',ROOT/'MODS/Widescreen/widescreen.py')
    out=P/'staging';out.mkdir(exist_ok=True)
    public=out/'WarBreeds-Fixes';public.mkdir(exist_ok=True)
    for folder in ('payload','patches','source','licenses','validation'):(public/folder).mkdir(exist_ok=True)
    variants=[];evidence=[]
    canonical=[]
    dlls={'animation':'WBAnim.dll','ui':'WBUIAnim.dll','zoom':'WBZoom.dll','video':'WBVideo.dll'}
    for mask in range(32):
        if mask&8 and not mask&1:continue
        target=ws.patch_executable(original) if mask&1 else original
        hooks=[]
        for bit,key in ((2,'animation'),(4,'ui'),(8,'zoom'),(16,'video')):
            if mask&bit:
                module=modules[key];module.BASE_SHA=sha(target);module.BASE=sha(target)
                target,code=module.build(target);hooks.append({'module':key,'code':code})
        if mask==31:assert sha(target)=='1d09d029ecbc3bd410b633e22385063f0d1d79c2aa857b5df72d5d0ad855b695'
        blob,spans=delta(original,target);name='patches/%02d.wbdelta'%mask;(public/name).write_bytes(blob)
        # Inspect the actual PE import table, not incidental DLL strings in data.
        pe=struct.unpack_from('<I',target,60)[0];opt=pe+24;count=struct.unpack_from('<H',target,pe+6)[0]
        table=opt+struct.unpack_from('<H',target,pe+20)[0]
        sections=[struct.unpack_from('<IIII',target,table+i*40+8) for i in range(count)]
        def offset(r):return next(raw+r-start for vs,start,size,raw in sections if start<=r<start+max(vs,size))
        at=offset(struct.unpack_from('<I',target,opt+104)[0]);imports=[]
        while target[at:at+20]!=bytes(20):
            p=offset(struct.unpack_from('<I',target,at+12)[0]);imports.append(target[p:target.index(0,p)].decode('ascii'));at+=20
        expected=[dlls[key] for bit,key in ((2,'animation'),(4,'ui'),(8,'zoom'),(16,'video')) if mask&bit]
        assert sorted(n for n in imports if n.startswith('WB'))==sorted(expected)
        variants.append({'mask':mask,'file':name,'patchSha256':sha(blob),'outputSha256':sha(target),'outputLength':len(target)})
        evidence.append({'mask':mask,'delta_spans':spans,'delta_bytes':len(blob),'imports':imports,'hooks':hooks})
    files=[]
    def payload(source,name,feature):
        data=source.read_bytes();dest=public/'payload'/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data)
        files.append({'name':name,'sha256':sha(data),'feature':feature,'length':len(data)})
    for key,directory,feature in [('animation','Animation-Timing',2),('ui','UI-Animation',4),('zoom','Camera-Zoom',8),('video','Video-Layout',16)]:
        payload(ROOT/'MODS'/directory/'prepared'/dlls[key],dlls[key],feature)
    crt=json.loads((ROOT/'MODS/CRT-Filters/build-manifest.json').read_text())
    for name,digest in crt['files'].items():
        source=ROOT/'MODS/CRT-Filters/prepared'/name;assert sha(source.read_bytes())==digest
        payload(source,name,32)
    runtime=json.loads((ROOT/'MODS/Video-Fix/runtime-manifest.json').read_text())
    manifest={'version':VERSION,'originalSha256':ORIGINAL_SHA,'originalLength':len(original),'variants':variants,'files':files,
              'runtimeUrl':runtime['source_url'],'runtimeArchiveSha256':runtime['archive_sha256'],
              'runtime':[{'name':r['path'],'sha256':r['sha256'],'length':r['size_bytes']} for r in runtime['files']],
              'userValidation':'14/10/2026: usuario confirma peliculas y zoom; zoom tiene parpadeo negro al cambiar resolucion.'}
    write_json(public/'manifest.json',manifest)
    compiler=Path('C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')
    args=[str(compiler),'/nologo','/target:exe','/platform:anycpu','/optimize+',
          '/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll',
          '/reference:System.IO.Compression.dll','/reference:System.IO.Compression.FileSystem.dll']
    subprocess.run(args+['/out:'+str(public/'WarBreeds-Fixes.exe'),str(P/'Installer.cs')],check=True)
    subprocess.run(args+['/define:QA','/out:'+str(P/'Installer-QA.exe'),str(P/'Installer.cs')],check=True)
    for name in ('LEEME.txt','README.md','STEAM.txt','CHANGELOG.md','THIRD-PARTY.txt','LICENSE.txt'):
        shutil.copy2(P/name,public/name)
    shutil.copy2(ROOT/'MODS/CRT-Filters/DDrawCompat-LICENSE.txt',public/'licenses/DDrawCompat-LICENSE.txt')
    for name in ('Installer.cs','build_release.py'):shutil.copy2(P/name,public/'source'/name)
    # Local helper sources are useful to audit. Builders are included without their game payloads.
    for directory in ('Animation-Timing','UI-Animation','Camera-Zoom','Video-Layout','Widescreen'):
        for source in (ROOT/'MODS'/directory).glob('*'):
            if source.suffix in ('.c','.cpp','.def') or source.name in ('build_patch.py','widescreen.py','build-native.cmd'):
                dest=public/'source'/directory/source.name;dest.parent.mkdir(exist_ok=True);shutil.copy2(source,dest)
    docs_checks={'game_started':False,'variants':evidence,'canonical_full_stack_reproduced':True,'no_game_executable_distributed':True}
    write_json(P/'variant-checks.json',docs_checks)
    for name in ('variant-checks.json','installer-checks.json','selected-hook-checks.json','dependency-checks.json'):
        if (P/name).exists():shutil.copy2(P/name,public/'validation'/name)
    private=out/'WarBreeds-Fixes-Offline';shutil.copytree(public,private,dirs_exist_ok=True)
    (private/'runtime').mkdir(exist_ok=True)
    for row in runtime['files']:
        source=ROOT/'MODS/Video-Fix/runtime-source/qt2'/row['path'];assert sha(source.read_bytes())==row['sha256']
        shutil.copy2(source,private/'runtime'/row['path'])
    (private/'COPIA-PERSONAL.txt').write_text('Copia personal sin conexion. Incluye los componentes QuickTime 2 usados localmente.\nPara publicar usar el ZIP Public, que obtiene esa dependencia por separado.\n',encoding='utf-8')
    dist=P/'dist';dist.mkdir(exist_ok=True)
    assets=[]
    for flavor,tree in (('Public',public),('Personal-Offline',private)):
        archive=dist/('WarBreeds-Fixes-'+VERSION+'-'+flavor+'.zip')
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for f in sorted(tree.rglob('*')):
                if f.is_file():z.write(f,Path(tree.name)/f.relative_to(tree))
        assets.append({'file':archive.name,'sha256':sha(archive.read_bytes()),'bytes':archive.stat().st_size})
    write_json(P/'release-checks.json',{'version':VERSION,'assets':assets,'variants':len(variants),'game_started':False})
    (dist/'SHA256SUMS.txt').write_text(''.join(r['sha256']+'  '+r['file']+'\n' for r in assets))
    print(json.dumps(assets,indent=2))
if __name__=='__main__':build()
