// Portable .NET Framework installer. Never launches the game or requests elevation.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Forms;

public class Payload { public string name,sha256; public int feature,length; }
public class Variant { public int mask,outputLength; public string file,patchSha256,outputSha256; }
public class Manifest {
    public string version,originalSha256,runtimeUrl,runtimeArchiveSha256,userValidation;
    public int originalLength; public Payload[] files,runtime; public Variant[] variants;
}
public class Change {
    public string name,kind,beforeHash,afterHash,backup;
    public Dictionary<string,string> beforeKeys,afterKeys;
    public string[] addedModes; public int[] beforeResolution;
}
public class State { public string version,status,backupId,executableHash; public int mask; public bool crt,quickTime; public Change[] changes; }
public class Plan { public Change record; public byte[] before,after; }

public static class Installer {
    static readonly UTF8Encoding Utf8=new UTF8Encoding(false,true);
    static readonly JavaScriptSerializer Json=new JavaScriptSerializer { MaxJsonLength=10000000 };
    static readonly string Package=AppDomain.CurrentDomain.BaseDirectory;
    const string StateFolder="WarBreedsFixes";
    static Manifest manifest; static string root; static int writes;
#if QA
    static int failAfter=-1;
#endif
    static string Hash(byte[] data) { if(data==null)return null; using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(data)).Replace("-","").ToLowerInvariant(); }
    static byte[] Read(string path) { return File.Exists(path)?File.ReadAllBytes(path):null; }
    static T Load<T>(string path) { return Json.Deserialize<T>(File.ReadAllText(path,Utf8)); }
    static byte[] Serialize(object value) { return Utf8.GetBytes(Json.Serialize(value)+"\n"); }
    static string Safe(string basis,string name) {
        if(String.IsNullOrEmpty(name)||Path.IsPathRooted(name)||name.Contains(":")||name.Split('/','\\').Any(s=>s==".."||s=="."||s.Length==0))throw new Exception("Ruta relativa invalida.");
        string full=Path.GetFullPath(Path.Combine(basis,name.Replace('/',Path.DirectorySeparatorChar)));
        string prefix=Path.GetFullPath(basis).TrimEnd('\\','/')+Path.DirectorySeparatorChar;
        if(!full.StartsWith(prefix,StringComparison.OrdinalIgnoreCase))throw new Exception("Ruta fuera de la carpeta elegida.");
        // Avoid following directory links into unrelated folders.
        for(string parent=Path.GetDirectoryName(full);parent!=null&&parent.StartsWith(prefix,StringComparison.OrdinalIgnoreCase);parent=Path.GetDirectoryName(parent))
            if(Directory.Exists(parent)&&(File.GetAttributes(parent)&FileAttributes.ReparsePoint)!=0)throw new Exception("No se admiten subcarpetas enlazadas: "+parent);
        if(File.Exists(full)&&(File.GetAttributes(full)&FileAttributes.ReparsePoint)!=0)throw new Exception("No se admiten archivos enlazados: "+name);
        return full;
    }
    static string Target(string name) { return Safe(root,name); }
    static string StatePath { get { return Target(StateFolder+"/state.json"); } }
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool MoveFileEx(string from,string to,int flags);
    static void Atomic(string path,byte[] data) {
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        if(data==null) { if(File.Exists(path))File.Delete(path); return; }
        string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try {
            using(var f=new FileStream(temp,FileMode.CreateNew,FileAccess.Write,FileShare.None)) { f.Write(data,0,data.Length); f.Flush(true); }
            if(!MoveFileEx(temp,path,1|8))throw new IOException("No se pudo escribir "+path+" (Windows "+Marshal.GetLastWin32Error()+").");
        } finally { if(File.Exists(temp))File.Delete(temp); }
    }
    static void ManagedWrite(string path,byte[] data) {
#if QA
        if(++writes==failAfter)throw new IOException("Fallo de escritura simulado.");
#else
        writes++;
#endif
        Atomic(path,data);
    }
    static void ClosedGame() {
        if(Process.GetProcessesByName("WARBREED").Length!=0)throw new Exception("Cerrar WarBreeds antes de instalar o restaurar.");
    }
    static void ValidateRoot(string path) {
        root=Path.GetFullPath(path).TrimEnd('\\','/');
        if(!Directory.Exists(root)||!File.Exists(Target("WARBREED.EXE"))||!Directory.Exists(Target("DATA")))throw new Exception("Elegir la carpeta que contiene WARBREED.EXE y DATA.");
        if(Path.GetPathRoot(root).TrimEnd('\\','/').Equals(root,StringComparison.OrdinalIgnoreCase))throw new Exception("No se admite la raiz de una unidad como carpeta del juego.");
    }
    static byte[] Verified(string path,string hash) {
        byte[] data=File.ReadAllBytes(path);if(Hash(data)!=hash)throw new Exception("Archivo del paquete alterado: "+Path.GetFileName(path));return data;
    }
    static byte[] Patch(byte[] original,Variant variant) {
        byte[] blob=Verified(Safe(Package,variant.file),variant.patchSha256);
        using(var reader=new BinaryReader(new MemoryStream(blob))) {
            if(Encoding.ASCII.GetString(reader.ReadBytes(8))!="WBFIX001")throw new Exception("Formato de parche invalido.");
            int old=reader.ReadInt32(),size=reader.ReadInt32(),count=reader.ReadInt32();
            if(old!=original.Length||size!=variant.outputLength||size<old||size>16000000||count<0||count>100000)throw new Exception("Limites de parche invalidos.");
            byte[] output=new byte[size];Buffer.BlockCopy(original,0,output,0,original.Length);int last=0;
            for(int i=0;i<count;i++) {
                int offset=reader.ReadInt32(),length=reader.ReadInt32();
                if(offset<last||length<=0||offset>size-length)throw new Exception("Segmento de parche invalido.");
                byte[] bytes=reader.ReadBytes(length);if(bytes.Length!=length)throw new Exception("Parche truncado.");
                Buffer.BlockCopy(bytes,0,output,offset,length);last=offset+length;
            }
            if(reader.BaseStream.Position!=blob.Length||Hash(output)!=variant.outputSha256)throw new Exception("Resultado del parche no valido.");return output;
        }
    }
    static string IniText(byte[] bytes) { return bytes==null?"":Utf8.GetString(bytes).TrimStart('\uFEFF'); }
    static string GetKey(string text,string key) {
        Match m=Regex.Match(text,@"(?im)^\s*"+Regex.Escape(key)+@"\s*=\s*([^\r\n]*)");return m.Success?m.Groups[1].Value.Trim():null;
    }
    static string SetKey(string text,string key,string value) {
        string pattern=@"(?im)^[ \t]*"+Regex.Escape(key)+@"[ \t]*=[^\r\n]*(?:\r?\n|$)";
        if(Regex.IsMatch(text,pattern)) {
            bool first=true;return Regex.Replace(text,pattern,m=>{if(value==null||!first)return "";first=false;return key+" = "+value+"\r\n";});
        }
        return value==null?text:text+(text.Length>0&&!text.EndsWith("\n")?"\r\n":"")+key+" = "+value+"\r\n";
    }
    static List<string> Modes(string value) { return (value??"").Split(',').Select(s=>s.Trim()).Where(s=>s.Length>0).ToList(); }
    static Plan Make(string name,byte[] data,string kind) {
        byte[] before=Read(Target(name));return new Plan { before=before,after=data,record=new Change {name=name,kind=kind,beforeHash=Hash(before),afterHash=Hash(data)} };
    }
    static Plan Ini(string name,Dictionary<string,string> settings) {
        Plan plan=Make(name,null,"ini");string text=IniText(plan.before);var old=new Dictionary<string,string>();var after=new Dictionary<string,string>();
        foreach(var pair in settings) {
            old[pair.Key]=GetKey(text,pair.Key);text=SetKey(text,pair.Key,pair.Value);after[pair.Key]=pair.Value;
        }
        plan.record.beforeKeys=old;plan.record.afterKeys=after;plan.after=Utf8.GetBytes(text);plan.record.afterHash=Hash(plan.after);
        if(after.ContainsKey("SupportedResolutions"))plan.record.addedModes=Modes(after["SupportedResolutions"]).Except(Modes(old["SupportedResolutions"]),StringComparer.OrdinalIgnoreCase).ToArray();
        return plan;
    }
    static ushort U16(byte[] b,int p) { Bounds(b,p,2);return (ushort)((b[p]<<8)|b[p+1]); }
    static int U32(byte[] b,int p) { Bounds(b,p,4);uint value=((uint)b[p]<<24)|((uint)b[p+1]<<16)|((uint)b[p+2]<<8)|b[p+3];if(value>Int32.MaxValue)throw new Exception("Preferencias fuera de rango.");return (int)value; }
    static void Bounds(byte[] b,int p,int size) { if(p<0||size<0||p>b.Length-size)throw new Exception("Contenedor de preferencias invalido."); }
    static int[] PrefOffsets(byte[] b) {
        Bounds(b,0,28);if(Encoding.ASCII.GetString(b,0,4)!="MHWK"||Encoding.ASCII.GetString(b,8,4)!="RSRC")throw new Exception("prefs.dbg no tiene el formato esperado.");
        int basis=U32(b,20),table=basis+U16(b,24),count=U32(b,table);if(count>10000)throw new Exception("Demasiadas preferencias.");
        var files=new List<int[]>();for(int i=0;i<count;i++){int p=table+4+i*10;Bounds(b,p,8);int start=U32(b,p),size=U16(b,p+4)+(b[p+6]<<16)+((b[p+7]&7)<<24);Bounds(b,start,size);files.Add(new[]{start,size});}
        int strings=basis+U16(b,basis);var found=new Dictionary<string,int>();int types=U16(b,basis+2);
        for(int i=0;i<types;i++) {
            int p=basis+4+i*8,resources=basis+U16(b,p+4),names=basis+U16(b,p+6);var labels=new Dictionary<int,string>();
            for(int j=0;j<U16(b,names);j++){int pos=names+2+j*4,start=strings+U16(b,pos),index=U16(b,pos+2);Bounds(b,start,1);int end=Array.IndexOf(b,(byte)0,start);if(end<0)throw new Exception("Nombre de preferencia invalido.");labels[index]=Encoding.ASCII.GetString(b,start,end-start);}
            for(int j=0;j<U16(b,resources);j++){int index=U16(b,resources+4+j*4);if(index<1||index>files.Count)throw new Exception("Indice de preferencia invalido.");string label;if(labels.TryGetValue(index,out label)&&(label=="OPTNPRFRESW"||label=="OPTNPRFRESH")){if(files[index-1][1]!=2||found.ContainsKey(label))throw new Exception("Preferencia de resolucion invalida.");found[label]=files[index-1][0];}}
        }
        if(!found.ContainsKey("OPTNPRFRESW")||!found.ContainsKey("OPTNPRFRESH"))throw new Exception("No se encontro la resolucion en prefs.dbg.");return new[]{found["OPTNPRFRESW"],found["OPTNPRFRESH"]};
    }
    static int[] Resolution(byte[] b) { int[] p=PrefOffsets(b);return new[]{(int)BitConverter.ToUInt16(b,p[0]),(int)BitConverter.ToUInt16(b,p[1])}; }
    static byte[] SetResolution(byte[] b,int[] size) { byte[] output=(byte[])b.Clone();int[] p=PrefOffsets(output);for(int i=0;i<2;i++)Buffer.BlockCopy(BitConverter.GetBytes((ushort)size[i]),0,output,p[i],2);return output; }
    [DllImport("user32.dll")]static extern bool SetProcessDPIAware();
    static int[] Desktop() {
        SetProcessDPIAware();Rectangle rect=Screen.PrimaryScreen.Bounds;int w=rect.Width,h=rect.Height;
        if(w<640||h<480||w>4096||h>4096)return new[]{1920,1080};return new[]{w,h};
    }
    static Dictionary<string,byte[]> Runtime(bool offlineOnly) {
        var result=new Dictionary<string,byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach(var row in manifest.runtime) {
            string packaged=Safe(Package,"runtime/"+row.name);byte[] game=Read(Target(row.name));
            if(game!=null&&Hash(game)!=row.sha256)throw new Exception("Existe otra version de "+row.name+"; no se sobrescribira.");
            if(File.Exists(packaged))result[row.name]=Verified(packaged,row.sha256);else if(game!=null)result[row.name]=game;
        }
        if(result.Count==manifest.runtime.Length)return result;
        if(offlineOnly)throw new Exception("Faltan componentes QuickTime y se indico --offline. Usar la copia personal o agregar los componentes indicados en THIRD-PARTY.txt.");
        Console.WriteLine("Descargando QuickTime 2 desde la fuente indicada en THIRD-PARTY.txt...");
        Console.WriteLine(manifest.runtimeUrl);ServicePointManager.SecurityProtocol|=SecurityProtocolType.Tls12;
        byte[] archive;
        using(var client=new WebClient())using(var stream=client.OpenRead(manifest.runtimeUrl))using(var output=new MemoryStream()) {
            byte[] buffer=new byte[8192];int n;while((n=stream.Read(buffer,0,buffer.Length))>0){output.Write(buffer,0,n);if(output.Length>8000000)throw new Exception("Descarga demasiado grande.");}archive=output.ToArray();
        }
        if(Hash(archive)!=manifest.runtimeArchiveSha256)throw new Exception("La descarga no coincide con el paquete QuickTime verificado. No se modifico el juego.");
        using(var zip=new ZipArchive(new MemoryStream(archive),ZipArchiveMode.Read)) {
            foreach(var row in manifest.runtime) {
                var matches=zip.Entries.Where(e=>Path.GetFileName(e.FullName.Replace('\\','/')).Equals(row.name,StringComparison.OrdinalIgnoreCase)).ToArray();
                if(matches.Length!=1||matches[0].Length!=row.length)throw new Exception("Contenido QuickTime inesperado.");
                using(var s=matches[0].Open())using(var output=new MemoryStream()){s.CopyTo(output);byte[] bytes=output.ToArray();if(Hash(bytes)!=row.sha256)throw new Exception("Componente QuickTime alterado: "+row.name);result[row.name]=bytes;}
            }
        }
        return result;
    }
    static bool NeedsWrapper(int mask,bool crt) { return crt||(mask&25)!=0; }
    static void Install(int mask,bool crt,bool qt,bool offline,int[] canvas) {
        ClosedGame();if((mask&8)!=0&&(mask&1)==0)throw new Exception("El zoom por resolucion necesita seleccionar 16:9.");
        if(File.Exists(StatePath)) {
            State existing=Load<State>(StatePath);
            if(existing.status=="installed") {
                if(existing.mask==mask&&existing.crt==crt&&existing.quickTime==qt&&Hash(Read(Target("WARBREED.EXE")))==existing.executableHash) {
                    foreach(var c in existing.changes.Where(c=>c.kind=="binary"))if(Hash(Read(Target(c.name)))!=c.afterHash)throw new Exception("Instalacion alterada: "+c.name);
                    Console.WriteLine("El perfil ya esta instalado. Se conservaron tus preferencias.");return;
                }
                throw new Exception("Ya hay un perfil instalado. Restaurarlo primero para elegir otra combinacion.");
            }
            if(existing.status!="restored")throw new Exception("Hay una instalacion incompleta. Conservar WarBreedsFixes y revisar su state.json antes de continuar.");
        }
        byte[] original=File.ReadAllBytes(Target("WARBREED.EXE"));
        if(Hash(original)!=manifest.originalSha256||original.Length!=manifest.originalLength)throw new Exception("Ejecutable no compatible o ya modificado. Este paquete admite la edicion Steam verificada. Restaurar parches anteriores o usar una instalacion limpia; no se sobrescribio el ejecutable.");
        var variant=manifest.variants.SingleOrDefault(v=>v.mask==mask);if(variant==null)throw new Exception("Combinacion no admitida.");
        if(canvas[0]<640||canvas[0]>4096||canvas[1]<480||canvas[1]>4096)throw new Exception("Lienzo de video fuera de rango (640..4096 por 480..4096).");
        var plan=new List<Plan>();plan.Add(Make("WARBREED.EXE",Patch(original,variant),"binary"));
        foreach(var file in manifest.files) {
            bool include=file.name=="ddraw.dll"?NeedsWrapper(mask,crt):file.feature==32?crt:(mask&file.feature)!=0;
            if(!include)continue;byte[] bytes=Verified(Safe(Package,"payload/"+file.name),file.sha256);Plan p=Make(file.name,bytes,"binary");
            if(p.before!=null&&p.record.beforeHash!=p.record.afterHash) {
                bool oldWrapper=file.name=="ddraw.dll"&&p.record.beforeHash=="32d86c4317c25d687682e3a8e53d4258147f0f94cd682c0a06fecccd9f151280";
                if(!oldWrapper)throw new Exception("Otro archivo ocupa "+file.name+". No se sobrescribira.");
            }
            plan.Add(p);
        }
        if((mask&2)!=0)plan.Add(Make("WarBreeds-Animation.ini",Utf8.GetBytes("[Animation]\r\nEnabled=1\r\nCursorFPS=12\r\nMovementRingFPS=10\r\n"),"config"));
        if((mask&4)!=0)plan.Add(Make("WarBreeds-UI.ini",Utf8.GetBytes("[UIAnimation]\r\nEnabled=1\r\nHologramFPS=12\r\nPanelFPS=12\r\n"),"config"));
        if((mask&8)!=0)plan.Add(Make("WarBreeds-Zoom.ini",Utf8.GetBytes("[Zoom]\r\nEnabled=1\r\nInvertWheel=0\r\nResolutionZoom=1\r\n"),"config"));
        if((mask&16)!=0)plan.Add(Make("WarBreeds-Video.ini",Utf8.GetBytes("[Video]\r\nEnabled=1\r\nCanvasWidth="+canvas[0]+"\r\nCanvasHeight="+canvas[1]+"\r\n"),"config"));
        if(NeedsWrapper(mask,crt)) {
            foreach(string name in new[]{"DDrawCompat-WARBREED.ini","DDrawCompatOverlay-WARBREED.ini"}) {
                byte[] before=Read(Target(name));if(before==null&&name.Contains("Overlay"))continue;
                string text=IniText(before);var settings=new Dictionary<string,string>();
                settings["FullscreenMode"]="borderless";settings["DisplayResolution"]="desktop";settings["DisplayAspectRatio"]="app";
                settings["ConfigHotKey"]="shift+f11";settings["ConfigRows"]="DisplayFilter, PresentDelay";
                if(GetKey(text,"PresentDelay")==null)settings["PresentDelay"]="on(10)";
                settings["DisplayFilter"]=crt?@"crt\WarBreeds-CRT-Suave.cgp":"bilinear(0)";
                var modes=Modes(GetKey(text,"SupportedResolutions")??"native");
                if((mask&1)!=0)modes.Add("1920x1080");if((mask&8)!=0)modes.Add("960x540");if((mask&16)!=0)modes.Add(canvas[0]+"x"+canvas[1]);
                settings["SupportedResolutions"]=String.Join(", ",modes.Distinct(StringComparer.OrdinalIgnoreCase));plan.Add(Ini(name,settings));
            }
        }
        if((mask&1)!=0&&File.Exists(Target("DATA/prefs.dbg"))) {
            byte[] prefs=File.ReadAllBytes(Target("DATA/prefs.dbg"));Plan p=Make("DATA/prefs.dbg",SetResolution(prefs,new[]{1920,1080}),"prefs");p.record.beforeResolution=Resolution(prefs);plan.Add(p);
        }
        if(qt)foreach(var row in Runtime(offline))plan.Add(Make(row.Key,row.Value,"binary"));
        // All input validation, dependency acquisition and backups finish before the first game write.
        plan=plan.Where(p=>p.record.beforeHash!=p.record.afterHash).ToList();
        if(plan.Count==0){Console.WriteLine("No hay cambios que instalar.");return;}
        string id=DateTime.UtcNow.ToString("yyyyMMddHHmmss")+"-"+Guid.NewGuid().ToString("N").Substring(0,16);
        string backup=Target(StateFolder+"/backups/"+id);Directory.CreateDirectory(backup);
        for(int i=0;i<plan.Count;i++) { var p=plan[i];p.record.backup=i.ToString("D4")+".bin";if(p.before!=null)Atomic(Safe(backup,p.record.backup),p.before); }
        byte[] previous=Read(StatePath);if(previous!=null)Atomic(Safe(backup,"previous-state.json"),previous);
        var state=new State {version=manifest.version,status="installing",backupId=id,mask=mask,crt=crt,quickTime=qt,executableHash=variant.outputSha256,changes=plan.Select(p=>p.record).ToArray()};
        Atomic(StatePath,Serialize(state));var completed=new List<Plan>();
        try {
            foreach(var p in plan) { // Executable commits last, after its optional imported DLLs.
                if(p.record.name=="WARBREED.EXE")continue;
                if(Hash(Read(Target(p.record.name)))!=p.record.beforeHash)throw new Exception("Archivo cambiado durante instalacion: "+p.record.name);
                ManagedWrite(Target(p.record.name),p.after);completed.Add(p);
            }
            var exe=plan.FirstOrDefault(p=>p.record.name=="WARBREED.EXE");
            if(exe!=null){if(Hash(Read(Target(exe.record.name)))!=exe.record.beforeHash)throw new Exception("Ejecutable cambiado durante instalacion.");ManagedWrite(Target(exe.record.name),exe.after);completed.Add(exe);}
            state.status="installed";ManagedWrite(StatePath,Serialize(state));
        } catch {
            foreach(var p in completed.AsEnumerable().Reverse())Atomic(Target(p.record.name),p.before);
            Atomic(StatePath,previous);throw;
        }
        Console.WriteLine("Instalado: WarBreeds Fixes "+manifest.version+". No se inicio el juego.");
        Console.WriteLine("Respaldo: "+backup);Console.WriteLine("Zoom: parpadeo negro conocido al cambiar resolucion. Filtros: Shift+F11 > Export.");
        if((mask&1)!=0&&!File.Exists(Target("DATA/prefs.dbg")))Console.WriteLine("Al iniciar por primera vez, elegir 1920x1080 en las opciones del juego.");
    }
    static State ValidState() {
        State s=Load<State>(StatePath);
        if(s.version!=manifest.version||!Regex.IsMatch(s.backupId??"",@"^\d{14}-[a-f0-9]{16}$")||s.changes==null||s.changes.Length>100)throw new Exception("Estado de restauracion invalido.");
        if(s.changes.Select(c=>c.name.ToLowerInvariant()).Distinct().Count()!=s.changes.Length)throw new Exception("Archivos duplicados en el estado.");
        var allowed=new HashSet<string>(manifest.files.Select(f=>f.name),StringComparer.OrdinalIgnoreCase);
        foreach(var row in manifest.runtime)allowed.Add(row.name);
        foreach(string name in new[]{"WARBREED.EXE","WarBreeds-Animation.ini","WarBreeds-UI.ini","WarBreeds-Zoom.ini","WarBreeds-Video.ini","DATA/prefs.dbg","DDrawCompat-WARBREED.ini","DDrawCompatOverlay-WARBREED.ini"})allowed.Add(name);
        foreach(var c in s.changes) {
            if(!allowed.Contains(c.name)||!Regex.IsMatch(c.backup??"",@"^\d{4}\.bin$")||!new[]{"binary","config","prefs","ini"}.Contains(c.kind))throw new Exception("Archivo inesperado en el estado.");
            Target(c.name);
        }
        return s;
    }
    static byte[] RestoreIni(Change c,byte[] current,byte[] before) {
        if(Hash(current)==c.afterHash)return before;
        if(current==null)return null;string text=IniText(current);
        if(c.afterKeys==null||c.beforeKeys==null)throw new Exception("Faltan claves del respaldo.");
        foreach(var pair in c.afterKeys) {
            string value=GetKey(text,pair.Key),old=c.beforeKeys[pair.Key];
            if(value==pair.Value)text=SetKey(text,pair.Key,old);
            else if(pair.Key=="SupportedResolutions"&&c.addedModes!=null) {
                var values=Modes(value);var kept=values.Except(c.addedModes,StringComparer.OrdinalIgnoreCase).ToArray();
                if(kept.Length!=values.Count)text=SetKey(text,pair.Key,String.Join(", ",kept));
            }
        }
        return Utf8.GetBytes(text);
    }
    static void Restore() {
        ClosedGame();if(!File.Exists(StatePath))throw new Exception("No hay una instalacion de este paquete para restaurar.");
        State s=ValidState();if(s.status=="restored"){Console.WriteLine("El perfil ya fue restaurado.");return;}if(s.status!="installed")throw new Exception("Estado incompleto; conservar respaldos para revisar.");
        string backup=Target(StateFolder+"/backups/"+s.backupId);var plan=new List<Plan>();
        foreach(var c in s.changes) {
            byte[] before=c.beforeHash==null?null:Verified(Safe(backup,c.backup),c.beforeHash),current=Read(Target(c.name)),after=before;
            if(c.kind=="binary"&&Hash(current)!=c.afterHash&&Hash(current)!=c.beforeHash)throw new Exception("Archivo con cambios posteriores: "+c.name+". No se sobrescribira.");
            if(c.kind=="ini")after=RestoreIni(c,current,before);
            if(c.kind=="prefs"&&current!=null&&Hash(current)!=c.afterHash) {
                if(c.beforeResolution==null||c.beforeResolution.Length!=2)throw new Exception("Resolucion respaldada invalida.");
                int[] now=Resolution(current);after=(now[0]==1920&&now[1]==1080)?SetResolution(current,c.beforeResolution):current;
            }
            // Save manual edits to our dedicated INIs before removing/replacing them.
            plan.Add(new Plan {record=c,before=current,after=after});
        }
        // Export may create an overlay after installation. Keep user choices, but
        // replace our CRT references if their shader files are about to be removed.
        string overlay="DDrawCompatOverlay-WARBREED.ini";Plan op=plan.FirstOrDefault(p=>p.record.name==overlay);
        byte[] ob=op!=null?op.after:Read(Target(overlay));string ot=IniText(ob);string of=GetKey(ot,"DisplayFilter");
        bool removesShader=plan.Any(p=>p.record.name.EndsWith("WarBreeds-CRT-Suave.cgp")&&p.after==null);
        if(removesShader&&of!=null&&(of.IndexOf("WarBreeds-CRT-",StringComparison.OrdinalIgnoreCase)>=0||of.IndexOf("crt-lottes",StringComparison.OrdinalIgnoreCase)>=0)) {
            Plan cp=plan.FirstOrDefault(p=>p.record.name=="DDrawCompat-WARBREED.ini");string replacement=GetKey(IniText(cp==null?Read(Target("DDrawCompat-WARBREED.ini")):cp.after),"DisplayFilter")??"bilinear(0)";
            byte[] sanitized=Utf8.GetBytes(SetKey(ot,"DisplayFilter",replacement));
            if(op!=null)op.after=sanitized;else plan.Add(Make(overlay,sanitized,"config"));
        }
        string history=Safe(backup,"restore-"+Guid.NewGuid().ToString("N").Substring(0,16));Directory.CreateDirectory(history);
        for(int i=0;i<plan.Count;i++)if(plan[i].before!=null)Atomic(Safe(history,i.ToString("D4")+".bin"),plan[i].before);
        Atomic(Safe(history,"files.json"),Serialize(plan.Select(p=>new {name=p.record.name,hash=Hash(p.before)}).ToArray()));
        byte[] stateBefore=Read(StatePath);var completed=new List<Plan>();
        try {
            foreach(var p in plan.OrderBy(p=>p.record.name=="WARBREED.EXE"?0:1)) {
                if(Hash(Read(Target(p.record.name)))!=Hash(p.before))throw new Exception("Archivo cambiado durante restauracion: "+p.record.name);
                ManagedWrite(Target(p.record.name),p.after);completed.Add(p);
            }
            s.status="restored";ManagedWrite(StatePath,Serialize(s));
        } catch {foreach(var p in completed.AsEnumerable().Reverse())Atomic(Target(p.record.name),p.before);Atomic(StatePath,stateBefore);throw;}
        Console.WriteLine("Perfil restaurado. Partidas y otros ajustes conservados. Respaldos retenidos en WarBreedsFixes.");
    }
    static void Status() {
        Console.WriteLine("Carpeta: "+root);string hash=Hash(Read(Target("WARBREED.EXE")));Console.WriteLine("EXE SHA256: "+hash);
        if(!File.Exists(StatePath)){Console.WriteLine(hash==manifest.originalSha256?"Original compatible; listo para instalar.":"Ejecutable modificado o de otra edicion; no instalar encima.");return;}
        State s=ValidState();Console.WriteLine("Estado: "+s.status+"; version "+s.version+"; opciones "+s.mask+"; CRT="+s.crt+"; QuickTime="+s.quickTime);
        if(s.status=="installed")foreach(var c in s.changes){string now=Hash(Read(Target(c.name)));Console.WriteLine((now==c.afterHash?"OK":c.kind=="binary"?"CAMBIO EXTERNO":"PREFERENCIAS MODIFICADAS")+"  "+c.name);}
    }
    static string Choose(ref int mask,ref bool crt,ref bool qt,ref string folder,string renderPath=null) {
        Application.EnableVisualStyles();using(var form=new Form()) {
            form.Text="WarBreeds Fixes "+manifest.version;form.ClientSize=new Size(660,470);form.StartPosition=FormStartPosition.CenterScreen;form.FormBorderStyle=FormBorderStyle.FixedDialog;form.MaximizeBox=false;
            form.Controls.Add(new Label {Text="Carpeta del juego (WARBREED.EXE)",Left=20,Top=18,Width=600});
            var path=new TextBox {Left=20,Top=42,Width=515,Text=folder??""};form.Controls.Add(path);
            var browse=new Button {Text="Buscar...",Left=545,Top=40,Width=95};form.Controls.Add(browse);
            browse.Click+=(sender,e)=>{using(var dialog=new FolderBrowserDialog {Description="Elegir la carpeta de WarBreeds",SelectedPath=path.Text})if(dialog.ShowDialog(form)==DialogResult.OK)path.Text=dialog.SelectedPath;};
            string[] labels={"Partida 16:9: 1920x1080 (opcional)","Corregir animaciones del cursor y circulo de movimiento","Corregir hologramas y paneles de la UI","Zoom con rueda: 960x540 / 1920x1080 (necesita 16:9)","Ampliar peliculas conservando sus proporciones","Filtros CRT seleccionables (Shift+F11)","Reparar reproduccion de peliculas (descarga QuickTime 2 si falta)"};
            var boxes=new CheckBox[7];for(int i=0;i<7;i++){boxes[i]=new CheckBox {Text=labels[i],Left=20,Top=88+i*31,Width=620,Checked=i<5?(mask&(1<<i))!=0:i==5?crt:qt};form.Controls.Add(boxes[i]);}
            boxes[0].CheckedChanged+=(sender,e)=>{boxes[3].Enabled=boxes[0].Checked;if(!boxes[0].Checked)boxes[3].Checked=false;};boxes[3].Enabled=boxes[0].Checked;
            form.Controls.Add(new Label {Text="El zoom puede producir un breve parpadeo negro. Las peliculas mantienen franjas\nsegun su formato original. No se modifican fondos del menu ni partidas guardadas.\nPara cambiar un perfil instalado: restaurar primero y volver a instalar.",Left=20,Top=318,Width=620,Height=70});
            string action=null;string[] actions={"install","restore","status"};string[] titles={"Instalar seleccion","Restaurar","Ver estado"};
            for(int i=0;i<3;i++){string choice=actions[i];var button=new Button {Text=titles[i],Left=20+i*210,Top=412,Width=195,Height=32};button.Click+=(sender,e)=>{action=choice;form.DialogResult=DialogResult.OK;form.Close();};form.Controls.Add(button);}
            if(renderPath!=null) {
                var handle=form.Handle;
                using(var bitmap=new Bitmap(form.Width,form.Height)) {
                    form.DrawToBitmap(bitmap,new Rectangle(0,0,bitmap.Width,bitmap.Height));
                    int dx=(form.Width-form.ClientSize.Width)/2,dy=form.Height-form.ClientSize.Height-dx;
                    using(var graphics=Graphics.FromImage(bitmap))foreach(Control control in form.Controls) {
                        var childHandle=control.Handle;
                        using(var child=new Bitmap(control.Width,control.Height)){control.DrawToBitmap(child,new Rectangle(0,0,child.Width,child.Height));graphics.DrawImageUnscaled(child,control.Left+dx,control.Top+dy);}
                    }
                    bitmap.Save(renderPath,System.Drawing.Imaging.ImageFormat.Png);
                }return null;
            }
            if(form.ShowDialog()!=DialogResult.OK)return null;folder=path.Text;mask=0;for(int i=0;i<5;i++)if(boxes[i].Checked)mask|=1<<i;crt=boxes[5].Checked;qt=boxes[6].Checked;return action;
        }
    }
    [STAThread]public static int Main(string[] args) {
        bool interactive=args.Length==0;try {
            manifest=Load<Manifest>(Safe(Package,"manifest.json"));
            if(manifest.version!="1.0.0"||manifest.originalSha256!="0e0768693a62ba89fcd5f1fd56dfcda68206d32bc6d5b5c285792996115061e3"||manifest.runtime.Length!=13||manifest.variants.Length!=24)throw new Exception("Manifiesto de version inesperado.");
#if QA
            if(args.Length==2&&args[0]=="--render-ui") {
                int previewMask=31;bool previewCRT=true,previewQT=true;string previewFolder=@"C:\SteamLibrary\steamapps\common\WarBreeds";
                Choose(ref previewMask,ref previewCRT,ref previewQT,ref previewFolder,args[1]);return 0;
            }
#endif
            string action="install",folder=null;int mask=31;bool crt=true,qt=true,offline=false;int[] canvas=Desktop();
            for(int i=0;i<args.Length;i++) {
                switch(args[i]) {
                    case "--game":folder=args[++i];break;case "--action":action=args[++i];break;case "--mask":mask=Int32.Parse(args[++i]);break;
                    case "--no-crt":crt=false;break;case "--no-quicktime":qt=false;break;case "--offline":offline=true;break;
                    case "--canvas":string[] size=args[++i].Split('x');canvas=new[]{Int32.Parse(size[0]),Int32.Parse(size[1])};break;
#if QA
                    case "--test-fail-after":failAfter=Int32.Parse(args[++i]);break;
#endif
                    default:throw new Exception("Parametro desconocido: "+args[i]);
                }
            }
            if(interactive){action=Choose(ref mask,ref crt,ref qt,ref folder);if(action==null)return 0;}
            if(folder==null)throw new Exception("Indicar --game o abrir sin parametros para elegir carpeta.");ValidateRoot(folder);
            Console.WriteLine("WarBreeds Fixes "+manifest.version+" - opciones independientes. Lienzo de peliculas: "+canvas[0]+"x"+canvas[1]);
            if(action=="install")Install(mask,crt,qt,offline,canvas);else if(action=="restore")Restore();else if(action=="status")Status();else throw new Exception("Accion desconocida.");
            if(interactive)MessageBox.Show("Operacion completada. Revisar la consola para el detalle.","WarBreeds Fixes",MessageBoxButtons.OK,MessageBoxIcon.Information);return 0;
        } catch(Exception ex) {
#if QA
            Console.Error.WriteLine(ex.ToString());
#else
            Console.Error.WriteLine("ERROR: "+ex.Message);
#endif
            if(interactive)MessageBox.Show(ex.Message,"WarBreeds Fixes",MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
        finally {if(interactive){Console.WriteLine("Pulsar Enter para cerrar.");Console.ReadLine();}}
    }
}
