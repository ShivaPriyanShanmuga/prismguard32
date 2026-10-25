"""Prepare a sanitized public export and verified archive. No deletion.
Only the new project is copied. No browser/account data or existing user files.
"""
from pathlib import Path
import hashlib
import json
import re
import shutil
import zipfile

ROOT=Path(__file__).resolve().parents[1]
RELEASE=ROOT/'release';PUBLIC=RELEASE/'public-source'
OMIT={'tools/narrate.ps1','evidence/baseline-preservation.json','docs/SUBMISSION-STATUS.md'}
TEXT={'.rs','.py','.ps1','.md','.tex','.toml','.json','.jsonl','.csv','.txt','.ffconcat','.s'}

def main():
    RELEASE.mkdir(exist_ok=True);PUBLIC.mkdir(exist_ok=True)
    selected=[]
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file():continue
        rel=path.relative_to(ROOT);key=rel.as_posix()
        if rel.parts[0] in {'build','release'} or '__pycache__' in rel.parts or key in OMIT or path.suffix=='.pyc':continue
        selected.append((path,key))
    selected.append((ROOT/'build'/'prismguard32.s','evidence/target-library.s'))
    manifest={}
    for source,key in selected:
        target=PUBLIC/key;target.parent.mkdir(parents=True,exist_ok=True)
        data=source.read_bytes()
        if source.suffix.lower() in TEXT or source.name in {'LICENSE','.gitignore','.gitattributes'}:
            text=data.decode('utf-8').replace('\r\n','\n')
            for base,label in [(ROOT,'<project>'),(Path.home(),'<user-home>')]:
                for variant in [str(base),str(base).replace('\\','/'),str(base).replace('\\','\\\\')]:text=text.replace(variant,label)
            assert not re.search(r"[A-Za-z]:[\\/]+Users[\\/]+[A-Za-z0-9._-]+",text),key
            data=text.encode('utf-8')
        target.write_bytes(data)
        manifest[key]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
    (PUBLIC/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    archive=RELEASE/'PrismGuard-32-review-kit.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
        for key in sorted(manifest):z.write(PUBLIC/key,'PrismGuard-32/'+key)
        z.write(PUBLIC/'MANIFEST.json','PrismGuard-32/MANIFEST.json')
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name in z.namelist():assert name.startswith('PrismGuard-32/') and '..' not in Path(name).parts
        for key,info in manifest.items():assert hashlib.sha256(z.read('PrismGuard-32/'+key)).hexdigest()==info['sha256']
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (RELEASE/'SHA256.txt').write_text(f'{digest}  {archive.name}\n',encoding='ascii')
    shutil.copyfile(ROOT/'build'/'prismguard32.exe',RELEASE/'PrismGuard-32-demo.exe')
    print(json.dumps({'archive':str(archive),'public_files':len(manifest)+1,'bytes':archive.stat().st_size,'sha256':digest,
                      'debug_binaries_exported':False,'absolute_user_paths_exported':False}))

if __name__=='__main__':main()
