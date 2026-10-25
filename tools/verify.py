"""Reproduce the project evidence without downloads, installation or deletion.
All writes are inside PrismGuard-32. Existing baseline is read-only.
"""
from pathlib import Path
import hashlib
import json
import platform
import re
import subprocess
import sys
import shutil

ROOT=Path(__file__).resolve().parents[1]
BUILD=ROOT/'build';EVIDENCE=ROOT/'evidence'
OPT=['rustc','--edition=2021','-D','warnings','-C','opt-level=3','-C','overflow-checks=yes']

def run(args,expected=0):
    p=subprocess.run(args,cwd=ROOT,text=True,encoding='utf-8',errors='replace',capture_output=True)
    if p.returncode!=expected:raise RuntimeError(f'{args}\n{p.stdout}\n{p.stderr}')
    return p.stdout+p.stderr

def baseline_hashes():
    baseline=ROOT.parent/'PrismLock-32'
    return {str(p.relative_to(baseline)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(baseline.rglob('*')) if p.is_file()}

def compile_fail(name,body,error):
    p=BUILD/f'{name}_must_not_compile.rs'
    p.write_text('#[allow(dead_code)]\n#[path="../src/lib.rs"]mod prism;\nfn main(){'+body+'}\n',encoding='utf-8')
    proc=subprocess.run(['rustc','--edition=2021',str(p),'-o',str(BUILD/f'{name}_unexpected.exe')],cwd=ROOT,text=True,capture_output=True)
    assert proc.returncode!=0 and error in proc.stderr,proc.stderr
    (EVIDENCE/f'{name}.txt').write_text(proc.stderr,encoding='utf-8')
    return {'expected_error':error,'rejected_by_compiler':True}

def main():
    before=baseline_hashes()
    print('Building isolated source and running functional tests...',flush=True)
    run(['rustc','--edition=2021','-D','warnings','--test','src/lib.rs','-o',str(BUILD/'tests.exe')])
    tests=run([str(BUILD/'tests.exe'),'--nocapture']);assert '14 passed; 0 failed' in tests
    (EVIDENCE/'rust-tests.txt').write_text(tests,encoding='utf-8')
    run(OPT+['src/main.rs','-o',str(BUILD/'prismguard32.exe')])
    run(OPT+['--cfg','feature="audit"','--cfg','feature="fixtures"','tools/audit.rs','-o',str(BUILD/'audit.exe')])
    for name in ['timing','benchmark']:
        run(OPT+['--cfg','feature="fixtures"',f'tools/{name}.rs','-o',str(BUILD/f'{name}.exe')])
    print('Comparing independent reference and exact probing models...',flush=True)
    reference=json.loads(run([sys.executable,'tools/reference.py']))
    model=json.loads(run([str(BUILD/'audit.exe'),'model']))
    mutations=json.loads(run([str(BUILD/'audit.exe'),'fuzz']))
    (EVIDENCE/'gadget-model.json').write_text(json.dumps(model,indent=2)+'\n',encoding='utf-8')
    (EVIDENCE/'mutation-tests.json').write_text(json.dumps(mutations,indent=2)+'\n',encoding='utf-8')
    sender=compile_fail('sender-reuse','let mut e=prism::entropy::Entropy::system().unwrap();let(s,_)=prism::provision([0;16],&mut e).unwrap();let m=prism::ingest(prism::Secret32::new([0;32]),&mut e).unwrap();let _=prism::seal(s,&m,b"x",&mut e);let _=prism::seal(s,&m,b"x",&mut e);','E0382')
    receiver=compile_fail('receiver-clone','let mut e=prism::entropy::Entropy::system().unwrap();let(_,r)=prism::provision([0;16],&mut e).unwrap();let _=r.clone();','E0599')
    print('Measuring seal/open and full OS-RNG workflow...',flush=True)
    benchmarks=[json.loads(line) for line in run([str(BUILD/'benchmark.exe')]).splitlines()]
    (EVIDENCE/'benchmark.json').write_text(json.dumps(benchmarks,indent=2)+'\n',encoding='utf-8')
    timing=[]
    if (EVIDENCE/'timing.json').exists() and not (EVIDENCE/'timing-before-raw-retention.json').exists():
        shutil.copyfile(EVIDENCE/'timing.json',EVIDENCE/'timing-before-raw-retention.json')
    for seed in [20261025,90731,481516]:
        print(f'Timing diagnostic run {len(timing)+1}/3 (10,000 samples per class)...',flush=True)
        entries=[json.loads(line) for line in run([str(BUILD/'timing.exe'),'10000',str(seed),'raw']).splitlines()]
        cases=[entry for entry in entries if 'case' in entry]
        for entry in entries:
            if 'raw_samples_for' in entry:
                path=EVIDENCE/f"timing-{seed}-{entry['raw_samples_for']}.csv"
                path.write_text('class,nanoseconds\n'+''.join(f'{group},{ns}\n' for group,ns in entry['ordered_class_and_ns']),encoding='ascii')
        assert len(cases)==4
        control=next(case for case in cases if case['negative_control'])
        assert control['max_abs_t_with_cropping']>10,'Timing negative control was not detected'
        timing.append({'seed':seed,'cases':cases})
    (EVIDENCE/'timing.json').write_text(json.dumps(timing,indent=2)+'\n',encoding='utf-8')
    print('Saving target assembly and demo output...',flush=True)
    run(OPT+['--crate-type','lib','--emit','asm','src/lib.rs','-o',str(BUILD/'prismguard32.s')])
    asm=(BUILD/'prismguard32.s').read_text(encoding='utf-8')
    division=len(re.findall(r'^\s*(?:i?div)[bwlq]?\s',asm,re.M))
    assert division==0
    assembly_review=json.loads(run([sys.executable,'tools/assembly_review.py']))
    demo=run([str(BUILD/'prismguard32.exe'),'demo']);(EVIDENCE/'demo-output.txt').write_text(demo,encoding='utf-8')
    after=baseline_hashes();assert before==after,'Baseline changed during verification'
    (EVIDENCE/'baseline-preservation.json').write_text(json.dumps({'unchanged':True,'files_compared':len(before),'sha256':before},indent=2)+'\n',encoding='utf-8')
    timing_signals=[{'seed':r['seed'],'case':c['case'],'max_abs_t':c['max_abs_t_with_cropping']}
                    for r in timing for c in r['cases'] if not c['negative_control'] and c['max_abs_t_with_cropping']>4.5]
    report={'compiler':run(['rustc','--version']).strip(),'target':platform.machine(),'platform':platform.platform(),
            'functional_test_groups':14,'single_bit_capsule_modifications':832,'byte_value_roundtrips':256,
            'reference':reference,'gadget_model':model,'mutations':mutations,'sender_reuse':sender,'receiver_clone':receiver,
            'benchmark':benchmarks,'timing_runs':timing,'timing_exploratory_signals_over_4_5':timing_signals,
            'integer_division_instructions':division,'baseline_unchanged':before==after,
            'assembly_shape_checks':assembly_review,
            'security_scope':'Ideal arithmetic circuit: single field-wire distribution argument + exact F5 gadget enumeration. No whole-protocol formal verifier, compiler proof, hardware power/EM test or independent human audit.',
            'source_sha256':{str(p.relative_to(ROOT)).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest()
                             for folder in ['src','tools'] for p in sorted((ROOT/folder).glob('*')) if p.suffix in ['.rs','.py']}}
    (EVIDENCE/'verification.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'functional_groups':14,'vectors':reference['wire_vectors'],'arithmetic_operations':reference['arithmetic_operations'],
                      'gadget_executions_each_implementation':model['executions'],'negative_control_tv':model['unsafe_cross_sum_total_variation'],
                      'benchmark':benchmarks,'timing_signals':timing_signals,'baseline_unchanged':True},indent=2),flush=True)

if __name__=='__main__':main()
