"""Instruction-shape checks only, not a constant-time verifier."""
from pathlib import Path
import json
import re
ROOT=Path(__file__).resolve().parents[1]

def main():
    text=(ROOT/'build'/'prismguard32.s').read_text(encoding='utf-8')
    blocks=re.split(r'\n\s*\.def\s+',text)
    markers={'release':'masked7release','refresh':'masked7refresh','add':'masked3add',
             'sub':'masked3sub','multiply':'masked8multiply'}
    result={}
    for label,marker in markers.items():
        candidates=[block for block in blocks if marker in block.splitlines()[0] and '?dtor' not in block.splitlines()[0]]
        assert len(candidates)==1,(label,len(candidates))
        body=candidates[0]
        branches=re.findall(r'^\s*(j(?!mp)[a-z]+)\s',body,re.M)
        divisions=re.findall(r'^\s*(?:i?div)[bwlq]?\s',body,re.M)
        assert not branches and not divisions,(label,branches,divisions)
        result[label]={'conditional_jump_instructions':0,'integer_division_instructions':0,
                       'conditional_move_instructions':len(re.findall(r'^\s*cmov\w+',body,re.M))}
    report={'target':'Rust 1.89.0 x86_64-pc-windows-msvc opt-level=3 overflow-checks=yes',
            'function_shape_checks':result,'whole_library_integer_divisions':len(re.findall(r'^\s*(?:i?div)[bwlq]?\s',text,re.M)),
            'limits':'Calls to entropy-provider bounds checks are not inlined into these bodies. This checks instruction shape, not dataflow, compiler preservation, hardware timing, transitions or leakage.'}
    (ROOT/'evidence'/'assembly-review.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
