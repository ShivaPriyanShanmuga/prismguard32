"""Independent exact correlated-mask audit, compared with the Rust schedule.
Only synthetic arithmetic; writes its own build/evidence files. No downloads.
"""
from itertools import product
from pathlib import Path
import json
import hashlib
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def histogram(a, b, offset):
    counts = [[0] * 5 for _ in range(19)]
    for u, da, db, rho in product(range(5), repeat=4):
        v = (u + offset) % 5
        ar, br = (a-u) % 5, (b-v) % 5
        x, y = (u+da) % 5, (v+db) % 5
        xr, yr = (a-x) % 5, (b-y) % 5
        p00, p01, p10, p11 = x*y % 5, x*yr % 5, xr*y % 5, xr*yr % 5
        left, t0 = (p00+rho) % 5, (p01-rho) % 5
        # Independent expanded output expression checks the scheduled sum.
        right = (a*b - x*y - rho) % 5
        assert right == (t0+p10+p11) % 5
        assert (left+right) % 5 == a*b % 5
        wires = [u, ar, da, x, xr, v, br, db, y, yr, rho,
                 p00, p01, p10, p11, left, t0, (t0+p10) % 5, right]
        for row, value in zip(counts, wires): row[value] += 1
    return counts

def main():
    build, evidence = ROOT/'build', ROOT/'evidence'
    build.mkdir(exist_ok=True); evidence.mkdir(exist_ok=True)
    binary = build/'correlation-audit.exe'
    subprocess.run(['rustc', '--edition=2021', '-D', 'warnings', '-C', 'opt-level=3',
                    '-C', 'overflow-checks=yes', '--cfg', 'feature="audit"',
                    '--cfg', 'feature="fixtures"', 'tools/correlation_audit.rs',
                    '-o', str(binary)], cwd=ROOT, check=True)
    rust = json.loads(subprocess.check_output([str(binary)], cwd=ROOT, text=True))
    for offset in range(5):
        expected = histogram(0, 0, offset)
        assert expected == rust['reference_histograms_per_offset'][offset]
        for a, b in product(range(5), repeat=2):
            assert histogram(a, b, offset) == expected, (offset, a, b)
    expected = histogram(0, 0, 0)
    assert expected == rust['squaring_reference_histograms']
    for a in range(5): assert histogram(a, a, 0) == expected
    broken = [[sum(u*(a-u) % 5 == value for u in range(5))
               for value in range(5)] for a in range(5)]
    tv = sum(abs(x-y) for x, y in zip(broken[0], broken[1])) / 10
    assert tv > 0 and tv == rust['missing_refresh_control_tv']
    assert rust['correlated_executions'] == 78125
    assert rust['squaring_executions'] == 3125
    assert rust['distribution_mismatches'] == 0
    report = {'source_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                for name in ['src/lib.rs', 'src/masked.rs', 'src/field.rs', 'src/entropy.rs',
                             'tools/correlation_audit.rs', 'tools/correlation_audit.py']},
        'rust': rust, 'independent_python': {
        'correlated_executions': 78125, 'squaring_executions': 3125,
        'wire_comparisons': 2470, 'distribution_mismatches': 0,
        'missing_refresh_control_histograms_a0_a1': broken[:2],
        'missing_refresh_control_tv': tv},
        'meaning': 'Fresh independent operand refresh handles these correlated-share cases. '
                   'A missing-refresh control leaks. This finite gadget experiment does '
                   'not prove arbitrary composition, a complete protocol, or physical resistance.'}
    (evidence/'correlation-audit.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({key: value for key, value in rust.items()
                      if 'histogram' not in key}, indent=2))

if __name__ == '__main__': main()
