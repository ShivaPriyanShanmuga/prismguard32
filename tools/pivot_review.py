"""Exact F5 experiment for a rejected secret-matrix pivot, not a new cipher.
Shows why changing the algebraic appearance does not settle originality.
"""
from collections import Counter
from itertools import product
from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = 5
    matrices = [(a,b,c,d) for a,b,c,d in product(range(p), repeat=4)
                if (a*d-b*c) % p]
    assert len(matrices) == (p*p-1)*(p*p-p) == 480
    def apply(matrix, message):
        a,b,c,d = matrix
        return ((a*message+b) % p, (c*message+d) % p)
    distributions = [Counter(apply(mat, m) for mat in matrices) for m in range(p)]
    assert all(dist == distributions[0] for dist in distributions)
    assert len(distributions[0]) == p*p-1
    assert set(distributions[0].values()) == {20}
    recovered = 0
    for mat in matrices:
        for m0, m1 in product(range(p), repeat=2):
            if m0 == m1: continue
            u0,v0 = apply(mat, m0); u1,v1 = apply(mat, m1)
            inv = pow((m1-m0) % p, -1, p)
            a, c = (u1-u0)*inv % p, (v1-v0)*inv % p
            guess = (a, (u0-a*m0) % p, c, (v0-c*m0) % p)
            assert guess == mat
            recovered += 1
    report = {'field': p, 'invertible_matrices': len(matrices),
              'lift': '(m,1)', 'outputs_per_message': 24,
              'matrices_per_output': 20, 'one_use_distributions_equal': True,
              'reused_matrix_two_known_plaintext_recoveries': recovered,
              'decision': 'Reject as an originality fix: established secret linear-map '
                          'ideas, larger material, and one-use assumptions remain. '
                          'A toy secrecy argument is not evidence of a new primitive.'}
    (ROOT/'evidence').mkdir(exist_ok=True)
    (ROOT/'evidence'/'pivot-review.json').write_text(json.dumps(report, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(report, indent=2))

if __name__ == '__main__': main()
