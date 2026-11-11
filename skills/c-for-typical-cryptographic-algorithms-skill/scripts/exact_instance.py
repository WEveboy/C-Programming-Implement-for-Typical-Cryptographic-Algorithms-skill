"""Bounded educational arithmetic, JSON stdin -> JSON stdout; no production crypto."""
import json
import math
import sys


def integer(x, name, lo=0, hi=(1 << 64)-1):
    if type(x) is not int or not lo <= x <= hi:
        raise ValueError(f'{name}: integer outside [{lo}, {hi}]')
    return x


def prime(p):
    integer(p, 'prime', 2, 65535)
    if any(p % d == 0 for d in range(2, math.isqrt(p)+1)):
        raise ValueError('expected prime')
    return p


def vector(v, n=None):
    if not isinstance(v, list) or not 1 <= len(v) <= 32 or (n is not None and len(v) != n):
        raise ValueError('invalid vector length (1..32)')
    for x in v:
        integer(x, 'coefficient', -65535, 65535)
    return v


def conv(a, b):
    n = len(a)
    return [sum(a[i]*b[(j-i) % n] for i in range(n)) for j in range(n)]


def point_add(P, Q, p, a):
    if P is None: return Q
    if Q is None: return P
    x, y = P; u, v = Q
    if x == u and (y+v) % p == 0: return None
    slope = ((3*x*x+a)*pow(2*y, -1, p) if P == Q else (v-y)*pow(u-x, -1, p)) % p
    rx = (slope*slope-x-u) % p
    return [rx, (slope*(x-rx)-y) % p]


def solve(d):
    if not isinstance(d, dict): raise ValueError('expected JSON object')
    alg = d['algorithm']
    if alg == 'rsa':
        p = prime(d['p']); q = prime(d['q'])
        if p == q: raise ValueError('p and q must differ')
        n = p*q; phi = (p-1)*(q-1)
        e = integer(d['e'], 'e', 2, phi-1)
        m = integer(d['message'], 'message', 0, n-1)
        if math.gcd(e, phi) != 1: raise ValueError('e not invertible')
        secret = pow(e, -1, phi); c = pow(m, e, n)
        return dict(n=n, d=secret, ciphertext=c, recovered=pow(c, secret, n))
    if alg == 'paillier':
        p = prime(d['p']); q = prime(d['q'])
        if p == q or min(p, q) == 2: raise ValueError('distinct odd primes required')
        n = p*q; ns = n*n; lam = math.lcm(p-1, q-1)
        g = integer(d.get('g', n+1), 'g', 1, ns-1)
        r = integer(d['r'], 'r', 1, n-1); m = integer(d['message'], 'message', 0, n-1)
        if math.gcd(r, n) != 1 or math.gcd(g, ns) != 1: raise ValueError('r/g must be units')
        u = pow(g, lam, ns)
        if (u-1) % n or math.gcd((u-1)//n, n) != 1: raise ValueError('invalid L(g^lambda)')
        mu = pow((u-1)//n, -1, n); c = pow(g, m, ns)*pow(r, n, ns) % ns
        v = pow(c, lam, ns)
        if (v-1) % n: raise ValueError('L not exactly divisible')
        return dict(n=n, ciphertext=c, recovered=(v-1)//n*mu % n)
    if alg == 'mh':
        b = vector(d['private']); n = integer(d['modulus'], 'modulus', 2)
        w = integer(d['multiplier'], 'multiplier', 1, n-1); bits = vector(d['bits'], len(b))
        if any(x not in [0, 1] for x in bits): raise ValueError('binary message required')
        if any(x <= sum(b[:i]) for i, x in enumerate(b)) or n <= sum(b) or math.gcd(w, n) != 1:
            raise ValueError('superincreasing / modulus / inverse precondition')
        public = [w*x % n for x in b]; c = sum(x*y for x, y in zip(bits, public))
        rem = c*pow(w, -1, n) % n; recovered = [0]*len(b)
        for i in range(len(b)-1, -1, -1):
            if rem >= b[i]: recovered[i] = 1; rem -= b[i]
        return dict(public=public, ciphertext=c, recovered=recovered, remaining=rem)
    if alg == 'elgamal':
        p = prime(d['p']); g = integer(d['g'], 'g', 2, p-1)
        a = integer(d['private'], 'private', 1, p-2); k = integer(d['nonce'], 'nonce', 1, p-2)
        m = integer(d['message'], 'message', 1, p-1)
        # Full multiplicative group only; reject a proper-subgroup generator.
        if len({pow(g, i, p) for i in range(1, p)}) != p-1: raise ValueError('g is not primitive')
        y = pow(g, a, p); c1 = pow(g, k, p); c2 = m*pow(y, k, p) % p
        return dict(public=y, ciphertext=[c1, c2], recovered=c2*pow(pow(c1, a, p), -1, p) % p)
    if alg == 'ecc':
        p = prime(d['p'])
        if p <= 3: raise ValueError('short Weierstrass requires p > 3')
        a = integer(d['a'], 'a', 0, p-1); b = integer(d['b'], 'b', 0, p-1)
        if (4*a*a*a+27*b*b) % p == 0: raise ValueError('singular curve')
        P = d['point']
        if P is not None:
            vector(P, 2)
            x, y = P
            if not (0 <= x < p and 0 <= y < p) or (y*y-x*x*x-a*x-b) % p:
                raise ValueError('invalid curve point')
        k = integer(d['scalar'], 'scalar', 0, (1 << 32)-1); out = None
        while k:
            if k & 1: out = point_add(out, P, p, a)
            P = point_add(P, P, p, a); k >>= 1
        return dict(point=out)
    if alg == 'ntru':
        f = vector(d['f']); n = len(f); g = vector(d['g'], n); m = vector(d['message'], n)
        r = vector(d['r'], n); fp = vector(d['fp'], n); fq = vector(d['fq'], n)
        p = prime(d['p']); q = integer(d['q'], 'q', p+1, 65535)
        unit = [1]+[0]*(n-1)
        if [x % p for x in conv(f, fp)] != unit or [x % q for x in conv(f, fq)] != unit:
            raise ValueError('incorrect polynomial inverse')
        h = [x % q for x in conv(fq, g)]
        c = [(p*x+y) % q for x, y in zip(conv(r, h), m)]
        raw = [p*x+y for x, y in zip(conv(r, g), conv(f, m))]
        # Tie for even q is represented by -q/2: interval [-floor(q/2), ceil(q/2)).
        if any(not -(q//2) <= x < (q+1)//2 for x in raw): raise ValueError('decryption wrap risk')
        centered = [(x+q//2) % q-q//2 for x in conv(f, c)]
        return dict(public=h, ciphertext=c, centered=centered, recovered=[x % p for x in conv(fp, centered)])
    if alg == 'mceliece-toy':
        G = d['generator']
        if not isinstance(G, list) or not 1 <= len(G) <= 10: raise ValueError('toy k must be 1..10')
        n = len(vector(G[0])); k = len(G)
        for row in G:
            vector(row, n)
            if any(x not in [0, 1] for x in row): raise ValueError('binary generator required')
        c = vector(d['ciphertext'], n); t = integer(d['t'], 't', 0, n)
        if any(x not in [0, 1] for x in c): raise ValueError('binary ciphertext required')
        words = []
        for mask in range(1 << k):
            bits = [(mask >> i) & 1 for i in range(k)]
            words.append((bits, [sum(bits[i]*G[i][j] for i in range(k)) % 2 for j in range(n)]))
        if len({tuple(w) for _, w in words}) != len(words): raise ValueError('generator rank deficient')
        distance = min(sum(w) for _, w in words[1:])
        if distance < 2*t+1: raise ValueError('distance insufficient')
        hits = [(bits, w) for bits, w in words if sum(x != y for x, y in zip(w, c)) <= t]
        if len(hits) != 1: raise ValueError('uncorrectable ciphertext')
        return dict(message=hits[0][0], codeword=hits[0][1], minimum_distance=distance)
    raise ValueError('unsupported algorithm')


def main():
    try:
        data = sys.stdin.buffer.read(65537)
        if len(data) > 65536: raise ValueError('input exceeds 64 KiB')
        result = solve(json.loads(data))
        print(json.dumps(dict(status='ok', result=result), ensure_ascii=False))
    except (ValueError, KeyError, TypeError, IndexError, OverflowError) as error:
        print(json.dumps(dict(status='rejected', reason=str(error)), ensure_ascii=False))
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
