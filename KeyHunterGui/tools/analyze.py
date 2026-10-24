import json, struct, sys, os, math, random, base64, textwrap

# Stage 2: reconstruct the private exponent from the recorded limb-multiply
# operands, verify it, factor n, and export PEM/KEY.

def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def der_int(v):
    b = v.to_bytes((v.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + der_len(len(b)) + b

def der_seq(*parts):
    body = b"".join(parts)
    return b"\x30" + der_len(len(body)) + body

def der_octet(b):
    return b"\x04" + der_len(len(b)) + b

def pem(der, label):
    b64 = base64.b64encode(der).decode()
    return ("-----BEGIN %s-----\n" % label) + "\n".join(textwrap.wrap(b64, 64)) + ("\n-----END %s-----\n" % label)

def main():
    d = sys.argv[1] if len(sys.argv) > 1 else r"D:\Project\SignPKCS_rewrite\tool\out"
    meta = json.load(open(os.path.join(d, "meta.json")))
    n = int(meta["n"], 16)
    sig = bytes.fromhex(meta["signature"])
    h = bytes.fromhex(meta["hash"])
    e = int(meta["e"])
    ops = open(os.path.join(d, "ops.bin"), "rb").read()
    recs = [struct.unpack_from("<II", ops, i) for i in range(0, len(ops), 8)]

    print("[*] n bits=%d  e=%d  ops=%d" % (n.bit_length(), e, len(recs)))
    if len(recs) % 64 != 0:
        print("[!] op count not a multiple of 64:", len(recs) % 64)
    blocks = len(recs) // 64
    B = []
    for k in range(blocks):
        blk = recs[k * 64:(k + 1) * 64]
        v = 0
        for i, (a, b) in enumerate(blk):
            v |= b << (32 * i)
        B.append(v)
    print("[*] %d 2048-bit multipliers reconstructed" % blocks)

    DI = bytes.fromhex("3031300d060960864801650304020105000420")
    EM = b"\x00\x01" + b"\xff" * (256 - 3 - 19 - 32) + b"\x00" + DI + h
    m = int.from_bytes(EM, "big")
    s = int.from_bytes(sig, "big")

    R = 1 << 2048
    invR = pow(R, -1, n)
    def mont(a, b):
        return (a * b % n) * invR % n

    best = None
    for start in range(0, min(4, blocks - 2)):
        for base_idx in (start + 1, start + 2):
            if base_idx >= blocks:
                continue
            base = B[base_idx]
            seq = []
            k = start
            cur = B[k]
            ok = 0
            unknown = 0
            for j in range(base_idx, blocks - 1):
                x, y = B[j], B[j + 1]
                if y == mont(x, x):
                    seq.append("S"); ok += 1
                elif y == mont(x, base):
                    seq.append("M"); ok += 1
                else:
                    seq.append("?"); unknown += 1
            if unknown == 0 and len(seq) > 100:
                best = (start, base_idx, base, seq)
                break
        if best:
            break

    if not best:
        print("[!] no consistent square/multiply chain found")
        return 2

    start, base_idx, base, seq = best
    print("[*] chain found: start=%d base=B[%d] steps=%d (S=%d, M=%d)"
          % (start, base_idx, len(seq), seq.count("S"), seq.count("M")))

    kval = 1
    for o in seq:
        if o == "S":
            kval *= 2
        else:
            kval += 1

    if pow(m, kval, n) != s:
        print("[!] reconstructed exponent does not verify")
        return 3
    print("[+] exponent verified: pow(m, d, n) == signature   (d bits=%d, hamming=%d)"
          % (kval.bit_length(), bin(kval).count("1")))

    # ---- factor n from (e, d) ----
    kk = e * kval - 1
    t = 0
    r = kk
    while r % 2 == 0:
        r //= 2
        t += 1
    random.seed(1)
    p = q = None
    for _ in range(500):
        g = random.randrange(2, n - 1)
        x = pow(g, r, n)
        if x in (1, n - 1):
            continue
        for _ in range(t):
            y = x * x % n
            if y == 1:
                f = math.gcd(x - 1, n)
                if 1 < f < n:
                    p = f
                break
            x = y
        if p:
            break
    if not p:
        print("[!] factorisation failed (d may be blinded)")
        return 4
    q = n // p
    if q > p:
        p, q = q, p
    assert p * q == n
    print("[+] factored: p bits=%d, q bits=%d" % (p.bit_length(), q.bit_length()))

    dmod = kval % (math.lcm(p - 1, q - 1))
    dp = kval % (p - 1)
    dq = kval % (q - 1)
    qinv = pow(q, -1, p)
    assert (e * dp) % (p - 1) == 1 and (e * dq) % (q - 1) == 1

    rsa = der_seq(der_int(0), der_int(n), der_int(e), der_int(kval),
                  der_int(p), der_int(q), der_int(dp), der_int(dq), der_int(qinv))
    alg = der_seq(b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01", b"\x05\x00")
    p8 = der_seq(der_int(0), alg, der_octet(rsa))

    open(os.path.join(d, "private_pkcs1.pem"), "w").write(pem(rsa, "RSA PRIVATE KEY"))
    open(os.path.join(d, "private_pkcs8.pem"), "w").write(pem(p8, "PRIVATE KEY"))

    def hx(v):
        hh = format(v, "x")
        if len(hh) % 2:
            hh = "0" + hh
        return "\n    ".join(hh[i:i + 64] for i in range(0, len(hh), 64))
    lines = ["SignPKCS — extracted RSA key", "=" * 60, ""]
    for name, val in [("n (modulus)", n), ("e", e), ("d", kval), ("p", p), ("q", q),
                      ("dp", dp), ("dq", dq), ("qinv", qinv)]:
        lines += ["%s:" % name, "    " + hx(val), ""]
    open(os.path.join(d, "KEY.txt"), "w").write("\n".join(lines))
    print("[+] wrote KEY.txt, private_pkcs1.pem, private_pkcs8.pem to " + d)
    return 0

if __name__ == "__main__":
    sys.exit(main())
