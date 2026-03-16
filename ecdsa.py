#!/usr/bin/env python3
"""ECDSA signature on secp256k1 (Bitcoin curve)."""
import hashlib, random, sys

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def modinv(a, m): return pow(a, -1, m)
def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1,y1=p1; x2,y2=p2
    if x1==x2 and y1!=y2: return None
    if x1==x2: lam=(3*x1*x1)*modinv(2*y1,P)%P
    else: lam=(y2-y1)*modinv(x2-x1,P)%P
    x3=(lam*lam-x1-x2)%P; y3=(lam*(x1-x3)-y1)%P
    return (x3,y3)
def scalar_mult(k, point):
    result=None; addend=point
    while k:
        if k&1: result=point_add(result, addend)
        addend=point_add(addend, addend); k>>=1
    return result

def sign(msg, privkey):
    z=int(hashlib.sha256(msg.encode()).hexdigest(),16)%N
    k=random.randrange(1,N); R=scalar_mult(k,(Gx,Gy))
    r=R[0]%N; s=(modinv(k,N)*(z+r*privkey))%N
    return r,s
def verify(msg, sig, pubkey):
    r,s=sig; z=int(hashlib.sha256(msg.encode()).hexdigest(),16)%N
    w=modinv(s,N); u1=(z*w)%N; u2=(r*w)%N
    P1=scalar_mult(u1,(Gx,Gy)); P2=scalar_mult(u2,pubkey)
    R=point_add(P1,P2)
    return R is not None and R[0]%N==r

if __name__ == "__main__":
    random.seed(42)
    priv=random.randrange(1,N); pub=scalar_mult(priv,(Gx,Gy))
    msg="Hello ECDSA!"
    sig=sign(msg,priv)
    ok=verify(msg,sig,pub)
    print(f"Message: {msg}")
    print(f"Signature: (r={hex(sig[0])[:20]}..., s={hex(sig[1])[:20]}...)")
    print(f"Valid: {ok}")
    print(f"Tampered: {verify('tampered',sig,pub)}")
