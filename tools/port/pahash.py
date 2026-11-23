import struct
M=0xffffffff
def _rot(x,k): return ((x<<k)|(x>>(32-k)))&M
def hashlittle(data,initval=0xC5EDE):
    """Bob Jenkins lookup3 hashlittle; Crimson Desert uses initval 0xC5EDE."""
    n=len(data); a=b=c=(0xdeadbeef+n+initval)&M; i=0
    while n>12:
        a=(a+struct.unpack_from('<I',data,i)[0])&M; b=(b+struct.unpack_from('<I',data,i+4)[0])&M; c=(c+struct.unpack_from('<I',data,i+8)[0])&M
        a=(a-c)&M;a^=_rot(c,4);c=(c+b)&M; b=(b-a)&M;b^=_rot(a,6);a=(a+c)&M; c=(c-b)&M;c^=_rot(b,8);b=(b+a)&M
        a=(a-c)&M;a^=_rot(c,16);c=(c+b)&M; b=(b-a)&M;b^=_rot(a,19);a=(a+c)&M; c=(c-b)&M;c^=_rot(b,4);b=(b+a)&M
        n-=12;i+=12
    if n==0: return c
    t=data[i:]+b'\0'*12
    a=(a+struct.unpack_from('<I',t,0)[0])&M
    if n>4: b=(b+struct.unpack_from('<I',t,4)[0])&M
    if n>8: c=(c+struct.unpack_from('<I',t,8)[0])&M
    c^=b;c=(c-_rot(b,14))&M; a^=c;a=(a-_rot(c,11))&M; b^=a;b=(b-_rot(a,25))&M
    c^=b;c=(c-_rot(b,16))&M; a^=c;a=(a-_rot(c,4))&M; b^=a;b=(b-_rot(a,14))&M; c^=b;c=(c-_rot(b,24))&M
    return c
