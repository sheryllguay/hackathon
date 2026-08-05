import hashlib, itertools, re

target = "968c2349040273dd57dc4be7e238c5ac200ceac5"

alice = ["alice","Alice","ALICE"]
john  = ["johnson","Johnson","JOHNSON"]
nick  = ["aj","AJ","Aj"]
birth = ["15-07-1990","15-7-1990","15071990","150790","1507199","15-07-90","15-7-90","1990","15","07","15071990","1507199","150790"]
bob   = ["bob","Bob","BOB"]
char  = ["charlie","Charlie","CHARLIE"]

seps = ["","-","_",".","@","#","!","1","123"]

names = alice+john+nick+bob+char
bparts = ["15-07-1990","15-7-1990","15071990","15071990","150790","1990","15","07","90","1507","071990"]

cands = set()
# simple name + birthdate combos
for n in names:
    for b in bparts:
        for s in seps:
            cands.add(n+s+b)
            cands.add(b+s+n)
# two names combos
for a in alice+john+nick:
    for c in char:
        for s in seps:
            cands.add(a+s+c)
            cands.add(c+s+a)
        for b in bparts:
            cands.add(a+s+c+s+b)

for pw in cands:
    if hashlib.sha1(pw.encode()).hexdigest()==target:
        print("FOUND:", repr(pw)); break
else:
    print("not found in", len(cands))
