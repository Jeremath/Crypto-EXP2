p = 1009
q = 3643
n = p * q
fai = 1008 * 3642
min = n
sum = 0
def RSA(p, q, e, m):
    n = p * q
    c = pow(m, e, n)
    return c
def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)
results = {}
for e in range(1, fai):
    cnt = 0
    if gcd(e, fai) != 1:
        continue
    else:
        for m in range(1, n):
            if m == RSA(p, q, e, m):
                cnt += 1
        if cnt < min:
            min = cnt
            results[e] = cnt
for e in range(1, fai):
    if results[e] == min:
        sum += e
print(sum)

