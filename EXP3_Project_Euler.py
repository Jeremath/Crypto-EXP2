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
def num_of_unen(p, q, e):
    return (1+gcd(e-1, p-1))*(1+gcd(e-1, q-1))

results = {}
for e in range(1, fai):
    if gcd(e, fai) != 1:
        continue
    else:
        cnt = num_of_unen(p, q, e)
        if cnt < min:
            min = cnt
        results[e] = cnt
for e in range(1, fai):
    if gcd(e, fai) != 1:
        continue    
    if results[e] == min:
        sum += e
print(sum)
print(min)


