#imports------------------------------------------------------
import random
from secrets import randbelow
#end of imports-----------------------------------------------

#moduled power------------------------------------------------
def mPower(a, p, n):
    l = len (bin (p)) - 2
    res = 1
    for i in range(l):
        tmp = p >> (i)
        if tmp % 2 != 0:
            tmp = a % n
            for j in range (i):
                tmp = ((tmp % n) ** 2) % n
            res = (res * tmp) % n
    return (res)
#end of moduled power-----------------------------------------

#miller-rabin's test------------------------------------------
def primetest(n, k):
    #testmass = open('output.out', 'r')
    #for line in testmass:
     #   if (n % int(line) == 0):
      #      return False
    t = n - 1
    s = 0
    while (t % 2 == 0):
        t = t // 2
        s += 1
    for i in range (k):
        a = random.randint(2, n - 2)
        x = mPower(a, t, n)
        if (x == 1 or x == n - 1):
            continue        
        for j in range (s - 1):
            x = ((x % n) ** 2) % n
            if (x == 1):
                return False
            if (x == n - 1):
                break
        else:
            return False
    return True
#end of miller-rabin's test-----------------------------------

#big hardprime generator--------------------------------------
def primegen(le, te):
   # te = te // 3
    x = (randbelow(te - le) + le)
    x += x % 2 - 1
    while (True):
        if (not primetest(x, 1)):
            x += 2
            continue
        else:
            break 
    return x
#end of big hardprime generator-----------------------------

#primeroot generator----------------------------------------
def proot(p):
    fact = []
    phi = p - 1
    n = phi
    i = 2
    while (i * i <= n):
        fact.append(i)
        while (n % i == 0):
            n = n // i
        i += 1
    if (n > 1):
        fact.append(n)
    res = 2
    while (res <= p):
        trig = True
        i = 0
        while ((i < len(fact)) and trig):
            trig = trig & (mPower(res, phi // fact[i], p) != 1)
            i += 1
        if (trig):
            return res
        res += 1
    return -1
#end of primeroot generator---------------------------------

#Shanks test------------------------------------------------
def Shanks(n):
    l = stest
    if l != -1:
        return l
    elif n % 4 == 1:
        n = 2 * n
    D = 4 * n

#end of Shanks test-----------------------------------------

#Squaretest-------------------------------------------------
def stest(n):
    i = 1
    while (i * i < n):
        i += 1
    if (i * i == n):
        return i
    else:
        return -1
#end of Squaretest------------------------------------------

#keygen-----------------------------------------------------
def keygen(keylen):
    ple = 1
    ple = ple << keylen - 1 
    pte = 1
    pte = pte << keylen
    p = primegen(ple, pte)
    g = proot(p)
    x = randbelow(p - 2) + 1
    y = mPower(g, x, p)
    Elprivatkey = open('Elprivat.key', 'w')
    Elpublickey = open('Elpublic.key', 'w')
    Elprivatkey.write(str(x))
    Elpublickey.write(str(p) + '\n' + str(g) + '\n' + str(y))
    Elprivatkey.close()
    Elpublickey.close()
#end of keygen---------------------------------------------

#encryption------------------------------------------------
def encrypt(inname, outname):
    inp = open(inname, 'rb')
    key = open('Elpublic.key', 'r')
    out = open(outname, 'w')
    p = int(key.readline())
    g = int(key.readline())
    y = int(key.readline())
    current = []
    current.append(inp.read(3))
    i = 0
    while (current[i] != b''):
        current.append(inp.read(3))
        i += 1
    i = 0
    for i in range(len(current) - 1):
        k = randbelow(p - 2) + 1
        a = mPower(g, k, p)
        b = mPower(y, k, p)
        current[i] = (int.from_bytes(current[i], byteorder='little') * b) % p
        out.write(str(a) + ' ' + str(current[i]) + ' ')
    inp.close()
    key.close()
    out.close()
    return 0
#end of encryption-----------------------------------------

#decryption------------------------------------------------
def decrypt(inname, outname):
    inp = open(inname, 'r')
    key = open('Elprivat.key', 'r')
    okey = open('Elpublic.key', 'r')
    out = open(outname, 'w')
    x = int(key.readline())
    p = int(okey.readline())
    current = inp.read()
    current = current.split(' ')
    for i in range(len(current) // 2):
        j = i * 2
        if (current[j] != ''):
            prtb = ((int(current[j]) * mPower(int(current[j - 1]), p - 1 - x, p) % p).to_bytes(3, byteorder='little')).decode('utf-8')
            for j in range(len(prtb)):
                if (prtb[j] != '\0' ):
                    out.write(prtb[j])
    inp.close()
    key.close()
    okey.close()
    out.close()
    return 0
#end of decryption-----------------------------------------

#keygen(128)
#encrypt('inf', 'elinfenc')
#decrypt('elinfenc', 'elifdenc')

