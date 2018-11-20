# -*- coding: utf-8 -*-
__author__ = 'mykko'
__time__ = '2018/11/16 10:55'

import os
import gmpy2
import requests
import sys
sys.setrecursionlimit(100000)

NUM = 21

#root_path = u'D:\\学习\\现代密码学\\实验\\RSA加密体制破译题目\\密码挑战赛赛题三\\附件3-1（加密案例）\\'
root_path = u'E:\\学习\\现代密码学\\实验\\RSA加密体制破译题目\\密码挑战赛赛题三\\附件3-2（发布截获数据）\\'


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
def hex_to_string(m_hex):
    m = {}
    m['hex'] = m_hex
    m['b_flag'] = m['hex'][:16]
    m['num_flag'] = int(m['hex'][16:24],16)
    m['str_flag'] = m['hex'][-16:].decode('hex')
    return m

def cma_attack(n,e1,e2,c1,c2):
    s = egcd(e1, e2)
    s1 = s[1]
    s2 = s[2]
    if s1<0:
        s1 = - s1
        c1 = gmpy2.invert(c1, n)
    elif s2<0:
        s2 = - s2
        c2 = gmpy2.invert(c2, n)
    m = (pow(c1,s1,n)*pow(c2,s2,n))%n
    return m


def CRT(items):
    N = reduce(lambda x, y: x * y, (i[1] for i in items))
    result = 0
    for a, n in items:
        m = N / n
        d, r, s = gmpy2.gcdext(n, m)
        if d != 1: raise Exception("Input not pairwise co-prime")
        result += a * s * m
    return result % N, N

if __name__ == '__main__':
    rsa = []
    rsa_done = []
    n = []
    e = []
    c = []

    for i in xrange(NUM):
        rsa.append({})
        path = root_path + u'Frame{}'.format(i)
        with open (path,'rb') as f:
            x = f.read()
        rsa[i]['n'] = int(x[:256],16)
        rsa[i]['e'] = int(x[256:512],16)
        rsa[i]['c'] = int(x[512:],16)
        rsa[i]['num'] = i
        n.append(int(x[:256],16))
        e.append(int(x[256:512],16))
        c.append(int(x[512:],16))
    #e = set(e)
    m_s = []
    cma_find = []

    #共模攻击
    len_rsa = len(rsa)
    for i in xrange(len_rsa-1):
        for l in xrange(i+1,len_rsa):
            if rsa[i]['n'] == rsa[l]['n'] and rsa[i]['e'] != rsa[l]['e']:
                cma_find.append((rsa[i],rsa[l]))
    for i in cma_find:
        m_hex = cma_attack(i[0]['n'],i[0]['e'],i[1]['e'],i[0]['c'],i[1]['c'])
        m = hex_to_string(hex(m_hex)[2:])
        m['num_frame'] = i[0]['num']
        m_s.append(m.copy())
        m['num_frame'] = i[1]['num']
        m_s.append(m.copy())
        rsa.remove(i[0])
        rsa.remove(i[1])
        rsa_done.append(i[0])
        rsa_done.append(i[1])

    #公约数
    gcd_find = []
    len_rsa = len(rsa)
    for i in xrange(len_rsa-1):
        for l in xrange(i+1,len_rsa):
            q = gmpy2.gcd(rsa[i]['n'],rsa[l]['n'])
            if q != 1 and q != rsa[i]['n'] and q != rsa[l]['n']:
                gcd_find.append((rsa[i],rsa[l]))
    for i in gcd_find:
        q = gmpy2.gcd(i[0]['n'],i[1]['n'])
        p_1 = i[0]['n'] / q
        p_2 = i[1]['n'] / q
        o_1 = (q-1) * (p_1 - 1)
        o_2 = (q-1) * (p_2 - 1)
        d_1 = gmpy2.invert(i[0]['e'],o_1)
        d_2 = gmpy2.invert(i[1]['e'],o_2)

        m_hex = pow(i[0]['c'],d_1,i[0]['n'])
        m = hex_to_string(hex(m_hex)[2:])
        m['num_frame'] = i[0]['num']
        m_s.append(m.copy())


        m_hex = pow(i[1]['c'],d_2,i[1]['n'])
        m = hex_to_string(hex(m_hex)[2:])
        m['num_frame'] = i[1]['num']
        m_s.append(m.copy())

        rsa.remove(i[0])
        rsa.remove(i[1])
        rsa_done.append(i[0])
        rsa_done.append(i[1])

        pass

    #低加密指数广播攻击
    lowere_find = {}
    len_rsa = len(rsa)
    e = []
    for j in rsa:
        if j['e'] not in e:
            e.append(j['e'])
    for i in set(e):
        l = []
        for j in rsa:
            if j['e'] == i:
                l.append(j)
        lowere_find[str(i)] = l
    for i in [5]:
        l = lowere_find[str(i)]
        c = []
        n = []
        for j in l:
            c.append(j['c'])
            n.append(j['n'])
        data = zip(c, n)
        x, n = CRT(data)
        realnum = gmpy2.iroot(gmpy2.mpz(x), i)[0].digits()
        m_hex = hex(int(realnum))[2:-1]
        m = hex_to_string(m_hex)
        for j in l:
            m['num_frame'] = j['num']
            m_s.append(m.copy())
            rsa.remove(j)
            rsa_done.append(j)

    #Coppersmith定理攻击



    pass
