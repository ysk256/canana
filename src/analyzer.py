#!/usr/bin/env python
# -*- coding: utf-8 -*-
import math
import collections
import hashlib
import sympy

def factorint(i):
  return sympy.factorint(i)


class lcgs():
  def __init(self):
    pass
  def gcd(self, u, v):
    while v:
      u, v = v, u % v
    return abs(u)
  def egcd(self, a, b):
    if a == 0:
      return (b, 0, 1)
    else:
      g, x, y = self.egcd(b % a, a)
      return (g, y - (b // a) * x, x)
  def modinv(self, b, n):
    g, x, _ = self.egcd(b, n)
    if g == 1:
      return x % n
    return 0
  def crack_unknown_increment(self, states, modulus, multiplier):
    if modulus != 0:
      increment = (states[1] - states[0]*multiplier) % modulus
    else:
      increment = states[1] - states[0]*multiplier
    return modulus, multiplier, increment
  def crack_unknown_multiplier(self, states, diffs, modulus):
    if modulus != 0:
      multiplier = diffs[1] * self.modinv(diffs[0], modulus) % modulus
    elif diffs[0] != diffs[1]:
      multiplier = diffs[1] // diffs[0]
    else:
      multiplier = 1
    return self.crack_unknown_increment(states, modulus, multiplier)
  def solver(self, states):
    """
    s1=(s0*m+c)%n
    return n,m,c
    t0 = s1 - s0 = (s0*m + c) - s0 = (m - 1) * s0 + c (mod n)
    t1 = s2 - s1 = (s1*m + c) - (s0*m + c) = m*(s1 - s0) = m*t0 (mod n)
    t2 = s3 - s2 = (s2*m + c) - (s1*m + c) = m*(s2 - s1) = m*t1 (mod n)
    t3 = s4 - s3 = (s3*m + c) - (s2*m + c) = m*(s3 - s2) = m*t2 (mod n)
    t2*t0 - t1*t1 = (m*m*t0 * t0) - (m*t0 * m*t0) = 0 (mod n)
    """
    states = states[:6]
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    #print("debug", states)
    #print("debug", diffs)
    a = zeroes[0]
    for b in zeroes[1:]:
      a = self.gcd(a,b)
    modulus = abs(a)
    #modulus = abs(reduce(gcd, zeroes))
    return self.crack_unknown_multiplier(states, diffs, modulus)

class analyzer_cipher():
  def __init__(self):
    pass
    self.statistic_byte_dat = {}
  def statistic_byte(self, msg_id, msg_dat):
    if msg_id not in self.statistic_byte_dat:
      self.statistic_byte_dat[msg_id] = [0]*256
    for i in range(0,len(msg_dat),2):
      b = int(msg_dat[i:i+2],16)
      self.statistic_byte_dat[msg_id][b] += 1
  def hash(self):
    hashstr = hashlib.sha256(key).hexdigest()
  def solver(self, dat):
    if 2 <= len(dat):
      pass
  def print_statistic_byte_all(self):
    for msg_id, byte_dat in self.statistic_byte_dat.items():
      print("===============")
      print("0x%03X" % msg_id)
      for j in range(0,256,64):
        for i in range(j,j+64):
          print("%02X "%i, end="")
        print("")
        for i in range(j,j+64):
          print("%02d " % byte_dat[i], end="")
        print("")

class analyzer():
  def __init__(self):
    self.msgs_max = 6
    self.msgs = {} # key:msg_id, val:[ts, dev_name, msg_id, msg_size, msg_dat]
    self.analyzed_dat = collections.defaultdict(lambda: {"diff_ts":[0]*5, "diff_msg_dat":"", "range":[[None]*8,[None]*8,[None]*8]}) # key:msg_id, val:{"diff_ts":[ts_sum, ts_sqr, ts_cnt, ts_avg, ts_var], "diff_msg_dat":msg_dat_xor, "range":[[min_b1,..,min_b8],[max_b1,..,max_b8],[bit_b1,..,bit_b8]]}
    self.nmc = None
    self.analyzed_line = ""
    self.lcgs = lcgs()
  def analyze_ts(self, msg_id, ts):
    if msg_id not in self.msgs:
      return
    ts_before, _, _, _, _ = self.msgs[msg_id][-1]
    dts = (ts - ts_before) * 1000
    ts_sum, ts_sqr, ts_cnt, ts_avg, ts_var = self.analyzed_dat[msg_id]["diff_ts"]
    if ts_cnt >= 100:
      ts_sum, ts_sqr, ts_cnt = 0, 0, 0
    ts_sum += dts
    ts_sqr += dts ** 2
    ts_cnt += 1
    ts_avg = ts_sum // ts_cnt
    ts_var = math.sqrt((ts_sum ** 2 - ts_sqr) // ts_cnt)
    self.analyzed_dat[msg_id]["diff_ts"] = [ts_sum, ts_sqr, ts_cnt, ts_avg, ts_var]
  def analyze_diff(self, msg_id, msg_dat):
    if msg_id not in self.msgs:
      return
    _, _, _, _, msg_dat_before = self.msgs[msg_id][-1]
    msg_dat_before_len = len(msg_dat_before)
    msg_dat_len = len(msg_dat)
    msg_dat_xor = "".join(["%X" % (int(msg_dat_before[i],16) ^ int(msg_dat[i],16)) for i in range(min(msg_dat_before_len, msg_dat_len))])
    msg_dat_xor += "F" * max(0, msg_dat_len - msg_dat_before_len)
    self.analyzed_dat[msg_id]["diff_msg_dat"] = msg_dat_xor
  def analyze_range(self, msg_id, msg_size, msg_dat):
    range_min = self.analyzed_dat[msg_id]["range"][0]
    range_max = self.analyzed_dat[msg_id]["range"][1]
    range_bit = self.analyzed_dat[msg_id]["range"][2]
    for i in range(msg_size):
      tmp = int(msg_dat[i*2:i*2+2],16)
      range_min[i] = tmp if range_min[i] is None else min(range_min[i], tmp)
      range_max[i] = tmp if range_max[i] is None else max(range_max[i], tmp)
      range_bit[i] = tmp if range_bit[i] is None else range_bit[i] | tmp
    self.analyzed_dat[msg_id]["range"][0] = range_min
    self.analyzed_dat[msg_id]["range"][1] = range_max
    self.analyzed_dat[msg_id]["range"][2] = range_bit
  def analyze_lcgs(self, msg_id):
    # Linear Congruential Generators:LCGs j==(i*m+c)%n
    if msg_id in self.msgs and len(self.msgs[msg_id]) >= self.msgs_max:
      n, m, c = self.lcgs.solver([int(i[4],16) for i in self.msgs[msg_id][:6]])
      self.nmc = n, m, c
    else:
      self.nmc = None
  def analyze(self, msg):
    # msg: ts, msg_id, msg_size, msg_dat
    ts, dev_name, msg_id, msg_size, msg_dat = msg
    self.analyze_ts(msg_id, ts)
    self.analyze_diff(msg_id, msg_dat)
    self.analyze_range(msg_id, msg_size, msg_dat)
    # xor/rshift/lshift i^j, ((i>>x)&0xff)==((j>>y)&0xff), ((i<<x)&0xff)==((j>>y)&0xff)
    self.analyze_lcgs(msg_id)
    # sha1/sha256/sha512/crc32
    # update msgs
    if msg_id not in self.msgs:
      self.msgs[msg_id] = []
    elif len(self.msgs[msg_id]) >= 6:
      self.msgs[msg_id] = self.msgs[msg_id][1:]
    self.msgs[msg_id].append(msg)
  def get_ts_info(self, msg_id):
    if msg_id in self.msgs:
      # make analyzed_line
      _, _, _, ts_avg, ts_var = self.analyzed_dat[msg_id]["diff_ts"]
      return "% 4d(+/-%03d)" % (ts_avg, ts_var)
    return ""
  def get_diff_info(self, msg_id):
    if msg_id in self.msgs:
      return self.analyzed_dat[msg_id]["diff_msg_dat"]
    return ""
  def get_msg_ascii(self, msg_id):
    ret = "".ljust(8)
    if msg_id in self.msgs:
      _, _, _, _, msg_dat = self.msgs[msg_id][-1]
      for i in range(0, len(msg_dat), 2):
        tmp = int(msg_dat[i:i+2],16)
        ret += chr(tmp) if 0x20 <= tmp and tmp < 0x7f else "."
    return ret.ljust(8)
  def get_msg_range(self, msg_id):
    range_min = self.analyzed_dat[msg_id]["range"][0]
    range_max = self.analyzed_dat[msg_id]["range"][1]
    range_bit = self.analyzed_dat[msg_id]["range"][2]
    return range_min, range_max, range_bit
  def get_msg_lcgs(self, msg_id):
    if self.nmc is not None:
      n, m, c = self.nmc
      return "x1=(x0*%X+%X)%%%X"%(m, c, n)
    else:
      return ""

