#!/usr/bin/env python
# -*- coding: utf-8 -*-
import math
import collections
import hashlib
import sympy
import can


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

class cipher():
  #
  def __init__(self):
    pass
    self.statistic_byte_dat = {}
  def statistic_byte(self, msg_id, msg_dat):
    if msg_id not in self.statistic_byte_dat:
      self.statistic_byte_dat[msg_id] = [0]*256
    for i in range(0,len(msg_dat),2):
      b = int(msg_dat[i:i+2],16)
      self.statistic_byte_dat[msg_id][b] += 1
  def bitshift(self):
    # rshift/lshift i^j, ((i>>x)&0xff)==((j>>y)&0xff), ((i<<x)&0xff)==((j>>y)&0xff)
    pass
  def checksum(self):
    #crc*
    pass
  def hash(self):
    # sha1/sha256/sha512
    hashstr = hashlib.sha256(key).hexdigest()
  def xor(self):
    pass
  def crypto(self):
    #aes128/aes256/speck/simon
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
  def solver(self, dat):
    if len(dat) < 2:
      pass
    # simple pattern
    m, c, key = dat[0], dat[0], 0 # c=partial(c)
    self.checksum(m, c, key)
    self.hash(m, c, key)
    m, c, key = dat[0], dat[1], 0 # c=next(m)
    self.bitshift(m, c, key)
    c, key = dat[0], 0            # c=crypto(m) & entropy of m < threshold
    self.xor(c, key)
    self.crypto(c, key)

class analyzer():
  def __init__(self, level = 1):
    self.msgs_max = 7
    self.msgs = {} # key:msg_id, val:can.Message
    self.analyzed_dat = collections.defaultdict(lambda: {"diff_ts":[0]*5, "diff_msg_dat":"", "range":[[None]*8,[None]*8,[None]*8], "is_regularity":True}) # key:msg_id, val:{"diff_ts":[ts_sum, ts_sqr, ts_cnt, ts_avg, ts_var], "diff_msg_dat":msg_dat_xor, "range":[[min_b1,..,min_b8],[max_b1,..,max_b8],[bit_b1,..,bit_b8]], "is_regularity":is_regularity}
    self.nmc = None
    self.analyzed_line = ""
    self.level = level
    self.lcgs = lcgs()
  def analyze_ts(self, msg):
    msg_id = msg.arbitration_id
    if msg_id not in self.msgs:
      return
    ts = msg.timestamp
    ts_before = self.msgs[msg_id][-1].timestamp
    dts = ts - ts_before
    ts_sum, ts_sqr, ts_cnt, ts_avg, ts_var = self.analyzed_dat[msg_id]["diff_ts"]
    if ts_cnt >= 100:
      ts_sum, ts_sqr, ts_cnt = 0, 0, 0
    ts_sum += dts
    ts_sqr += dts ** 2
    ts_cnt += 1
    ts_avg = (ts_sum / ts_cnt) * 1000 # msec
    ts_var = math.sqrt(ts_sum ** 2 - ts_sqr) / ts_cnt * 1000 # msec
    self.analyzed_dat[msg_id]["diff_ts"] = [ts_sum, ts_sqr, ts_cnt, ts_avg, ts_var]
  def analyze_diff(self, msg):
    msg_id = msg.arbitration_id
    if msg_id not in self.msgs:
      return
    msg_before = self.msgs[msg_id][-1]
    msg_dat_xor = "".join(["%02X" % (msg.data[i] ^ msg_before.data[i]) for i in range(min(msg.dlc, msg_before.dlc))])
    msg_dat_xor += "FF" * max(0, msg.dlc - msg_before.dlc)
    self.analyzed_dat[msg_id]["diff_msg_dat"] = msg_dat_xor
  def analyze_range(self, msg):
    msg_id = msg.arbitration_id
    range_min = self.analyzed_dat[msg_id]["range"][0]
    range_max = self.analyzed_dat[msg_id]["range"][1]
    range_bit = self.analyzed_dat[msg_id]["range"][2]
    for i in range(msg.dlc):
      tmp = msg.data[i]
      range_min[i] = tmp if range_min[i] is None else min(range_min[i], tmp)
      range_max[i] = tmp if range_max[i] is None else max(range_max[i], tmp)
      range_bit[i] = tmp if range_bit[i] is None else range_bit[i] | tmp
    self.analyzed_dat[msg_id]["range"][0] = range_min
    self.analyzed_dat[msg_id]["range"][1] = range_max
    self.analyzed_dat[msg_id]["range"][2] = range_bit
  def analyze_lcgs(self, msg):
    # Linear Congruential Generators:LCGs j==(i*m+c)%n
    msg_id = msg.arbitration_id
    #check_num = 3
    lcgs_require_data_number = 6
    if msg_id in self.msgs and len(self.msgs[msg_id]) >= lcgs_require_data_number:
      msg_dat_ints = [int(i.data.hex(),16) for i in self.msgs[msg_id]]
      n, m, c = self.lcgs.solver(msg_dat_ints[:6])
      if n <= 1:
        self.nmc = None
      else:
        self.nmc = n, m, c
    else:
      self.nmc = None
  def analyze_cipher(self, msg):
    pass
  def analyze_regularity(self, msg):
    msg_id = msg.arbitration_id
    if msg_id not in self.msgs:
      return
    msg_dat_ints = [int(i.data.hex(),16) for i in self.msgs[msg_id]]
    is_match = True
    for i in range(len(self.msgs[msg_id]) - 1):
      a = msg_dat_ints[i]
      b = msg_dat_ints[i+1]
      # check ts
      ts_sum, ts_sqr, ts_cnt, ts_avg, ts_var = self.analyzed_dat[msg_id]["diff_ts"]
      dts = self.msgs[msg_id][i+1].timestamp - self.msgs[msg_id][i].timestamp
      dts *= 1000
      if dts <= ts_avg - ts_var or dts >= ts_avg + ts_var:
        is_match = False
        break
      # check range
      msg_dat_xor = self.analyzed_dat[msg_id]["diff_msg_dat"]
      range_min, range_max, range_bit = self.analyzed_dat[msg_id]["range"]
      for a, b, c in zip(self.msgs[msg_id][i].data, range_min, range_max):
        if a < b or a > c:
          is_match = False
          break
      if not is_match:
        break
      # check lcgs
      if self.nmc is not None:
        n, m, c = self.nmc
        if (a*m+c)%n != b:
          is_match = False
          break
    return is_match
  def analyze_uds(self, msg):
    # UDS ISO14229-1
    # ISO-TP ISO15765-2
    pass
  def analyze(self, msg):
    # common
    self.analyze_ts(msg)
    self.analyze_diff(msg)
    self.analyze_range(msg)
    self.analyze_lcgs(msg)
    self.analyze_cipher(msg)
    self.analyzed_dat[msg.arbitration_id]["is_regularity"] = self.analyze_regularity(msg)  # baseline/anomaly
    # protocol
    self.analyze_uds(msg)
    # update msg history
    msg_id = msg.arbitration_id
    if msg_id not in self.msgs:
      self.msgs[msg_id] = collections.deque([msg])
    else:
      if len(self.msgs[msg_id]) >= self.msgs_max:
        _ = self.msgs[msg_id].popleft()
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
    ret = ""
    if msg_id in self.msgs:
      for i in self.msgs[msg_id][-1].data:
        ret += chr(i) if 0x20 <= i and i < 0x7f else "."
    return ret.ljust(8)
  def get_msg_range(self, msg_id):
    range_min = self.analyzed_dat[msg_id]["range"][0]
    range_max = self.analyzed_dat[msg_id]["range"][1]
    range_bit = self.analyzed_dat[msg_id]["range"][2]
    return range_min, range_max, range_bit
  def get_msg_lcgs(self, msg_id):
    if self.nmc is not None:
      n, m, c = self.nmc
      return "x1=(x0*%X%+X)%%%X"%(m, c, n)
    else:
      return ""
  def get_regularity(self, msg_id):
    if msg_id not in self.msgs or self.analyzed_dat[msg_id]["is_regularity"]:
      return ""
    else:
      return "**Irregular**"

