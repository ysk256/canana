#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Version History
  0.1.0: New created. Support CANUSB, candump *.log, logging, display can message/interval/ascii.
  0.1.1: Support vehicle spy *.csv
  0.1.2: Improvement cui view. move color.py to screen.py
"""
import os
import time
import math
import argparse
import collections
import screen
import interface

__version__ = "0.1.2"

class analyzer():
  def __init__(self):
    self.msgs = collections.defaultdict(lambda: [0, "", 0, 0, ""]) # key:msg_id, val:[ts, dev_name, msg_id, msg_size, msg_dat]
    self.analyzed_dat = collections.defaultdict(lambda: {"diff_ts":[0]*5, "diff_msg_dat":"", "range":[[None]*8,[None]*8,[None]*8]}) # key:msg_id, val:{"diff_ts":[ts_sum, ts_sqr, ts_cnt, ts_avg, ts_var], "diff_msg_dat":msg_dat_xor, "range":[[min_b1,..,min_b8],[max_b1,..,max_b8],[bit_b1,..,bit_b8]]}
    self.analyzed_line = ""
  def diff_ts(self, msg_id, ts_before, ts):
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
  def diff_msg_dat(self, msg_id, msg_dat_before, msg_dat):
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
  def analyze(self, msg):
    # msg: ts, msg_id, msg_size, msg_dat
    ts, dev_name, msg_id, msg_size, msg_dat = msg
    if msg_id in self.msgs:
      ts_before, _, _, msg_size_before, msg_dat_before = self.msgs[msg_id]
      self.diff_ts(msg_id, ts_before, ts)
      self.diff_msg_dat(msg_id, msg_dat_before, msg_dat)
    self.analyze_range(msg_id, msg_size, msg_dat)
    # update msgs
    self.msgs[msg_id] = msg
  def get_ts_info(self, msg_id):
    if msg_id in self.msgs:
      # make analyzed_line
      _, _, _, ts_avg, ts_var = self.analyzed_dat[msg_id]["diff_ts"]
      return "% 4d(+/-%03d)" % (ts_avg, ts_var)
    return ""
  def get_msg_info(self, msg_id):
    if msg_id in self.msgs:
      return self.analyzed_dat[msg_id]["diff_msg_dat"]
    return ""
  def get_msg_ascii(self, msg_id):
    _, _, _, _, msg_dat = self.msgs[msg_id]
    ret = ""
    for i in range(0, len(msg_dat), 2):
      tmp = int(msg_dat[i:i+2],16)
      ret += chr(tmp) if 0x20 <= tmp and tmp < 0x7f else "."
    return ret.ljust(8)
  def get_msg_range(self, msg_id):
    range_min = self.analyzed_dat[msg_id]["range"][0]
    range_max = self.analyzed_dat[msg_id]["range"][1]
    range_bit = self.analyzed_dat[msg_id]["range"][2]
    return range_min, range_max, range_bit


def view_msg(msg, msgs_view, scn, ana, view_line_num_latest, remove_time, uncolor_time):
  ts = msg[0]
  msg_id = msg[2]
  view_line_num = 0
  for _, v_msg in sorted(msgs_view.items()):
    v_ts, v_dev_name, v_msg_id, v_msg_size, v_msg_dat = v_msg
    if v_msg_id == msg_id:
      _, v_dev_name, v_msg_id, v_msg_size, v_msg_dat = msg
    if ts - v_ts >= remove_time:
      view_line_num_latest -= 1
      continue
    if ana is None:
      print("(%f) %s %03X#%s" % (v_ts, v_dev_name, v_msg_id, v_msg_dat.ljust(17)))
    else:
      if 1:
        print("(%f) %s %03X#" % (v_ts, v_dev_name, v_msg_id), end="")
        if ts - v_ts < uncolor_time:
          scn.color_by_flag(v_msg_dat.ljust(17), ana.get_msg_info(v_msg_id), "R")
        else:
          print(v_msg_dat.ljust(17), end="")
        scn.color(ana.get_msg_ascii(v_msg_id) + " ", "w")
        scn.color(ana.get_ts_info(v_msg_id).ljust(16) + " ", "Y")
        print("")
      else:
        tmp = "(%f) %s %03X#" % (v_ts, v_dev_name, v_msg_id) + v_msg_dat.ljust(17) + ana.get_msg_ascii(v_msg_id) + " " + ana.get_ts_info(v_msg_id) + " "
        print(tmp)
    view_line_num += 1
  for i in range(view_line_num_latest - view_line_num):
    print(" " * 80)
  return  view_line_num
  #time.sleep(0.000001)


def view_range(msgs_latest, ana, analyze_range):
  if ana is not None and analyze_range:
    range_min_arg, range_max_arg = analyze_range.split("-")[0:2]
    range_min_arg = int(range_min_arg,16)
    range_max_arg = int(range_max_arg,16)
    for _, v_msg in sorted(msgs_latest.items()):
      ts, dev_name, msg_id, msg_size, msg_dat = v_msg
      range_min, range_max, range_bit = ana.get_msg_range(msg_id)
      for i in range(len(range_min)):
        if range_min[i] is not None:
          if i == 0:
            print("0x%03X %s" % (msg_id,msg_dat))
          if range_min[i] != range_max[i] and range_min[i] >= range_min_arg and range_max[i] <= range_max_arg:
            print("      " + "  "*i + "^^%02X-%02X %s %s" % (range_min[i], range_max[i], format((range_bit[i]>>4)&0x0f,"04b"), format(range_bit[i]&0x0f,"04b")))
        else:
          break


def main():
  inf = None
  fd_log = None
  ana = None
  # initialize
  parser, args = parse_args()
  if args.version:
    print(__version__)
    return
  elif args.canusb_dev:
    inf = interface.canusb(args.canusb_dev)
    if inf is None:
      print("interface intialize error %s" % (args.canusb_dev))
      return
    if args.logging_name:
      fd_log = open(args.logging_name, "w")
  elif args.candump_log:
    remove_time = 1.2
    uncolor_time = 1.2
    inf = interface.candump(args.candump_log)
    if inf is None:
      print("interface intialize error %s" % (args.candump_log))
      return
  elif args.vehiclespy_csv:
    remove_time = 0.02
    uncolor_time = 0.002
    inf = interface.vehiclespy(args.vehiclespy_csv)
    if inf is None:
      print("interface intialize error %s" % (args.vehiclespy_csv))
      return
  else:
    parser.print_help()
    return
  # initialize filter/find
  if args.filter_by_ids:
    filter_by_ids = [int(i,16) for i in args.filter_by_ids.split(",")]
  else:
    filter_by_ids = None
  find_string_ids = []
  # initialize library
  scn = screen.screen()
  scn.color("", "w")
  if args.analyze:
    ana = analyzer()
  # main loop
  msgs_latest = {}
  view_line_num_latest = 0
  scn.clear()
  while 1:
    # recv new msg
    msg = inf.read_msg()
    if msg is None:
      break
    ts, dev_name, msg_id, msg_size, msg_dat = msg
    # filter by id
    if filter_by_ids and msg_id not in filter_by_ids:
      continue
    # find string
    if args.find_string:
      if msg_id in find_string_ids:
        pass
      elif args.find_string in ana.get_msg_ascii(msg_id):
        find_string_ids.append(msg_id)
      else:
        continue
    # logging
    if fd_log:
      fd_log.write("(%f) %s %03X#%s\x0a" % (ts, dev_name, msg_id, msg_dat))
      continue
    # analyze
    if ana:
      ana.analyze(msg)
    # view msg
    if args.not_view_msg:
      # not view msg
      pass
    elif args.sniffer:
      # sniffer view mode (only latest msg each msg_id)
      scn.move(0,0)
      view_line_num_latest = view_msg(msg, msgs_latest, scn, ana, view_line_num_latest, remove_time, uncolor_time)
    else:
      # flow view mode
      view_line_num_latest = view_msg(msg, {msg_id:msgs_latest.get(msg_id,msg)}, scn, ana, view_line_num_latest, remove_time, uncolor_time)
    # set latest msg
    msgs_latest[msg_id] = msg
  # view byte/bit range
  view_range(msgs_latest, ana, args.analyze_range)
  if fd_log:
    fd_log.close()
  inf.close()
  return

def parse_args():
  parser = argparse.ArgumentParser(
    prog = "canana.py",
    usage="",
    description="canbus data analyzer",
    epilog="end",
    add_help=True
    )
  # basic arg
  parser.add_argument("-v", "--version", action='store_true', help="show version")
  # read mode
  parser.add_argument("-u", "--canusb_dev", type=str, help="CANUSB device ex)Win:COM1, Linux:/dev/ttyUSB0, Mac:/dev/cu.usbserial-***", dest="canusb_dev")
  parser.add_argument("-d", "--candump_log", type=str, help="candump *.log", dest="candump_log")
  parser.add_argument("-s", "--vehiclespy_csv", type=str, help="Vehicle Spy *.csv", dest="vehiclespy_csv")
  # write mode
  parser.add_argument("-l", "--logging", type=str, help="logging *.log (candump format)", dest="logging_name")
  # view mode
  parser.add_argument("-S", "--sniffer", action='store_true', help="view only latest msgs")
  parser.add_argument("-n", "--not_view_msg", action='store_true', help="not view msg")
  parser.add_argument("-i", "--filter_by_ids", type=str, help="filter msg by msg_id eg) -i 0AA,200", dest="filter_by_ids")
  parser.add_argument("--find_string", type=str, help="find msg byte, then view msg eg) -c VIN", dest="find_string")
  # analyze mode
  parser.add_argument("-a", "--analyze", action='store_true', help="with analyzer")
  parser.add_argument("-r", "--analyze_range", nargs="?", const="00-FF", default=None, type=str, help="search range e.g) -r 05-FA", dest='analyze_range')
  # make parser
  args = parser.parse_args()
  return parser, args

if __name__ == "__main__":
  main()
