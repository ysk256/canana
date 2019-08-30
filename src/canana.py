#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Version History
  0.1.0: New created. Support CANUSB, candump *.log, logging, display can message/interval/ascii.
  0.1.1: Support vehicle spy *.csv
  0.1.2: Improvement cui view. move color.py to screen.py
  0.2.0: Support python-can devices (socketcan_native, etc...) and separate analyzer class file
  1.0.0: Change to using more python-can on interface.py, add analyzer.analyze_regularity() and change to recv()/write()
  1.1.0: Support Canalyze w/ libusb on windows, -diff option (CAN data bits diff) and candump *.log w/o timestamp.change diff time coloring
"""
import os
import time
import argparse
import screen
import interface
import analyzer
import can
import cantools

__version__ = "1.0.0"

def view_msg(msg, msgs_view, scn, ana, view_line_num_latest, remove_time, uncolor_time):
  ts = msg.timestamp
  msg_id = msg.arbitration_id
  view_line_num = 0
  for _, v_msg in sorted(msgs_view.items()):
    v_ts = v_msg.timestamp
    if v_msg.arbitration_id != msg.arbitration_id:
      v_dev_name, v_msg_id, v_msg_size, v_msg_dat = v_msg.channel, v_msg.arbitration_id, v_msg.dlc, v_msg.data.hex()
    else:
      v_dev_name, v_msg_id, v_msg_size, v_msg_dat = msg.channel, msg.arbitration_id, msg.dlc, msg.data.hex()
    if ts - v_ts >= remove_time:
      view_line_num_latest -= 1
      continue
    if ana is None:
      print(("(%f)"%v_ts).ljust(15) + " %s %03X#%s" % (v_dev_name, v_msg_id, v_msg_dat.ljust(17)))
    else:
      if 1:
        # coloring
        print(("(%f)"%v_ts).ljust(15) + " %s %03X#" % (v_dev_name, v_msg_id), end="")
        if ts - v_ts < uncolor_time:
          scn.color_by_flag(v_msg_dat.ljust(17), ana.get_diff_info(v_msg_id), "R")
        else:
          print(v_msg_dat.ljust(17), end="")
        #scn.color(ana.get_msg_ascii(v_msg_id) + " ", "w")
        print(ana.get_msg_ascii(v_msg_id) + " ", end="")
        #scn.color(ana.get_ts_info(v_msg_id).ljust(15) + " ", "Y")
        print(ana.get_ts_info(v_msg_id).ljust(15) + " ", end="")
        print(ana.get_msg_lcgs(v_msg_id), end="")
        #print(" " + ana.get_regularity(v_msg_id), end="")
        print("")
      else:
        tmp = ("(%f)"%v_ts).ljust(15) + " %s %03X#" % (v_dev_name, v_msg_id) + v_msg_dat.ljust(17) + ana.get_msg_ascii(v_msg_id) + " " + ana.get_ts_info(v_msg_id) + " "
        print(tmp)
    view_line_num += 1
  for i in range(view_line_num_latest - view_line_num):
    print(" " * 120)
  return  view_line_num


def view_range(msgs_latest, ana, analyze_range):
  if ana is not None and analyze_range:
    range_min_arg, range_max_arg = analyze_range.split("-")[0:2]
    range_min_arg = int(range_min_arg,16)
    range_max_arg = int(range_max_arg,16)
    for _, v_msg in sorted(msgs_latest.items()):
      ts, dev_name, msg_id, msg_size, msg_dat = v_msg.timestamp, v_msg.channel, v_msg.arbitration_id, v_msg.dlc, v_msg.data.hex()
      range_min, range_max, range_bit = ana.get_msg_range(msg_id)
      print("0x%03X %s" % (msg_id,msg_dat))
      for i in range(len(range_min)):
        if range_min[i] is not None:
          if range_min[i] != range_max[i] and range_min[i] >= range_min_arg and range_max[i] <= range_max_arg:
            print("      " + "  "*i + "^^%02X-%02X %s %s" % (range_min[i], range_max[i], format((range_bit[i]>>4)&0x0f,"04b"), format(range_bit[i]&0x0f,"04b")))
        else:
          break


def main():
  inf = None
  fd_log = None
  ana = None
  dbc = None
  remove_time = 1.2
  uncolor_time = 1.2
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
  elif args.pythoncan_dev:
    inf = interface.pythoncan(args.pythoncan_dev)
    if inf is None:
      print("interface intialize error %s" % (args.pythoncan_dev))
      return
    if args.logging_name:
      fd_log = open(args.logging_name, "w")
  elif args.usb2can_dev:
    inf = interface.usb2can()
    if inf is None:
      print("interface intialize error usb2can_dev")
      return
    if args.logging_name:
      fd_log = open(args.logging_name, "w")
  elif args.candump_log:
    inf = interface.candump(args.candump_log)
    if inf is None:
      print("interface intialize error %s" % (args.candump_log))
      return
  elif args.candump_log_nots:
    remove_time = 100
    inf = interface.candump_nots(args.candump_log_nots)
    if inf is None:
      print("interface intialize error %s" % (args.candump_log_nots))
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
  # diff mode
  if args.diff:
    main_diff(inf)
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
    ana_level = 1
    ana = analyzer.analyzer(ana_level)
  if args.dbc:
    dbc = cantools.database.load_file(args.dbc)
  # main loop
  msgs_latest = {}
  view_line_num_latest = 0
  scn.clear()
  for msg in inf.recv():
    # recv new msg
    ts, dev_name, msg_id, msg_size, msg_dat = msg.timestamp, msg.channel, msg.arbitration_id, msg.dlc, msg.data.hex()
    # filter by id
    if filter_by_ids and msg_id not in filter_by_ids:
      continue
    # logging
    if fd_log:
      fd_log.write("(%f) %s %03X#%s\x0a" % (ts, dev_name, msg_id, msg_dat))
      continue
    # analyze
    if ana:
      ana.analyze(msg)
    # find string
    if ana and args.find_string:
      if msg_id in find_string_ids:
        pass
      elif args.find_string in ana.get_msg_ascii(msg_id):
        find_string_ids.append(msg_id)
      else:
        continue
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
      if dbc:
        try:
          for k,v in dbc.decode_message(msg.arbitration_id, msg.data).items():
            print(k,v)
        except:
          pass
    # set latest msg
    msgs_latest[msg_id] = msg
  # view byte/bit range
  view_range(msgs_latest, ana, args.analyze_range)
  if fd_log:
    fd_log.close()
  inf.close()
  return

def main_diff(inf):
  # functions
  def view_range_one(diff_direction, msg_id, msg_dat, range_min, range_max, range_bit):
    print("%s0x%03X %s" % (diff_direction, msg_id,msg_dat))
    for i in range(len(range_min)):
      if range_min[i] is not None:
        if range_min[i] != range_max[i]:
          print(" " + "      " + "  "*i + "^^%02X-%02X %s %s" % (range_min[i], range_max[i], format((range_bit[i]>>4)&0x0f,"04b"), format(range_bit[i]&0x0f,"04b")))
      else:
        break
  def view_range_two(diff_direction, msg_id, msg_dat, range_min, range_max, range_bit, range_min2, range_max2, range_bit2):
    did_view_title = False
    for i in range(max(len(range_min), len(range_min2))):
      # view diff
      if (len(range_min) > i and range_min[i] is not None) and (len(range_min2) > i and range_min2[i] is not None):
        if range_bit[i] != range_bit2[i]:
          if did_view_title == False:
            print("%s0x%03X %s" % (diff_direction, msg_id,msg_dat))
            did_view_title = True
          print(" " + "      " + "  "*i + "^^%02X-%02X %s %s" % (range_min[i], range_max[i], format((range_bit[i]>>4)&0x0f,"04b"), format(range_bit[i]&0x0f,"04b")))
          print(" " + "      " + "  "*i + "^^%02X-%02X %s %s" % (range_min2[i], range_max2[i], format((range_bit2[i]>>4)&0x0f,"04b"), format(range_bit2[i]&0x0f,"04b")))
      elif len(range_min) > i and range_min[i] is not None:
        if range_min[i] != range_max[i]:
          if did_view_title == False:
            print("%s0x%03X %s" % (diff_direction, msg_id,msg_dat))
            did_view_title = True
          print(">" + "      " + "  "*i + "^^%02X-%02X %s %s" % (range_min[i], range_max[i], format((range_bit[i]>>4)&0x0f,"04b"), format(range_bit[i]&0x0f,"04b")))
      elif len(range_min2) > i and range_min2[i] is not None:
        if range_min2[i] != range_max2[i]:
          if did_view_title == False:
            print("%s0x%03X %s" % (diff_direction, msg_id,msg_dat))
            did_view_title = True
          print("<" + "      " + "  "*i + "^^%02X-%02X %s %s" % (range_min2[i], range_max2[i], format((range_bit2[i]>>4)&0x0f,"04b"), format(range_bit2[i]&0x0f,"04b")))
  # values
  inf2 = None
  ana = None
  ana2 = None
  # initialize
  parser, args = parse_args()
  if args.candump_log2:
    inf = interface.candump(args.candump_log2)
    if inf is None:
      print("interface intialize error %s" % (args.candump_log2))
      return
  elif args.candump_log_nots2:
    inf2 = interface.candump_nots(args.candump_log_nots2)
    if inf2 is None:
      print("interface intialize error %s" % (args.candump_log_nots2))
      return
  else:
    return
  # initialize library
  ana_level = 1
  ana = analyzer.analyzer(ana_level)
  ana2 = analyzer.analyzer(ana_level)
  # main_diff loop
  # read inf
  msgs_latest = {}
  view_line_num_latest = 0
  for msg in inf.recv():
    # recv new msg
    ts, dev_name, msg_id, msg_size, msg_dat = msg.timestamp, msg.channel, msg.arbitration_id, msg.dlc, msg.data.hex()
    # analyze
    ana.analyze(msg)
    # set latest msg
    msgs_latest[msg_id] = msg
  # read inf2
  msgs_latest2 = {}
  view_line_num_latest2 = 0
  for msg2 in inf2.recv():
    # recv new msg
    ts, dev_name, msg_id, msg_size, msg_dat = msg2.timestamp, msg2.channel, msg2.arbitration_id, msg2.dlc, msg2.data.hex()
    # analyze
    ana2.analyze(msg2)
    # set latest msg
    msgs_latest2[msg_id] = msg2
  # view byte/bit range
  msgs_latest, msgs_latest2 = sorted(msgs_latest.items()), sorted(msgs_latest2.items())
  v_msg, v_msg2 = None, None
  # init
  if len(msgs_latest) == 0 and len(msgs_latest) == 0:
    return
  _, v_msg = msgs_latest.pop(0)
  _, v_msg2 = msgs_latest2.pop(0)
  while v_msg is not None and v_msg2 is not None:
    #print(v_msg, v_msg2)
    msg_id = v_msg.arbitration_id if v_msg is not None else None
    msg_id2 = v_msg2.arbitration_id if v_msg2 is not None else None
    if (msg_id2 is None and msg_id is not None) or msg_id < msg_id2:
      # view v_msg
      range_min, range_max, range_bit = ana.get_msg_range(msg_id)
      view_range_one(">", msg_id, v_msg.data.hex(), range_min, range_max, range_bit)
      _, v_msg = msgs_latest.pop(0) if len(msgs_latest) > 0 else (None, None)
    elif (msg_id is None and msg_id2 is not None) or msg_id > msg_id2:
      # view v_msg2
      range_min2, range_max2, range_bit2 = ana2.get_msg_range(msg_id2)
      view_range_one("<", msg_id2, v_msg2.data.hex(), range_min2, range_max2, range_bit2)
      _, v_msg2 = msgs_latest2.pop(0) if len(msgs_latest2) > 0 else (None, None)
    else:
      # view diff v_msg, v_msg2
      range_min, range_max, range_bit = ana.get_msg_range(msg_id)
      range_min2, range_max2, range_bit2 = ana2.get_msg_range(msg_id2)
      view_range_two(" ", msg_id, v_msg.data.hex(), range_min, range_max, range_bit, range_min2, range_max2, range_bit2)
      _, v_msg = msgs_latest.pop(0) if len(msgs_latest) > 0 else (None, None)
      _, v_msg2 = msgs_latest2.pop(0) if len(msgs_latest2) > 0 else (None, None)
  inf.close()
  inf2.close()
  return

def parse_args():
  parser = argparse.ArgumentParser(
    prog = "canana.py",
    usage="",
    description="canbus data analyzer",
    epilog="end",
    add_help=True
    )
  # basic arguments
  parser.add_argument("-v", "--version", action='store_true', help="show version")
  # read arguments
  parser.add_argument("-u", "--canusb_dev", type=str, help="Serial CAN device ex)Win:COM1, Linux:/dev/ttyUSB0, Mac:/dev/cu.usbserial-***", dest="canusb_dev")
  parser.add_argument("-c", "--pythoncan_dev", type=str, help="Socketcan/python-can device ex)can0, slcan0", dest="pythoncan_dev")
  parser.add_argument("-u2c", "--usb2can_dev", type=bool, help="usb2can/usb8dev device for windows", dest="usb2can_dev")
  parser.add_argument("-d", "--candump_log", type=str, help="candump *.log", dest="candump_log")
  parser.add_argument("-d2", "--candump_log2", type=str, help="candump *.log for diff", dest="candump_log2")
  parser.add_argument("-dn", "--candump_log_nots", type=str, help="test", dest="candump_log_nots")
  parser.add_argument("-dn2", "--candump_log_nots2", type=str, help="test for diff", dest="candump_log_nots2")
  parser.add_argument("-s", "--vehiclespy_csv", type=str, help="Vehicle Spy *.csv", dest="vehiclespy_csv")
  # write arguments
  parser.add_argument("-l", "--logging", type=str, help="logging *.log (candump format)", dest="logging_name")
  # view arguments
  parser.add_argument("-S", "--sniffer", action='store_true', help="view only latest msgs")
  parser.add_argument("-n", "--not_view_msg", action='store_true', help="not view msg")
  parser.add_argument("-i", "--filter_by_ids", type=str, help="filter msg by msg_id eg) -i 0AA,200", dest="filter_by_ids")
  parser.add_argument("--find_string", type=str, help="find msg byte, then view msg eg) --find_string AAA", dest="find_string")
  # analyze arguments
  parser.add_argument("-a", "--analyze", action='store_true', help="with analyzer")
  parser.add_argument("-r", "--analyze_range", nargs="?", const="00-FF", default=None, type=str, help="search range e.g) -r 05-FA", dest='analyze_range')
  parser.add_argument("--dbc", type=str, help="analyzing msg with *.dbc", dest="dbc")
  parser.add_argument("-diff", "--diff", action='store_true', help="diff logs")
  # make parser
  args = parser.parse_args()
  return parser, args

if __name__ == "__main__":
  main()
