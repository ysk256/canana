#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import datetime
import binascii
import re
import serial
import can
import usb.core
import usb.util

# init
class base():
  def __init__(self):
    self.is_debug = False
  def close(self):
    pass
  def recv(self, timeout=None):
    pass
  def send(self, msg):
    pass
  def pdbg(self, p):
    if self.is_debug:
      print(p)
    pass
  def set_isdebug(self, is_debug):
    self.is_debug = is_debug
  def get_isdebug(self):
    return self.is_debug

class canusb(base):
  """
  import can.interfaces.slcan
  read/write CANUSB device
  inf = can.interfaces.slcan.slcanBus(channel=dev_name, ttyBaudrate=115200, timeout=0, bitrate=None)
  """
  fd = None
  def write_fd(self, dat):
    return self.fd.write(dat.encode() + b"\r")
  def read_fd(self, size):
    dat = self.fd.read(size)
    if dat is None:
      dat = ""
    dat = dat.decode()
    dat = dat.replace("\r","").replace("\n","")
    return dat
  def readline_fd(self):
    dat = b""
    #while 1:
    #  tmp = self.fd.read(1)
    #  if tmp is None or tmp == b"\r":
    #    break
    #  dat += tmp
    while  dat == b"" or dat[-1] != 0xd: # 0xd=\r
      dat = dat + self.fd.read()
      if len(dat) > 0 and dat[-1] == 0x07: # for UCAN UCC
        return ""
    return dat.decode()
  def __init__(self, dev_name, bps = 119200):
    super().__init__()
    #self.is_debug = True
    self.fd = serial.Serial(dev_name, bps, timeout=1)
    if self.fd is None:
      return None
    self.write_fd('V') # Version => V1011
    tmp = self.readline_fd()
    self.pdbg(tmp)
    self.write_fd('N') # Serial => NC***
    tmp = self.readline_fd()
    self.pdbg(tmp)
    self.write_fd('S6') # borate => 500kbps
    tmp = self.readline_fd()
    self.pdbg(tmp)
    self.write_fd('M00000000') # filter
    tmp = self.readline_fd()
    self.pdbg(tmp)
    self.write_fd('mFFFFFFFF') # filter
    tmp = self.readline_fd()
    self.pdbg(tmp)
    self.write_fd('Z0') # TimeStamp Off
    tmp = self.readline_fd()
    self.pdbg(tmp)
    self.write_fd('O') # Open
    tmp = self.readline_fd()
    self.pdbg(tmp)
  def close(self):
    self.write_fd('C')
    tmp = self.readline_fd()
    self.pdbg(tmp)
    self.fd.close()
  def send(self, frame):
    if frame.is_extended_id:
      tx_str = "T%08X%d" % (frame.arbitration_id, frame.dlc)
    else:
      tx_str = "t%03X%d" % (frame.arbitration_id, frame.dlc)
    for i in range(0, frame.dlc):
      tx_str = tx_str + ("%02X" % frame.data[i])
    self.write_fd(tx_str) # send 0x7E0 8 02210C00 00000000
  def recv(self, timeout=None):
    while 1:
      # read canbus
      dat = self.readline_fd()
      t = datetime.datetime.now()
      ts = t.timestamp()
      if len(dat) <= 0:
        continue
      # check frame type
      if dat[0] == 'T':
          ext_id = True
          remote = False
      elif dat[0] == 't':
          ext_id = False
          remote = False
      elif dat[0] == 'R':
          ext_id = True
          remote = True
      elif dat[0] == 'r':
          ext_id = False
          remote = True
      else:
        #print("error", dat)
        continue
      # parse USBCAN recive data
      # 't7E8804610C0C41000000' => 7E8 8 04610C0C41000000
      try:
        msg_id   = int(dat[1:4], 16)
        msg_size = int(dat[4], 16)
        #msg_dat = int(dat[5:], 16)
        #msg_dat = [(msg_dat>>i*8)&0xff for i in range(msg_size-1,-1,-1)]
        msg_dat = []
        for i in range(0, msg_size):
            msg_dat.append(int(dat[5+i*2:7+i*2], 16))
        dev_name_dummy = "can0"
      except:
        continue
      msg = can.Message(timestamp = ts, arbitration_id = msg_id, extended_id = ext_id, is_remote_frame = remote, is_error_frame = False, dlc = len(msg_dat), data = msg_dat, channel = dev_name_dummy)
      yield msg
  def set_filter_id(self, filter_id):
    # set CAN filter identifier
    self.fd.write_fd('F%X\r' % filter_id)

  def set_filter_mask(self, filter_mask):
    # set CAN filter mask
    self.df.write_fd('K%X\r' % filter_mask)

class candump(base):
  """
  read candump *.log
  
  import can
  inf = can.io.CanutilsLogReader(file_name)
  inf = can.io.CanutilsLogWriter(filename, channel='vcan0')
  """
  def __init__(self, file_name):
    self.file_name = file_name
    self.fd = can.io.CanutilsLogReader(self.file_name)
  def close(self):
    self.fd = None
  def recv(self, timeout=None):
    return self.fd.__iter__()

class candump_nots(base):
  """
  read candump *.log
  
  format
    can0  18E   [8]  00 00 00 00 06 EC 81 04
    can0  3EC   [2]  00 00
  """
  def __init__(self, file_name):
    self.file_name = file_name
    self.fd = open(file_name)
    self.pattern = re.compile(r"(\S+)\s+([0-9A-Fa-f]+)\s+\[(\d)+\]\s+([0-9A-Fa-f ]+)")
    self.dummy_ts = 0
  def close(self):
    self.fd.close()
    self.fd = None
  def recv(self, timeout=None):
    while 1:
      line = self.fd.readline()
      if not line:
        break
      line = line.strip(" ").rstrip("\n\r ")
      m = self.pattern.match(line)
      if m is None or len(m.groups()) != 4:
        continue
      dev_name, msg_id, msg_size, msg_dat = m.groups()
      ts = self.dummy_ts
      self.dummy_ts += 0.01
      msg_id  = int(msg_id, 16)
      msg_size = int(msg_size)
      msg_dat = [int(i,16) for i in msg_dat.split(" ")]
      dev_name = dev_name.replace(" ","_")
      msg = can.Message(timestamp = ts, arbitration_id = msg_id, extended_id = None, is_remote_frame = False, is_error_frame = False, dlc = msg_size, data = msg_dat, channel = dev_name)
      yield msg
    return None

class vehiclespy(base):
  """
  read vehicle spy *.csv
  """
  def __init__(self, file_name):
    self.file_name = file_name
    self.rd = csv.reader(open(self.file_name,"r"))
    self.id = None
    self.b1 = None
    self.b8 = None
    # find "ISO8601 Timestamp,2018/06/29T13:00:47.000019,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,"
    self.ts_start = 0
    while 1:
      rows = self.readrows()
      if rows is None or len(rows) == 0:
        return
      elif rows[0] == "ISO8601 Timestamp":
        self.ts_start = rows[1]
        break
      elif rows[0] == "Line" or rows[0].isdigit():
        break
    self.findline(rows)
    return
  def close(self):
    self.rd = None
  def findline(self, rows):
    # find "Line,Abs Time(Sec),Rel Time (Sec),Status,Er,Tx,Description,Network,Node,PT,Trgt,Src,B1,B2,B3,B4,B5,B6,B7,B8,Value,Trigger,Signals,,,,,,,,,,,,,,,,,,,,,,,,,,,"
    # find "Line,Abs Time(Sec),Rel Time (Sec),Status,Er,Tx,Description,Network,Node,Arb ID,Remote/EDL-BRS-ESI,Xtd,B1,B2,B3,B4,B5,B6,B7,B8,Value,Trigger,Signals,,,,,,,,,,,,,,,,,,,,,,,,,,,"
    while 1:
      if rows is None:
        return
      elif rows[0] == "Line" and "PT" in rows and "B1" in rows and "B8" in rows:
        self.id = rows.index("PT")
        self.dev_name = rows.index("Network")
        self.b1 = rows.index("B1")
        self.b8 = rows.index("B8")
        if self.b8 - self.b1 == 7:
          break
      rows = self.readrows()
  def readrows(self):
    try:
      while 1:
        rows = next(self.rd)
        if len(rows) != 0 and (self.id is None or int(rows[self.id],16) < 0x800):
          break
      return rows
    except:
      pass
    return None
  def recv(self, timeout=None):
    while 1:
      # read
      rows = self.readrows()
      if rows is None:
        break
      if not rows[0].replace(" ","").isdigit():
        self.findline(rows)
        continue
      # parse log
      # '1,1.90E-05,0,4.92581E+14,F,F,HS CAN $1F8,HS CAN,,1F8,F,F,11,F7,0,3E,E2,B1,5,C9,,,,,,,,,,,,,,,,,,,,,,,,,,,,' => [1.90E-05, "HS_CAN", 0x1F8, 8, "11F7003EE2B105C9"]
      if len(rows) <= self.b8:
        continue
      try:
        ts, dev_name, msg_id = rows[1], rows[self.dev_name], rows[self.id]
        ts = float(ts)
        msg_id  = int(msg_id, 16)
        msg_dat = [int(i,16) for i in rows[self.b1:self.b8+1] if i != ""]
        dev_name = dev_name.replace(" ","_")
      except:
        continue
      msg_size = len(msg_dat)
      msg = can.Message(timestamp = ts, arbitration_id = msg_id, extended_id = None, is_remote_frame = False, is_error_frame = False, dlc = msg_size, data = msg_dat, channel = dev_name)
      yield msg
    return None

class pythoncan(base):
  """
  read/write
  """
  fd = None
  def __init__(self, dev_name):
    try:
      self.fd = can.interface.Bus(bustype='socketcan_native', channel=dev_name)
    except:
      self.fd = can.interface.Bus(bustype='socketcan_ctypes', channel=dev_name)
    if self.fd is None:
      return None
  def close(self):
    self.fd.shutdown()
  def send(self, msg):
    self.fd.send(msg)
  def recv(self, timeout=None):
    while 1:
      msg = self.fd.recv(timeout)
      if msg is None:
        break
      yield msg

class usb2can(base):
  s = None
  def __init__(self, idVendor=0x0483, idProduct=0x1234):
    dev = usb.core.find(idVendor=idVendor, idProduct=idProduct)
    dev.set_configuration()
    cfg = dev.get_active_configuration()
    itfs = cfg[(0,0)]
    dat_in = usb.util.find_descriptor(itfs, bEndpointAddress=0x81)
    dat_out = usb.util.find_descriptor(itfs, bEndpointAddress=0x2)
    cmd_in = usb.util.find_descriptor(itfs, bEndpointAddress=0x83)
    cmd_out = usb.util.find_descriptor(itfs, bEndpointAddress=0x4)
    self.s = [dat_in, dat_out, cmd_in, cmd_out]
    self.open()
  def send_wait_cmd(self, msg):
    cmd_in, cmd_out = self.s[2], self.s[3]
    if cmd_out.write(msg) != len(msg):
      print("send error")
    return cmd_in.read(128)
  def make_cmd(self, command, opt1 = 0, opt2 = 0, data = ""):
    channel = 0
    #msg = "%02x"%USB_8DEV_CMD_START + "%02x"%channel + "%02x"%command + "%02x"%opt1 + "%02x"%opt2 + "".join(["%02x"%i for i in data]) + "%02x"%USB_8DEV_CMD_END
    msg = "1100%02x%02x%02x%s22" % (command, opt1, opt2, data)
    return binascii.unhexlify(msg)
  def version(self):
    # get firmwate and hardware version
    msg = self.make_cmd(0xC, data="00"*10) # USB_8DEV_GET_SOFTW_HARDW_VER
    ret = self.send_wait_cmd(msg)
    print(ret)
  def open(self):
    # data = [ts1+1,ts2+1,sjw+1,(brp>>8)&0xff,brp&0xff,0,0,0,8,0]
    #         0d    02    01    00            04
    #msg = "11 00 02 09 00 0d020100040000000800 22".replace(" ","")
    #cmd_out.write(binascii.unhexlify(msg)) # type can bitrate 500000bps
    #cmd_in.read(128) # array('B', [17, 0, 2, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 34])
    ctrlmode = 0x08
    msg = self.make_cmd(0x2, opt1=0x09, data="0d02010004000000%02x00" % ctrlmode) # USB_8DEV_OPEN
    ret = self.send_wait_cmd(msg)
    #print(ret)
  def close(self):
    msg = self.make_cmd(0x3, data="00"*10) # USB_8DEV_CLOSE
    ret = self.send_wait_cmd(self.s, msg)
    #print(ret)
  def send(self, msg):
    dat_out = self.s[1]
    # flags : RTR and EXT_ID (USB_8DEV_EXTID if msg.extended_id) flag
    # id : 11 / 29bit
    #msg = "%02x"%USB_8DEV_DATA_START + "%02x"%flags + "%08x"%id + "%02x"%dlc + "".join(["%02x"%i for i in data]) + "%02x"%USB_8DEV_DATA_END
    flags = 0
    dlc_max = 8
    data ="".join(["%02x"%i for i in msg.data])
    data += "00" * (dlc_max - len(msg.data))
    msg = "55%02x%08x%02x%saa" % (flags, msg.arbitration_id, msg.dlc, data)
    dat_out.write(binascii.unhexlify(msg))
  def recv(self, timeout=999):
    dat_in = self.s[0]
    timeout *= 1000
    dev_name_dummy = "can0"
    while 1:
      msg = dat_in.read(128, timeout = timeout)
      if msg[0] != 0x55 or msg[-1] != 0xAA or 13 + msg[7] != len(msg): # USB_8DEV_DATA_START, USB_8DEV_DATA_END
        break
      frame_type, flags, msg_id, dlc, data, timestamp = msg[1], msg[2], msg[3:7], msg[7], msg[8:-5], msg[-5:-1]
      msg_id = (((((msg_id[0]<<8) + msg_id[1])<<8) + msg_id[2])<<8) + msg_id[3]
      msg_dat = [i for i in data]
      timestamp = ((((((timestamp[3]<<8) + timestamp[2])<<8) + timestamp[1])<<8) + timestamp[0])/1000
      msg = can.Message(timestamp = timestamp, arbitration_id = msg_id, extended_id = False, is_remote_frame = False, is_error_frame = False, dlc = len(msg_dat), data = msg_dat, channel = dev_name_dummy)
      yield msg

