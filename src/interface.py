#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import datetime
import serial
import can

# init
class base():
  def __init__(self):
    self.is_debug = False
  def close(self):
    pass
  def recv(self):
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
    return dat.decode()
  def __init__(self, dev_name):
    super().__init__()
    #self.is_debug = True
    self.fd = serial.Serial(dev_name, 119200, timeout=1)
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
      tx_str = "T%08X%d" % (frame.arb_id, frame.dlc)
    else:
      tx_str = "t%03X%d" % (frame.arb_id, frame.dlc)
    for i in range(0, frame.dlc):
      tx_str = tx_str + ("%02X" % frame.data[i])
    self.write_fd(tx_str) # send 0x7E0 8 02210C00 00000000
  def recv(self):
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
  def recv(self):
    return self.fd.__iter__()

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
  def recv(self):
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
  def recv(self):
    while 1:
      msg = self.fd.recv()
      if msg is None:
        break
      yield msg
