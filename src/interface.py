#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import datetime
import serial
import can

# init
class base():
  def __init__(self):
    pass
  def ishex(self, val):
    try:
        int(val, 16)
        return True
    except ValueError:
        return False
  def pdbg(self, p):
    debug = True
    if debug:
      print(p)

class canusb(base):
  """
  read/write CANUSB device
  
  import can.interfaces.slcan
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
    while 1:
      tmp = self.fd.read(1)
      if tmp is None or tmp == b"\r":
        break
      dat += tmp
    if len(dat) != 0:
      return dat.decode()
    else:
      return None
  def __init__(self, dev_name):
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
  def write_msg(self, msg_id, msg_dat):
    self.write_fd('t%03X%d%s' % (msg_id, len(msg_dat)//2, msg_dat)) # send 0x7E0 8 02210C00 00000000
    self.readline_fd()
  def read_msg(self):
    while 1:
      # read canbus
      dat = self.readline_fd()
      if dat is None:
        break
      t = datetime.datetime.now()
      ts = t.timestamp()
      if len(dat) <= 0:
        continue
      if dat[0] != "t":
        #print("error", dat)
        continue
      # parse USBCAN recive data
      # 't7E8804610C0C41000000' => 7E8 8 04610C0C41000000
      dev_name_dummy = "can0"
      msg_id   = int(dat[1:4], 16)
      msg_size = int(dat[4], 16)
      msg_dat  = dat[5:]
      msg = [ts, dev_name_dummy, msg_id, msg_size, msg_dat]
      return msg
    return None

class candump(base):
  """
  read candump *.log
  
  import can
  inf = can.io.CanutilsLogReader(file_name)
  
  inf = can.io.CanutilsLogWriter(filename, channel='vcan0')
  """
  def __init__(self, file_name):
    self.file_name = file_name
    self.fd = open(self.file_name,"rb")
  def close(self):
    self.fd.close()
  def readline_fd(self):
    dat = self.fd.readline()
    dat = dat.replace(b"\n",b"").replace(b"\r",b"")
    if len(dat) != 0:
      return dat.decode()
    else:
      return None
  def read_msg(self):
    while 1:
      # read
      dat = self.readline_fd()
      if dat is None:
        break
      # '(1537705031.547013) can0 066#00208407768D' / '(1537705031.547013) can0 066#00208407768D . ..v.'
      dat_splited = dat.split(" ")
      if len(dat_splited) < 3:
        #print("error1", dat)
        continue
      # parse log of candump
      # '(1537705031.547013) can0 066#00208407768D' => [1537705031.547013, "can0", 0x066, 6, "00208407768D"]
      ts, dev_name, msg_dat = dat_splited[0:3]
      if ts[0] != "(" or ts[-1] != ")" or ts[1:-1].replace('.', '').isnumeric() == False or len(msg_dat.split("#")) != 2:
        #print("error2", dat)
        continue
      ts = float(ts[1:-1])
      msg_id, msg_dat = msg_dat.split("#")
      if self.ishex(msg_id) == False or self.ishex(msg_dat) == False:
        #print("error3", dat)
        continue
      msg_id   = int(msg_id, 16)
      msg_size = len(msg_dat)
      if msg_size % 2 != 0 or msg_size > 16:
        #print("error4", dat)
        continue
      msg_size = msg_size // 2
      msg = [ts, dev_name, msg_id, msg_size, msg_dat]
      return msg
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
  def read_msg(self):
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
      ts, dev_name, msg_id = rows[1], rows[self.dev_name], rows[self.id]
      ts = float(ts)
      dev_name = dev_name.replace(" ","_")
      msg_dat = "".join(["%02X" % int(i,16) for i in rows[self.b1:self.b8+1] if i != ""])
      if self.ishex(msg_id) == False or self.ishex(msg_dat) == False:
        continue
      msg_id   = int(msg_id, 16)
      msg_size = len(msg_dat) // 2
      msg = [ts, dev_name, msg_id, msg_size, msg_dat]
      return msg
    return None

class pythoncan():
  """
  read/write
  """
  fd = None
  def __init__(self, dev_name):
    self.fd = can.interface.Bus(bustype='socketcan_native', channel=dev_name)
    if self.fd is None:
      return None
  def close(self):
    self.fd.shutdown()
  def write_msg(self, msg):
    ts, dev_name, msg_id, msg_size, msg_dat = msg
    msg2 = Message(timestamp = ts, arbitration_id = msg_id, extended_id = None, is_remote_frame = False, is_error_frame = False, dlc = msg_size, data = [int(msg_dat[i:i+2],16) for i in range(0,len(msg_dat),2)])
    self.fd.send(msg2)
  def read_msg(self):
    msg = self.fd.recv()
    if msg is not None:
      msg2 = [msg.timestamp, msg.channel, msg.arbitration_id, msg.dlc, msg.data.hex()]
      return msg2
    return None
