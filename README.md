# canana
## Description
- Canbus analyzing tools.
- Support
  - Input
    - CANUSB device
    - candump *.log
    - vehicle spy *.csv
  - Output
    - Candump format *.log
    - Canbus messages view (Time stamp, ID, size, Message data and Message ascii)
    - Message data w/ coloring diff data
    - Message interval msec (average and variance)

## Requirements
- Language: Python3.x
- libraries: python-can, cantools, pySerial, sympy, click, ctype on windows
- OS: Windows, Linux, macOS
- Device: CANUSB on Windows/Linux and any other CAN I/F can be use python-can

## Install
- cpoy your project directory
- then run canana.py or import interface as library

## Example
- read candump logfile *.log
```
import interface

inf = interface.candump("dump.log")
while 1:
  msg = inf.recv()
  if msg is None:
    break
  ts, dev_name, msg_id, msg_size, msg_dat = msg.timestamp, msg.channel, msg.arbitration_id, msg.dlc, msg.data.hex()
  print("(%f) %s %03X#%s" % (ts, dev_name, msg_id, msg_dat))

inf.close()
```

- read vehiclespy logfile *.csv
```
import interface

inf = interface.vehiclespy("dump.csv")
while 1:
  msg = inf.recv()
  if msg is None:
    break
  ts, dev_name, msg_id, msg_size, msg_dat = msg.timestamp, msg.channel, msg.arbitration_id, msg.dlc, msg.data.hex()
  print("(%f) %s %03X#%s" % (ts, dev_name, msg_id, msg_dat))

inf.close()
```
