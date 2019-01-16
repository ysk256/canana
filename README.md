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
    - Below data on CUI
- CUI output
  - Canbus messages (Time stamp, ID, size, Message data and Message ascii)
  - Message data w/ coloring diff data
  - Message interval msec (average and variance)

## Requirements
- Python3 and libraries(click, pySerial)
- OS: Windows, Linux, Mac
- CANUSB Device or any other CAN I/F via Serial device

## Install
- cpoy your project directory, then import it.

## Example
- read candump logfile *.log
```
import interface

inf = interface.candump("dump.log")
while 1:
  msg = inf.read_msg()
  if msg is None:
    break
  ts, dev_name, msg_id, msg_size, msg_dat = msg
  print("(%f) %s %03X#%s" % (ts, dev_name, msg_id, msg_dat))

inf.close()
```

- read vehiclespy logfile *.csv
```
import interface

inf = interface.vehiclespy("dump.csv")
while 1:
  msg = inf.read_msg()
  if msg is None:
    break
  ts, dev_name, msg_id, msg_size, msg_dat = msg
  print("(%f) %s %03X#%s" % (ts, dev_name, msg_id, msg_dat))

inf.close()
```

