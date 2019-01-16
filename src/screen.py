#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
http://blog.livedoor.jp/baruth_/archives/18904245.html
"""
import sys
import os
import click
if os.name == 'nt':
  import ctypes

class screen():
  # common
  def __init__(self):
    if os.name == 'nt':
      self.init_win()
      self.color = self.color_win
      self.color_by_flag = self.color_by_flag_win
    else:
      self.init_linux()
      self.color = self.color_linux
      self.color_by_flag = self.color_by_flag_linux
  # for common
  def clear(self):
    click.clear()
  # for win
  def init_win(self):
    # curser
    self.STD_OUTPUT_HANDLE = -11
    self.hOut = ctypes.windll.kernel32.GetStdHandle(ctypes.wintypes.HANDLE(self.STD_OUTPUT_HANDLE))
    self.move = self.move_win
    # color
    self.STD_OUTPUT_HANDLE  = -11
    self.FOREGROUND_BLACK   = 0x00
    self.FOREGROUND_BLUE    = 0x01
    self.FOREGROUND_GREEN   = 0x02
    self.FOREGROUND_RED     = 0x04
    self.FOREGROUND_CYAN    = self.FOREGROUND_BLUE  | self.FOREGROUND_GREEN
    self.FOREGROUND_MAGENTA = self.FOREGROUND_BLUE  | self.FOREGROUND_RED
    self.FOREGROUND_YELLOW  = self.FOREGROUND_GREEN | self.FOREGROUND_RED
    self.FOREGROUND_WHITE   = self.FOREGROUND_BLUE  | self.FOREGROUND_GREEN | self.FOREGROUND_RED
    self.FOREGROUND_INTENSITY = 0x08
    self.BACKGROUND_BLACK   = 0x00
    self.BACKGROUND_BLUE    = 0x10
    self.BACKGROUND_GREEN   = 0x20
    self.BACKGROUND_RED     = 0x40
    self.BACKGROUND_CYAN    = self.BACKGROUND_BLUE  | self.BACKGROUND_GREEN
    self.BACKGROUND_MAGENTA = self.BACKGROUND_BLUE  | self.BACKGROUND_RED
    self.BACKGROUND_YELLOW  = self.BACKGROUND_GREEN | self.BACKGROUND_RED
    self.BACKGROUND_WHITE   = self.BACKGROUND_BLUE  | self.BACKGROUND_GREEN | self.BACKGROUND_RED
    self.BACKGROUND_INTENSITY = 0x80
    #
    self.std_out_handle = ctypes.windll.kernel32.GetStdHandle(self.STD_OUTPUT_HANDLE)
  def move_win(self, x = 0, y = 0):
    ctypes.windll.kernel32.SetConsoleCursorPosition(self.hOut, ctypes.wintypes._COORD(x, y))
  def set_colors_win(self, forecol = 'w', backcol = 'k'):
    fore = self.FOREGROUND_INTENSITY if forecol.isupper() else 0
    forecol = forecol.lower()
    if forecol == 'k':
      fore |= self.FOREGROUND_BLACK
    elif forecol == 'b':
      fore |= self.FOREGROUND_BLUE
    elif forecol == 'g':
      fore |= self.FOREGROUND_GREEN
    elif forecol == 'r':
      fore |= self.FOREGROUND_RED
    elif forecol == 'c':
      fore |= self.FOREGROUND_CYAN
    elif forecol == 'm':
      fore |= self.FOREGROUND_MAGENTA
    elif forecol == 'y':
      fore |= self.FOREGROUND_YELLOW
    elif forecol == 'w':
      fore |= self.FOREGROUND_WHITE
    else:
      fore = self.FOREGROUND_WHITE
    #
    back = self.FOREGROUND_INTENSITY if backcol.isupper() else 0
    backcol = backcol.lower()
    if backcol == 'k':
      back |= self.BACKGROUND_BLACK
    elif backcol == 'b':
      back |= self.BACKGROUND_BLUE
    elif backcol == 'g':
      back |= self.BACKGROUND_GREEN
    elif backcol == 'r':
      back |= self.BACKGROUND_RED
    elif backcol == 'c':
      back |= self.BACKGROUND_CYAN
    elif backcol == 'm':
      back |= self.BACKGROUND_MAGENTA
    elif backcol == 'y':
      back |= self.BACKGROUND_YELLOW
    elif backcol == 'w':
      back |= self.BACKGROUND_WHITE
    else:
      back = self.BACKGROUND_BLACK
    #
    ctypes.windll.kernel32.SetConsoleTextAttribute(self.std_out_handle, fore | back)
  def color_win(self, s, forecol = 'w', backcol = 'k'):
    sys.stdout.flush()
    self.set_colors_win(forecol, backcol)
    print(s, end="")
    sys.stdout.flush()
    self.set_colors_win()
  def color_by_flag_win(self, s, flg_str, forecol = 'w', backcol = 'k'):
    sys.stdout.flush()
    target_len = min(len(s), len(flg_str))
    color_flg = -1
    for i in range(target_len):
      if flg_str[i] != "0":
        # set color
        if color_flg != 1:
          self.set_colors_win(forecol, backcol)
        color_flg = 1
      else:
        # unset color
        if color_flg != 0:
          self.set_colors_win()
        color_flg = 0
      print(s[i],end="")
      sys.stdout.flush()
    self.set_colors_win()
    print(s[target_len:], end="")
  # for linux
  def init_linux(self):
    # curser
    self.move = self.move_linux
    # color
    self.BLACK = '\033[30m'
    self.RED = '\033[31m'
    self.GREEN = '\033[32m'
    self.YELLOW = '\033[33m'
    self.BLUE = '\033[34m'
    self.MAGENTA = '\033[35m'
    self.CYAN = '\033[36m'
    self.WHITE = '\033[37m'
    self.BOLD = '\033[1m'
    self.UNDERLINE = '\033[4m'
    self.INVISIBLE = '\033[08m'
    self.END = '\033[0m'
  def move_linux(self, x = 0, y = 0):
    print("\033[%d;%dH"%(y,x), end="")
  def set_colors_linux(self, forecol = '', backcol = 'k'):
    fore = self.BOLD if forecol.isupper() else ""
    forecol = forecol.lower()
    if forecol == 'k':
      fore += self.BLACK
    elif forecol == 'b':
      fore += self.BLUE
    elif forecol == 'g':
      fore += self.GREEN
    elif forecol == 'r':
      fore += self.RED
    elif forecol == 'c':
      fore += self.CYAN
    elif forecol == 'm':
      fore += self.MAGENTA
    elif forecol == 'y':
      fore += self.YELLOW
    elif forecol == 'w':
      fore += self.WHITE
    else:
      fore = self.END
    print(fore, end="")
  def color_linux(self, s, forecol, backcol = 'k'):
    self.set_colors_linux(forecol, backcol)
    print(s, end="")
    self.set_colors_linux()
  def color_by_flag_linux(self, s, flg_str, forecol, backcol = 'k'):
    target_len = min(len(s), len(flg_str))
    color_flg = -1
    for i in range(target_len):
      if flg_str[i] != "0":
        if color_flg != 1:
          self.set_colors_linux(forecol, backcol)
          color_flg = 1
      else:
        if color_flg == 1:
          self.set_colors_linux()
        color_flg = 0
      print(s[i], end="")
    if color_flg == 1:
      self.set_colors_linux()
    print(s[target_len:], end="")
