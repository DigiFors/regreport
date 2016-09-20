"""
Copyright (c) 2016 DigiFors GmbH, Leipzig

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR 
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, 
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR 
OTHER DEALINGS IN THE SOFTWARE.
"""

from Registry import Registry
import struct
import datetime
import os
import sys

def convert_time(time): # One unit = 100 nanoseconds, start date = 1601-01-01 00:00:00 UTC
  try:
    dt = datetime.datetime.fromtimestamp((time/10000000)-11644473600)
  except ValueError:
    dt = None
  return dt
  
  
def get_registry_data(sam_hive, system_hive, software_hive):
  system = {}
  users = {}
  
  reg_sam = Registry.Registry(sam_hive)
  reg_system = Registry.Registry(system_hive)
  reg_software = Registry.Registry(software_hive)
  
  users_key = reg_sam.open("SAM\\Domains\\Account\\Users")
  
  for subkey in users_key.subkeys():
    if subkey.name()[0] == "0":
      user_id = int(subkey.name(), 16) # User IDs are in subkeys
      if user_id < 1000:
        default = True
      else:
        default = False
      users[user_id] = {"default": default, "admin": False, "domain_admin": False}
      for value in subkey.values():
        if value.name() == "F":
          # "F" is a structure that contains a lot of forensically interesting data.
          users[user_id]["last_login"] = convert_time(struct.unpack("Q", value.value()[8:16])[0])
          users[user_id]["last_pwd_reset"] = convert_time(struct.unpack("Q", value.value()[24:32])[0])
          users[user_id]["expiration"] = convert_time(struct.unpack("Q", value.value()[32:40])[0])
          users[user_id]["last_failed_login"] = convert_time(struct.unpack("Q", value.value()[40:48])[0])
          acb_bits = struct.unpack("H", value.value()[56:58])[0]
          if acb_bits & 0x01 != 0:
            users[user_id]["disabled"] = True
          else:
            users[user_id]["disabled"] = False
          users[user_id]["failed_login_count"] = struct.unpack("H", value.value()[64:66])[0]
          users[user_id]["login_count"] = struct.unpack("H", value.value()[66:68])[0]
        if value.name() == "V":
          # V is only of interest to check for password set. We do not need to crack the
          # password hash itself; we know that a hash length of 4 means empty password
          hash_length = struct.unpack("<L", value.value()[172:176])[0]
          if hash_length == 4:
            users[user_id]["password"] = False
          else:
            users[user_id]["password"] = True
    
  names_key = reg_sam.open("SAM\\Domains\\Account\\Users\\Names")
  
  for subkey in names_key.subkeys():
    for value in subkey.values():
      if value.name() == "(default)":
        if value.value_type() in users.keys(): # For some reason, the user IDs are stored in value types.
          users[value.value_type()]["username"] = subkey.name()
          
  
  groups_key = reg_sam.open("SAM\\Domains\\Builtin\\Aliases")
  
  for subkey in groups_key.subkeys():
    if subkey.name()[0] == "0":
      group_id = int(subkey.name(), 16)
      if group_id == 544 or group_id == 519: # 544 = group ID of local admins, 519 = group ID of domain admins. Domain admins only visible on domain controller!
        for value in subkey.values():
          if value.name() == "C": # yet another binary structure.
            users_offset = struct.unpack("<L", value.value()[40:44])[0]
            user_count = struct.unpack("<L", value.value()[48:52])[0]
            for i in range(0, user_count):
              if group_id == 544:
                users[struct.unpack("<L", value.value()[users_offset+52+24+i*28:users_offset+4+52+24+i*28])[0]]["admin"] = True
                # 52 = offset from which users_offset is calculated
                # 28 = length of one user structure
                # 24 = offset of the user ID field
                # 4 = length of the user ID field
              else:
                users[struct.unpack("<L", value.value()[users_offset+52+24+i*28:users_offset+4+52+24+i*28])[0]]["domain_admin"] = True
     
  name_key = reg_system.open("ControlSet001\\Control\\ComputerName\\ComputerName")
  for value in name_key.values():
    if value.name() == "ComputerName":
      system["computer_name"] = value.value()
     
  curver_key = reg_software.open("Microsoft\\Windows NT\\CurrentVersion")
  
  for value in curver_key.values():
    if value.name() == "ProductName":
      system["version"] = value.value()
    if value.name() == "InstallDate":
      system["install_date"] = datetime.datetime.fromtimestamp(value.value())
      

  return system, users
  
if len(sys.argv) == 2:
  sam_hive = os.path.join(sys.argv[1], "SAM")
  system_hive = os.path.join(sys.argv[1], "SYSTEM")
  software_hive = os.path.join(sys.argv[1], "SOFTWARE")
  system, users = get_registry_data(sam_hive, system_hive, software_hive)
elif len(sys.argv) == 4:
  system, users = get_registry_data(sys.argv[1], sys.argv[2], sys.argv[3])
else:
  print "Usage: regreport.py path_to_files\n    or regreport.py path_to_SAM path_to_SYSTEM path_to_SOFTWARE"
  sys.exit(1)
  
print "System information"
print "------------------"
print "Version: %s" % system["version"]
print "Install date: %s" % system["install_date"]
print "Computer name: %s" % system["computer_name"]
print "\n"

for user_id in users.keys():
  user_string = "Information for user with ID %s" % user_id
  print user_string
  print "-"*len(user_string)
  print "Default user: %s" % users[user_id]["default"]
  print "User name: %s" % users[user_id]["username"]
  print "Last login: %s" % users[user_id]["last_login"]
  print "Last password reset: %s" % users[user_id]["last_pwd_reset"]
  print "Last failed login attempt: %s" % users[user_id]["last_failed_login"]
  print "Login count: %s" % users[user_id]["login_count"]
  print "Failed login attempt count: %s" % users[user_id]["failed_login_count"]
  print "Account disabled: %s" % users[user_id]["disabled"]
  print "Password set: %s" % users[user_id]["password"]
  print "Is admin: %s" % users[user_id]["admin"]
  print "Is domain admin: %s" % users[user_id]["domain_admin"]
  print "\n"
