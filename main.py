import hashlib
import subprocess
import ctypes
import tkinter as tk
import tkinter.messagebox as messagebox
import requests
import webbrowser
import platform
from tkinter import ttk

def get_hwid():
    serial = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
    return hashlib.md5(serial.encode()).hexdigest()

def check_hwid(hwid):
    response = requests.get("url")
    hwid_list = response.text.splitlines()
    return hwid in hwid_list

def start_csgo_loader():
    if platform.system() == "Windows":
        ctypes.windll.shell32.ShellExecuteW(None, "open", "steam://restart", None, None, 1)
    elif platform.system() == "Darwin":
        subprocess.call(["open", "-a", "Steam"])
    elif platform.system() == "Linux":
        subprocess.call(["steam", "-restart"])

    steam_url = "steam://run/730"
    webbrowser.open(steam_url)

def restore_ntopenfile():
    ntdll = ctypes.WinDLL("ntdll")
    nt_open_file = ntdll.NtOpenFile

    if hasattr(nt_open_file, "_original_bytes"):
        return

    original_bytes = (ctypes.c_ubyte * 5)()
    ctypes.memmove(original_bytes, nt_open_file, 5)
    nt_open_file._original_bytes = original_bytes

    PAGE_EXECUTE_READWRITE = 0x40
    SIZE_OF_BYTE = ctypes.sizeof(ctypes.c_ubyte)
    bytes_to_write = (ctypes.c_ubyte * 5)(*original_bytes)

    kernel32 = ctypes.WinDLL("kernel32")
    csgo_process_handle = kernel32.OpenProcess(0x1F0FFF, False, ctypes.windll.kernel32.GetCurrentProcessId())
    kernel32.WriteProcessMemory(csgo_process_handle, nt_open_file, ctypes.byref(bytes_to_write), SIZE_OF_BYTE * 5, None)
    kernel32.VirtualProtectEx(csgo_process_handle, nt_open_file, SIZE_OF_BYTE * 5, PAGE_EXECUTE_READWRITE, None)

def activate_hwid():
    hwid = get_hwid()
    messagebox.showerror("Error", f"Your HWID was not found in the database.\n\nHWID: {hwid}\n\nPlease provide your HWID to the administrator for activation.")

def copy_hwid():
    hwid = get_hwid()
    window.clipboard_clear()
    window.clipboard_append(hwid)
    messagebox.showinfo("Copy HWID", "HWID has been copied to the clipboard.")

def check_and_start():
    hwid = get_hwid()

    if check_hwid(hwid):
        print("HWID verified. Launching CS:GO...")
        restore_ntopenfile()
        start_csgo_loader()
    else:
        activate_hwid()

def main():
    global window
    window = tk.Tk()
    window.title("CS:GO Loader")
    window.configure(bg="#333333")
    ttk.Style().configure("TLabel", background="#333333", foreground="#FFFFFF")
    ttk.Style().configure("TButton", background="#444444", foreground="#000000")
    ttk.Style().map("TButton", background=[('active', '#555555')])
    hwid = get_hwid()
    hwid_label = ttk.Label(window, text=f"Your HWID: {hwid}")
    hwid_label.pack(pady=20)
    copy_button = ttk.Button(window, text="Copy HWID", command=copy_hwid)
    copy_button.pack(pady=10)
    check_button = ttk.Button(window, text="Check HWID and Start CS:GO", command=check_and_start)
    check_button.pack(pady=10)

    window.mainloop()

if __name__ == "__main__":
    main()
