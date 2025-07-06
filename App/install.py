import os
import sys
import shutil
import subprocess
import platform
import stat

APP_NAME = "HCA"
IS_WINDOWS = platform.system() == "Windows"
IS_ROOT = os.geteuid() == 0 if not IS_WINDOWS else True

# sudo: system install, else: user install
if IS_WINDOWS:
    INSTALL_DIR = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), APP_NAME)
    WRAPPER_DIR = INSTALL_DIR
else:
    if IS_ROOT:
        INSTALL_DIR = "/opt/HCA"
        WRAPPER_DIR = "/usr/local/bin"
    else:
        INSTALL_DIR = os.path.expanduser("~/.local/share/HCA")
        WRAPPER_DIR = os.path.expanduser("~/.local/bin")

WRAPPER = "hca.bat" if IS_WINDOWS else "hca"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ENTRY_FILE = os.path.join(SCRIPT_DIR, "HCA.py")
REQUIREMENTS_FILE = os.path.join(SCRIPT_DIR, "requirements.txt")

def install_dependencies():
    if os.path.exists(REQUIREMENTS_FILE):
        print("[+] Installing dependencies from requirements.txt...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", REQUIREMENTS_FILE])
    else:
        print("[!] No requirements.txt found, skipping dependency installation.")

def copy_script():
    os.makedirs(INSTALL_DIR, exist_ok=True)
    shutil.copy2(ENTRY_FILE, os.path.join(INSTALL_DIR, "HCA.py"))
    if os.path.exists(REQUIREMENTS_FILE):
        shutil.copy2(REQUIREMENTS_FILE, os.path.join(INSTALL_DIR, "requirements.txt"))
    print(f"[+] Installed HCA.py to {INSTALL_DIR}")

def create_wrapper():
    wrapper_path = os.path.join(WRAPPER_DIR, WRAPPER)
    os.makedirs(WRAPPER_DIR, exist_ok=True)
    if IS_WINDOWS:
        with open(wrapper_path, "w") as f:
            f.write(f'@echo off\npython "{os.path.join(INSTALL_DIR, "HCA.py")}" %*\n')
    else:
        with open(wrapper_path, "w") as f:
            f.write(f'#!/bin/bash\npython3 "{os.path.join(INSTALL_DIR, "HCA.py")}" "$@"\n')
        st = os.stat(wrapper_path)
        os.chmod(wrapper_path, st.st_mode | stat.S_IEXEC)
    print(f"[+] Created wrapper: {wrapper_path}")

def add_to_path_if_needed():
    if IS_WINDOWS:
        return  # Windows handled via registry

    target_path = WRAPPER_DIR
    bashrc = os.path.expanduser("~/.bashrc")
    path_line = f'export PATH="$PATH:{target_path}"'

    with open(bashrc, 'r') as f:
        contents = f.read()

    if path_line not in contents:
        with open(bashrc, 'a') as f:
            f.write(f'\n{path_line}\n')
        print(f"[+] PATH updated via ~/.bashrc (run 'source ~/.bashrc' to apply now)")
    else:
        print("[*] PATH already contains wrapper path.")

def add_to_path_windows():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                             0, winreg.KEY_ALL_ACCESS)
        path_val, _ = winreg.QueryValueEx(key, "Path")
        if INSTALL_DIR not in path_val:
            new_path = path_val + ";" + INSTALL_DIR
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
            print("[+] Added install path to system PATH.")
        else:
            print("[*] Install path already in PATH.")
        winreg.CloseKey(key)
    except PermissionError:
        print("[!] Run this script as Administrator to add to system PATH.")
    except Exception as e:
        print("[!] Failed to modify PATH:", e)

def main():
    print(f"[*] Installing {APP_NAME}...")
    if not os.path.isfile(ENTRY_FILE):
        print(f"[x] ERROR: HCA.py not found in {SCRIPT_DIR}")
        sys.exit(1)

    install_dependencies()
    copy_script()
    create_wrapper()

    if IS_WINDOWS:
        add_to_path_windows()
    else:
        add_to_path_if_needed()

    print(f"\n[✓] Installation complete.")
    print(f"    You can now run HCA with: hca\n")

if __name__ == "__main__":
    main()
