import tkinter as tk
import customtkinter as ctk
import subprocess
import threading
import shutil
import re
from tkinter import filedialog

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class NmapStudioV3(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Nmap Studio v3.1 - Npcap Sync")
        self.geometry("1000x800")

        # Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- LEFT SIDEBAR (Options) ---
        self.sidebar = ctk.CTkScrollableFrame(self, width=280, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="SCAN OPTIONS", font=("Segoe UI", 20, "bold")).pack(pady=20)

        self.switches = {
            "-sS": "SYN Stealth Scan",
            "-sV": "Version Detection",
            "-O": "OS Fingerprinting",
            "-A": "Aggressive (All-in-one)",
            "-Pn": "No Ping (Bypass FW)",
            "-sC": "Default Scripts",
            "-F": "Fast Scan",
            "--open": "Only Open Ports"
        }
        
        self.check_vars = {}
        for flag, desc in self.switches.items():
            var = ctk.BooleanVar()
            cb = ctk.CTkCheckBox(self.sidebar, text=desc, variable=var)
            cb.pack(anchor="w", padx=20, pady=8)
            self.check_vars[flag] = var

        # --- MAIN PANEL ---
        self.main = ctk.CTkFrame(self, fg_color="transparent")
        self.main.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main.grid_columnconfigure(0, weight=1)

        # 1. Target Input
        ctk.CTkLabel(self.main, text="Target IP / Domain", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w", padx=10)
        self.target_input = ctk.CTkEntry(self.main, placeholder_text="e.g. 192.168.1.10", height=40)
        self.target_input.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 15))

        # 2. Interface Selection (Scraped from Nmap)
        ctk.CTkLabel(self.main, text="Hardware Interface (Detected by Nmap)", font=("Segoe UI", 12, "bold")).grid(row=2, column=0, sticky="w", padx=10)
        
        # We fetch the interfaces directly from Nmap's perspective
        self.iface_list = self.get_nmap_interfaces()
        self.iface_dropdown = ctk.CTkOptionMenu(self.main, values=self.iface_list, height=35)
        self.iface_dropdown.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 20))

        # 3. Action Buttons
        btn_frame = ctk.CTkFrame(self.main, fg_color="transparent")
        btn_frame.grid(row=4, column=0, sticky="ew", pady=10)
        
        self.run_btn = ctk.CTkButton(btn_frame, text="START SCAN", command=self.start_scan, fg_color="#1f538d", height=45, font=("Segoe UI", 14, "bold"))
        self.run_btn.pack(side="left", expand=True, fill="x", padx=5)

        self.save_btn = ctk.CTkButton(btn_frame, text="SAVE LOG", command=self.save_log, fg_color="#333333", height=45)
        self.save_btn.pack(side="left", expand=True, fill="x", padx=5)

        # 4. Progress & Output
        self.progress = ctk.CTkProgressBar(self.main)
        self.progress.grid(row=5, column=0, sticky="ew", padx=10, pady=10)
        self.progress.set(0)

        self.output = ctk.CTkTextbox(self.main, font=("Consolas", 13), fg_color="#0d0d0d", text_color="#00ff41")
        self.output.grid(row=6, column=0, sticky="nsew", padx=10)
        self.main.grid_rowconfigure(6, weight=1)

    def get_nmap_interfaces(self):
        """Runs nmap --iflist and parses exactly what Nmap wants to see."""
        try:
            nmap_exe = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"
            result = subprocess.check_output([nmap_exe, "--iflist"], text=True, stderr=subprocess.STDOUT)
            
            # Look for lines starting with eth/wlan/dev etc.
            # Typical line: eth0 (Ethernet) 192.168.1.10/24 ...
            found = []
            lines = result.split('\n')
            for line in lines:
                # We want lines that have an IP address in them
                if "up" in line and "/" in line:
                    parts = line.split()
                    if len(parts) > 0:
                        found.append(parts[0]) # This is the internal name Nmap likes
            
            return found if found else ["Auto"]
        except:
            return ["Auto"]

    def log(self, msg):
        self.output.insert("end", msg + "\n")
        self.output.see("end")

    def start_scan(self):
        self.output.delete("1.0", "end")
        self.progress.set(0)
        self.progress.start()
        threading.Thread(target=self.execute, daemon=True).start()

    def execute(self):
        target = self.target_input.get()
        if not target:
            self.log("!! Error: No target entered.")
            self.progress.stop()
            return

        nmap = shutil.which("nmap") or r"C:\Program Files (x86)\Nmap\nmap.exe"
        cmd = [nmap]
        
        for f, v in self.check_vars.items():
            if v.get(): cmd.append(f)
            
        # Use the specific Nmap name from the dropdown
        selection = self.iface_dropdown.get()
        if selection != "Auto":
            cmd.extend(["-e", selection])
            
        cmd.append(target)
        self.log(f"[*] Command: {' '.join(cmd)}\n" + "="*50)

        try:
            # We must run as shell/admin for Pcap to work
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, 
                                   text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            for line in proc.stdout:
                self.log(line.strip())
            proc.wait()
        except Exception as e:
            self.log(f"!! System Error: {e}")
        
        self.progress.stop()
        self.progress.set(1)
        self.log("\n[+] Scan Finished.")

    def save_log(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w") as f: f.write(self.output.get("1.0", "end"))

if __name__ == "__main__":
    NmapStudioV3().mainloop()