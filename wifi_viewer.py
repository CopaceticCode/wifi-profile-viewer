import tkinter as tk
from tkinter import ttk
import subprocess
import re
import pyperclip
from datetime import datetime

class WifiViewer(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("WiFi Profile Viewer")
        self.configure(bg='#2d2d2d')
        self.geometry('1200x600')  # Increased width for more columns

        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure dark theme colors
        style.configure('TFrame', background='#2d2d2d')
        style.configure('TLabel', background='#2d2d2d', foreground='white')
        style.configure('TButton', background='#404040', foreground='white')
        style.configure('Treeview', 
                       background='#404040', 
                       foreground='white',
                       fieldbackground='#404040')
        
        # Create main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Create Treeview with scrollbar
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Create scrollbars
        y_scrollbar = ttk.Scrollbar(tree_frame)
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        x_scrollbar = ttk.Scrollbar(tree_frame, orient='horizontal')
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

        # Create Treeview with new columns
        self.tree = ttk.Treeview(tree_frame, 
                                columns=('SSID', 'Password', 'Authentication', 'Cipher', 'Security_Key',
                                       'Connection_Mode', 'MAC_Random', 'Cost', 'Congested'),
                                show='headings',
                                yscrollcommand=y_scrollbar.set,
                                xscrollcommand=x_scrollbar.set)

        # Configure scrollbars
        y_scrollbar.config(command=self.tree.yview)
        x_scrollbar.config(command=self.tree.xview)

        # Configure column headings and widths
        columns_config = {
            'SSID': 'WiFi Name',
            'Password': 'Password',
            'Authentication': 'Authentication',
            'Cipher': 'Cipher',
            'Security_Key': 'Security Key',
            'Connection_Mode': 'Connection Mode',
            'MAC_Random': 'MAC Randomization',
            'Cost': 'Cost Settings',
            'Congested': 'Congested'
        }

        for col, heading in columns_config.items():
            self.tree.heading(col, text=heading)
            self.tree.column(col, width=130, minwidth=100)

        self.tree.pack(fill=tk.BOTH, expand=True)

        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)

        # Buttons
        refresh_btn = ttk.Button(button_frame, text="Refresh", command=self.load_wifi_profiles)
        refresh_btn.pack(side=tk.LEFT, padx=5)

        copy_btn = ttk.Button(button_frame, text="Copy Selected Password", command=self.copy_password)
        copy_btn.pack(side=tk.LEFT, padx=5)

        copy_all_btn = ttk.Button(button_frame, text="Copy All Data", command=self.copy_all_data)
        copy_all_btn.pack(side=tk.LEFT, padx=5)

        # Status label
        self.status_label = ttk.Label(main_frame, text="")
        self.status_label.pack(pady=5)

        # Load profiles on startup
        self.load_wifi_profiles()

    def load_wifi_profiles(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)

        try:
            # Get list of WiFi profiles
            cmd = "netsh wlan show profiles"
            output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
            profiles = re.findall(r"All User Profile\s*:\s*(.*)\r", output)

            for profile in profiles:
                try:
                    profile = profile.strip()
                    cmd = f'netsh wlan show profile name="{profile}" key=clear'
                    output = subprocess.check_output(cmd, shell=True).decode('utf-8', errors='ignore')
                    
                    # Extract all information using regex
                    password_match = re.search(r"Key Content\s+:\s+(.*)\r", output)
                    auth_match = re.search(r"Authentication\s+:\s+(.*)\r", output)
                    cipher_match = re.search(r"Cipher\s+:\s+(.*)\r", output)
                    security_key_match = re.search(r"Security key\s+:\s+(.*)\r", output)
                    connection_mode_match = re.search(r"Connection mode\s+:\s+(.*)\r", output)
                    mac_random_match = re.search(r"Random MAC\s+:\s+(.*)\r", output)
                    cost_match = re.search(r"Cost\s+:\s+(.*)\r", output)
                    congested_match = re.search(r"Congested\s+:\s+(.*)\r", output)

                    # Get values with "N/A" as default
                    password = password_match.group(1) if password_match else "N/A"
                    auth = auth_match.group(1) if auth_match else "N/A"
                    cipher = cipher_match.group(1) if cipher_match else "N/A"
                    security_key = security_key_match.group(1) if security_key_match else "N/A"
                    connection_mode = connection_mode_match.group(1) if connection_mode_match else "N/A"
                    mac_random = mac_random_match.group(1) if mac_random_match else "N/A"
                    cost = cost_match.group(1) if cost_match else "N/A"
                    congested = congested_match.group(1) if congested_match else "N/A"
                    
                    self.tree.insert('', tk.END, values=(
                        profile, password, auth, cipher, security_key,
                        connection_mode, mac_random, cost, congested
                    ))
                    
                except subprocess.CalledProcessError:
                    continue

            self.status_label.config(text="Profiles loaded successfully")
        except Exception as e:
            self.status_label.config(text=f"Error: {str(e)}")

    def copy_password(self):
        selected_item = self.tree.selection()
        if not selected_item:
            self.status_label.config(text="Please select a WiFi profile")
            return
        
        password = self.tree.item(selected_item[0])['values'][1]
        pyperclip.copy(password)
        self.status_label.config(text="Password copied to clipboard!")

    def copy_all_data(self):
        # Create header row
        headers = [self.tree.heading(col)['text'] for col in self.tree['columns']]
        data = ['\t'.join(headers)]
        
        # Add all rows
        for item in self.tree.get_children():
            row = self.tree.item(item)['values']
            data.append('\t'.join(str(value) for value in row))
        
        # Join rows with newlines and copy to clipboard
        clipboard_text = '\n'.join(data)
        pyperclip.copy(clipboard_text)
        self.status_label.config(text="All data copied to clipboard! Ready to paste in Excel.")

if __name__ == "__main__":
    app = WifiViewer()
    app.mainloop()
