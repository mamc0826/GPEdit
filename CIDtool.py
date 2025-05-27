#!/usr/bin/env python3
"""
Cross-Platform System Administration GUI Tool
A comprehensive interface for managing users, groups, and system policies
Compatible with Linux and Windows? ... for now, or until the next update that ill probably mess up lol
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import subprocess
import os
import sys
import platform
from datetime import datetime
import json

# images go here dude
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("Pillow not available. Install: pip install Pillow")


# Windows-specific imports
if platform.system() == "Windows":
    try:
        import win32api
        import win32con
        import win32net
        import win32netcon
        import win32security
        import wmi
        WINDOWS_MODULES_AVAILABLE = True
    except ImportError:
        WINDOWS_MODULES_AVAILABLE = False
        print("Windows modules not available. Install pywin32 and wmi: pip install pywin32 wmi")

# unix imports for what it was originally for, now with windows comp!
else:
    try:
        import pwd
        import grp
        UNIX_MODULES_AVAILABLE = True
    except ImportError:
        UNIX_MODULES_AVAILABLE = False

class UserDialog(simpledialog.Dialog):
    """Custom dialog for adding/editing user information."""
    def __init__(self, parent, title, system, user_data=None, is_edit=False):
        self.system = system
        self.user_data = user_data # For pre-filling fields during editing
        self.is_edit = is_edit # Flag to indicate if it's an edit operation
        self.result = None
        super().__init__(parent, title)

    def body(self, master):
        # Username field
        tk.Label(master, text="Username:").grid(row=0, column=0, sticky="w", pady=2)
        self.username_entry = tk.Entry(master)
        self.username_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        # Password fields (only for adding user)
        if not self.is_edit:
            tk.Label(master, text="Password:").grid(row=1, column=0, sticky="w", pady=2)
            self.password_entry = tk.Entry(master, show="*")
            self.password_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

            tk.Label(master, text="Confirm Password:").grid(row=2, column=0, sticky="w", pady=2)
            self.confirm_password_entry = tk.Entry(master, show="*")
            self.confirm_password_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=2)
        else:
            # Placeholder entries if not adding (to maintain grid layout)
            self.password_entry = None
            self.confirm_password_entry = None

        # System-specific fields
        current_row = 1 if self.is_edit else 3 # Adjust row based on whether password fields are shown

        if self.system == "Windows":
            tk.Label(master, text="Full Name:").grid(row=current_row, column=0, sticky="w", pady=2)
            self.full_name_entry = tk.Entry(master)
            self.full_name_entry.grid(row=current_row, column=1, sticky="ew", padx=5, pady=2)
            current_row += 1

            tk.Label(master, text="Description:").grid(row=current_row, column=0, sticky="w", pady=2)
            self.description_entry = tk.Entry(master)
            self.description_entry.grid(row=current_row, column=1, sticky="ew", padx=5, pady=2)
        else: # Unix
            tk.Label(master, text="Home Directory (optional):").grid(row=current_row, column=0, sticky="w", pady=2)
            self.home_dir_entry = tk.Entry(master)
            self.home_dir_entry.grid(row=current_row, column=1, sticky="ew", padx=5, pady=2)
            current_row += 1

            tk.Label(master, text="Shell (optional):").grid(row=current_row, column=0, sticky="w", pady=2)
            self.shell_entry = tk.Entry(master)
            self.shell_entry.grid(row=current_row, column=1, sticky="ew", padx=5, pady=2)
            current_row += 1

            tk.Label(master, text="Groups (comma-separated, optional):").grid(row=current_row, column=0, sticky="w", pady=2)
            self.groups_entry = tk.Entry(master)
            self.groups_entry.grid(row=current_row, column=1, sticky="ew", padx=5, pady=2)

        # Pre-fill fields if editing
        if self.is_edit and self.user_data:
            self.username_entry.insert(0, self.user_data['username'])
            self.username_entry.config(state='disabled') # Username cannot be changed directly via this dialog

            if self.system == "Windows":
                self.full_name_entry.insert(0, self.user_data.get('full_name', ''))
                self.description_entry.insert(0, self.user_data.get('description', ''))
            else: # Unix
                self.home_dir_entry.insert(0, self.user_data.get('home_dir', ''))
                self.shell_entry.insert(0, self.user_data.get('shell', ''))
                # For groups, we'll need to fetch them if not already in user_data
                # For now, just show existing groups if available in user_data
                self.groups_entry.insert(0, self.user_data.get('groups', ''))

        return self.username_entry # initial focus

    def apply(self):
        username = self.username_entry.get().strip() if not self.is_edit else self.user_data['username']
        password = self.password_entry.get() if self.password_entry else None
        confirm_password = self.confirm_password_entry.get() if self.confirm_password_entry else None

        if not username:
            messagebox.showerror("Input Error", "Username cannot be empty.", parent=self)
            return

        if not self.is_edit and password != confirm_password:
            messagebox.showerror("Input Error", "Passwords do not match.", parent=self)
            return

        if self.system == "Windows":
            full_name = self.full_name_entry.get().strip()
            description = self.description_entry.get().strip()
            self.result = {
                'username': username,
                'password': password, # Will be None if editing
                'full_name': full_name,
                'description': description
            }
        else: # Unix
            home_dir = self.home_dir_entry.get().strip()
            shell = self.shell_entry.get().strip()
            groups = self.groups_entry.get().strip()
            self.result = {
                'username': username,
                'password': password, # Will be None if editing
                'home_dir': home_dir,
                'shell': shell,
                'groups': groups
            }

class SystemAdminGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cross-Platform System Administration Tool")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)

        self.system = platform.system()
        self.is_admin = self.check_admin_privileges()

        if not self.is_admin:
            messagebox.showwarning("Warning",
                                 f"Running without administrator privileges on {self.system}.\n"
                                 "Some features may be limited.")

        # Initialize WMI connection for Windows
        if self.system == "Windows" and WINDOWS_MODULES_AVAILABLE:
            try:
                self.wmi_conn = wmi.WMI()
            except Exception as e:
                self.wmi_conn = None
                messagebox.showerror("Error", f"Failed to initialize WMI connection: {e}")
        else:
            self.wmi_conn = None
            
        #Idk about this next one
        # Store user policies (program/folder restrictions)
        self.user_policies_file = "user_policies.json"
        self.user_policies = {} # {username: {'programs': [], 'folders': [], 'logon_hours': 'All' | 'formatted_string'}}
        self.load_user_policies()

        self.selected_user_for_policies = None # To hold the username selected in the Users tab

        self.setup_gui()
        self.refresh_all_data()

        # Log file setup
        self.log_file = "admin_tool.log"
        self.load_log()

    def check_admin_privileges(self):
        """Check if the script is running with admin privileges"""
        try:
            if self.system == "Windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    def setup_gui(self):
        """Setup the main GUI interface"""
        # System info label
        info_frame = ttk.Frame(self.root)
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        # Load and display logos
        if PIL_AVAILABLE:
            try:
                # Load CID logo (PNG)
                cid_image_path = "302146237_566763205241407_1753091949167487435_n.png"
                cid_img = Image.open(cid_image_path)
                cid_img = cid_img.resize((100, 50), Image.Resampling.LANCZOS) # Resize to 100x50
                self.cid_logo_tk = ImageTk.PhotoImage(cid_img)
                ttk.Label(info_frame, image=self.cid_logo_tk).pack(side=tk.LEFT, padx=5)

                # Load C logo (JPG)
                c_image_path = "images.jpg"
                c_img = Image.open(c_image_path)
                c_img = c_img.resize((50, 50), Image.Resampling.LANCZOS) # Resize to 50x50
                self.c_logo_tk = ImageTk.PhotoImage(c_img)
                ttk.Label(info_frame, image=self.c_logo_tk).pack(side=tk.LEFT, padx=5)

            except FileNotFoundError:
                print("Logo files not found. Ensure '302146237_566763205241407_1753091949167487435_n.png' and 'images.jpg' are in the script directory.")
                messagebox.showwarning("Logo Error", "Logo files not found. Please ensure '302146237_566763205241407_1753091949167487435_n.png' and 'images.jpg' are in the same directory as the script.")
            except Exception as e:
                print(f"Error loading or processing logos: {e}")
                messagebox.showerror("Logo Error", f"Failed to load or process logos: {e}\nEnsure Pillow is installed and image files are valid.")
        else:
            messagebox.showwarning("Warning", "Pillow library not found. Logos will not be displayed. Please install it using 'pip install Pillow'.")


        system_info = f"System: {self.system} | Admin: {'Yes' if self.is_admin else 'No'}"
        ttk.Label(info_frame, text=system_info, font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10)

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Create tabs
        self.setup_users_tab()
        self.setup_groups_tab()
        self.setup_policies_tab()
        self.setup_user_policies_tab() # New tab
        self.setup_processes_tab()
        self.setup_logs_tab()

        # Bind tab change event to refresh user policies tab
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

    def on_tab_change(self, event):
        """Handle tab change event to refresh relevant data."""
        selected_tab = self.notebook.tab(self.notebook.select(), "text")
        if selected_tab == "User Policies":
            self.refresh_user_policies_display()
        elif selected_tab == "Users":
            # Update selected user for policies when user tab is active
            self.users_tree.bind("<<TreeviewSelect>>", self.on_user_select)

    def on_user_select(self, event):
        """Update selected user for policies when a user is selected in the Users tab."""
        selected_item = self.users_tree.selection()
        if selected_item:
            self.selected_user_for_policies = self.users_tree.item(selected_item[0])["text"]
            self.user_policy_status_label.config(text=f"Selected User: {self.selected_user_for_policies}")
            self.refresh_user_policies_display()
        else:
            self.selected_user_for_policies = None
            self.user_policy_status_label.config(text="Selected User: None")
            self.clear_user_policies_display()


    def setup_users_tab(self):
        """Setup the Users management tab"""
        self.users_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.users_frame, text="Users")

        # Users list frame
        users_list_frame = ttk.LabelFrame(self.users_frame, text="System Users")
        users_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview for users
        if self.system == "Windows":
            columns = ("SID", "Full Name", "Description", "Disabled")
        else:
            columns = ("UID", "GID", "Home", "Shell")

        self.users_tree = ttk.Treeview(users_list_frame, columns=columns, show="tree headings")
        self.users_tree.heading("#0", text="Username")

        for col in columns:
            self.users_tree.heading(col, text=col)
            self.users_tree.column(col, width=150)

        # Scrollbar for users tree
        users_scrollbar = ttk.Scrollbar(users_list_frame, orient=tk.VERTICAL, command=self.users_tree.yview)
        self.users_tree.configure(yscrollcommand=users_scrollbar.set)

        self.users_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        users_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Users control frame
        users_control_frame = ttk.Frame(self.users_frame)
        users_control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(users_control_frame, text="Add User", command=self.add_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(users_control_frame, text="Delete User", command=self.delete_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(users_control_frame, text="Enable/Disable User", command=self.toggle_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(users_control_frame, text="Change Password", command=self.change_password).pack(side=tk.LEFT, padx=2)
        ttk.Button(users_control_frame, text="Rename User", command=self.rename_user).pack(side=tk.LEFT, padx=2) # New button
        ttk.Button(users_control_frame, text="Edit User Properties", command=self.edit_user_properties).pack(side=tk.LEFT, padx=2) # New button
        ttk.Button(users_control_frame, text="Refresh", command=self.refresh_users).pack(side=tk.RIGHT, padx=2)

        # Bind selection event to update selected_user_for_policies
        self.users_tree.bind("<<TreeviewSelect>>", self.on_user_select)

    def setup_groups_tab(self):
        """Setup the Groups management tab"""
        self.groups_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.groups_frame, text="Groups")

        # Groups list frame
        groups_list_frame = ttk.LabelFrame(self.groups_frame, text="System Groups")
        groups_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview for groups
        if self.system == "Windows":
            columns = ("SID", "Description", "Type")
        else:
            columns = ("GID", "Members")

        self.groups_tree = ttk.Treeview(groups_list_frame, columns=columns, show="tree headings")
        self.groups_tree.heading("#0", text="Group Name")

        for col in columns:
            self.groups_tree.heading(col, text=col)
            self.groups_tree.column(col, width=150)

        # Scrollbar for groups tree
        groups_scrollbar = ttk.Scrollbar(groups_list_frame, orient=tk.VERTICAL, command=self.groups_tree.yview)
        self.groups_tree.configure(yscrollcommand=groups_scrollbar.set)

        self.groups_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        groups_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Groups control frame
        groups_control_frame = ttk.Frame(self.groups_frame)
        groups_control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(groups_control_frame, text="Add Group", command=self.add_group).pack(side=tk.LEFT, padx=2)
        ttk.Button(groups_control_frame, text="Delete Group", command=self.delete_group).pack(side=tk.LEFT, padx=2)
        ttk.Button(groups_control_frame, text="Add User to Group", command=self.add_user_to_group).pack(side=tk.LEFT, padx=2)
        ttk.Button(groups_control_frame, text="Remove User from Group", command=self.remove_user_from_group).pack(side=tk.LEFT, padx=2)
        ttk.Button(groups_control_frame, text="Refresh", command=self.refresh_groups).pack(side=tk.RIGHT, padx=2)

    def setup_policies_tab(self):
        """Setup the Policies management tab"""
        self.policies_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.policies_frame, text="Policies & Permissions")

        # File permissions section
        file_frame = ttk.LabelFrame(self.policies_frame, text="File/Directory Permissions")
        file_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # File path entry
        path_frame = ttk.Frame(file_frame)
        path_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(path_frame, text="Path:").pack(side=tk.LEFT)
        self.file_path_var = tk.StringVar()
        ttk.Entry(path_frame, textvariable=self.file_path_var, width=50).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(path_frame, text="Browse", command=self.browse_file).pack(side=tk.RIGHT)

        # Permissions display
        self.permissions_text = tk.Text(file_frame, height=10, wrap=tk.WORD)
        perm_scroll = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.permissions_text.yview)
        self.permissions_text.configure(yscrollcommand=perm_scroll.set)

        self.permissions_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        perm_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Permission controls
        perm_control_frame = ttk.Frame(file_frame)
        perm_control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(perm_control_frame, text="Check Permissions", command=self.check_permissions).pack(side=tk.LEFT, padx=2)
        if self.system != "Windows":
            ttk.Button(perm_control_frame, text="Change Owner", command=self.change_owner).pack(side=tk.LEFT, padx=2)
            ttk.Button(perm_control_frame, text="Change Permissions", command=self.change_permissions).pack(side=tk.LEFT, padx=2)
        else:
            ttk.Button(perm_control_frame, text="Take Ownership", command=self.take_ownership).pack(side=tk.LEFT, padx=2)
            ttk.Button(perm_control_frame, text="Set Permissions", command=self.set_windows_permissions).pack(side=tk.LEFT, padx=2)

        # Local Security Policies section (New)
        policy_frame = ttk.LabelFrame(self.policies_frame, text="Local Security Policies")
        policy_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.policy_text = tk.Text(policy_frame, height=10, wrap=tk.WORD)
        policy_scroll = ttk.Scrollbar(policy_frame, orient=tk.VERTICAL, command=self.policy_text.yview)
        self.policy_text.configure(yscrollcommand=policy_scroll.set)

        self.policy_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        policy_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        policy_control_frame = ttk.Frame(policy_frame)
        policy_control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(policy_control_frame, text="View Policies", command=self.view_local_policies).pack(side=tk.LEFT, padx=2)
        if self.system == "Windows":
            ttk.Button(policy_control_frame, text="Edit Password Policy", command=self.edit_password_policy).pack(side=tk.LEFT, padx=2)
            ttk.Button(policy_control_frame, text="Edit Account Lockout Policy", command=self.edit_account_lockout_policy).pack(side=tk.LEFT, padx=2)
            ttk.Button(policy_control_frame, text="Open Local Security Policy Editor", command=self.open_secpol_msc).pack(side=tk.LEFT, padx=2)

    def setup_user_policies_tab(self):
        """Setup the User-specific Policies tab"""
        self.user_policies_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.user_policies_frame, text="User Policies")

        # User selection status
        user_status_frame = ttk.Frame(self.user_policies_frame)
        user_status_frame.pack(fill=tk.X, padx=5, pady=5)
        self.user_policy_status_label = ttk.Label(user_status_frame, text="Selected User: None", font=("Arial", 10, "bold"))
        self.user_policy_status_label.pack(side=tk.LEFT)
        ttk.Label(user_status_frame, text="(Select a user in 'Users' tab first)").pack(side=tk.LEFT, padx=10)


        # Program Restrictions
        program_restrict_frame = ttk.LabelFrame(self.user_policies_frame, text="Program Restrictions (Windows Only)")
        program_restrict_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(program_restrict_frame, text="Program Path:").pack(side=tk.LEFT, padx=2, pady=2)
        self.program_path_var = tk.StringVar()
        ttk.Entry(program_restrict_frame, textvariable=self.program_path_var, width=60).pack(side=tk.LEFT, padx=5, pady=2, fill=tk.X, expand=True)
        ttk.Button(program_restrict_frame, text="Browse", command=lambda: self.browse_path_for_entry(self.program_path_var, is_file=True)).pack(side=tk.LEFT, padx=2)
        ttk.Button(program_restrict_frame, text="Add Rule", command=self.add_program_restriction).pack(side=tk.LEFT, padx=2)
        ttk.Button(program_restrict_frame, text="Remove Rule", command=self.remove_program_restriction).pack(side=tk.LEFT, padx=2)

        self.program_rules_tree = ttk.Treeview(program_restrict_frame, columns=("Path",), show="headings", height=5)
        self.program_rules_tree.heading("Path", text="Blocked Program Path")
        self.program_rules_tree.column("Path", width=400)
        program_rules_scroll = ttk.Scrollbar(program_restrict_frame, orient=tk.VERTICAL, command=self.program_rules_tree.yview)
        self.program_rules_tree.configure(yscrollcommand=program_rules_scroll.set)
        self.program_rules_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        program_rules_scroll.pack(side=tk.RIGHT, fill=tk.Y)


        # Folder Restrictions
        folder_restrict_frame = ttk.LabelFrame(self.user_policies_frame, text="Folder Restrictions (Windows Only)")
        folder_restrict_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(folder_restrict_frame, text="Folder Path:").pack(side=tk.LEFT, padx=2, pady=2)
        self.folder_path_var = tk.StringVar()
        ttk.Entry(folder_restrict_frame, textvariable=self.folder_path_var, width=60).pack(side=tk.LEFT, padx=5, pady=2, fill=tk.X, expand=True)
        ttk.Button(folder_restrict_frame, text="Browse", command=lambda: self.browse_path_for_entry(self.folder_path_var, is_file=False)).pack(side=tk.LEFT, padx=2)
        ttk.Button(folder_restrict_frame, text="Add Rule", command=self.add_folder_restriction).pack(side=tk.LEFT, padx=2)
        ttk.Button(folder_restrict_frame, text="Remove Rule", command=self.remove_folder_restriction).pack(side=tk.LEFT, padx=2)

        self.folder_rules_tree = ttk.Treeview(folder_restrict_frame, columns=("Path",), show="headings", height=5)
        self.folder_rules_tree.heading("Path", text="Blocked Folder Path")
        self.folder_rules_tree.column("Path", width=400)
        folder_rules_scroll = ttk.Scrollbar(folder_restrict_frame, orient=tk.VERTICAL, command=self.folder_rules_tree.yview)
        self.folder_rules_tree.configure(yscrollcommand=folder_rules_scroll.set)
        self.folder_rules_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        folder_rules_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Timed Access / Logon Hours
        timed_access_frame = ttk.LabelFrame(self.user_policies_frame, text="Timed Access / Logon Hours (Windows Only)")
        timed_access_frame.pack(fill=tk.X, padx=5, pady=5)

        self.logon_hours_label = ttk.Label(timed_access_frame, text="Current Logon Hours: All")
        self.logon_hours_label.pack(pady=5)

        timed_access_control_frame = ttk.Frame(timed_access_frame)
        timed_access_control_frame.pack(pady=5)
        ttk.Button(timed_access_control_frame, text="Set Logon Hours", command=self.set_logon_hours).pack(side=tk.LEFT, padx=5)
        ttk.Button(timed_access_control_frame, text="Allow All Logon Hours", command=self.clear_logon_hours).pack(side=tk.LEFT, padx=5)

        ttk.Label(timed_access_frame, text="Note: Program/Folder timed restrictions are complex and typically require background services or advanced system policies (e.g., AppLocker, Task Scheduler). This tool focuses on basic access denial and logon hour restrictions.", wraplength=500, justify=tk.LEFT).pack(pady=5)


    def browse_path_for_entry(self, entry_var, is_file=True):
        """Helper to browse for a file or directory and set the entry variable."""
        if is_file:
            path = filedialog.askopenfilename()
        else:
            path = filedialog.askdirectory()
        if path:
            entry_var.set(path)

    def load_user_policies(self):
        """Loads user-specific policies from a JSON file."""
        if os.path.exists(self.user_policies_file):
            try:
                with open(self.user_policies_file, 'r') as f:
                    self.user_policies = json.load(f)
            except json.JSONDecodeError as e:
                messagebox.showerror("Error", f"Failed to load user policies JSON: {e}")
                self.user_policies = {}
            except Exception as e:
                messagebox.showerror("Error", f"An unexpected error occurred loading user policies: {e}")
                self.user_policies = {}
        else:
            self.user_policies = {}

    def save_user_policies(self):
        """Saves user-specific policies to a JSON file."""
        try:
            with open(self.user_policies_file, 'w') as f:
                json.dump(self.user_policies, f, indent=4)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save user policies: {e}")

    def refresh_user_policies_display(self):
        """Refreshes the display of program and folder restrictions for the selected user."""
        self.program_rules_tree.delete(*self.program_rules_tree.get_children())
        self.folder_rules_tree.delete(*self.folder_rules_tree.get_children())
        self.logon_hours_label.config(text="Current Logon Hours: N/A")

        if not self.selected_user_for_policies:
            return

        user_data = self.user_policies.get(self.selected_user_for_policies, {})
        programs = user_data.get('program_restrictions', [])
        folders = user_data.get('folder_restrictions', [])
        logon_hours = user_data.get('logon_hours', 'All')

        for p_path in programs:
            self.program_rules_tree.insert("", "end", values=(p_path,))
        for f_path in folders:
            self.folder_rules_tree.insert("", "end", values=(f_path,))

        self.logon_hours_label.config(text=f"Current Logon Hours: {logon_hours}")

    def clear_user_policies_display(self):
        """Clears the display of user policies when no user is selected."""
        self.program_rules_tree.delete(*self.program_rules_tree.get_children())
        self.folder_rules_tree.delete(*self.folder_rules_tree.get_children())
        self.logon_hours_label.config(text="Current Logon Hours: N/A")


    def refresh_users(self):
        """Refresh the users list"""
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)

        if self.system == "Windows":
            self.refresh_windows_users()
        else:
            self.refresh_unix_users()

    def refresh_windows_users(self):
        """Refresh Windows users"""
        if not WINDOWS_MODULES_AVAILABLE:
            messagebox.showerror("Error", "Windows modules not available")
            return

        try:
            # Get local users
            # Level 3 provides more detailed info including flags, full_name, comment
            users, total, resume = win32net.NetUserEnum(None, 3)
            for user in users:
                username = user['name']
                try:
                    sid = win32security.LookupAccountName(None, username)[0]
                    sid_string = win32security.ConvertSidToStringSid(sid)
                except Exception:
                    sid_string = "N/A" # Fallback if SID cannot be retrieved
                full_name = user.get('full_name', '')
                comment = user.get('comment', '')
                flags = user.get('flags', 0)
                disabled = "Yes" if flags & win32netcon.UF_ACCOUNTDISABLE else "No"

                self.users_tree.insert("", "end", text=username,
                                    values=(sid_string, full_name, comment, disabled))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh Windows users: {str(e)}")

    def refresh_unix_users(self):
        """Refresh Unix users"""
        if not UNIX_MODULES_AVAILABLE:
            messagebox.showerror("Error", "Unix modules not available")
            return

        try:
            for user in pwd.getpwall():
                # Show all users for comprehensive view
                self.users_tree.insert("", "end", text=user.pw_name,
                                        values=(user.pw_uid, user.pw_gid, user.pw_dir, user.pw_shell))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh Unix users: {str(e)}")


    def add_user(self):
        """Add a new user to the system"""
        dialog = UserDialog(self.root, "Add User", self.system, is_edit=False)
        if dialog.result:
            if self.system == "Windows":
                self.add_windows_user(dialog.result)
            else:
                self.add_unix_user(dialog.result)

    def add_windows_user(self, user_data):
        """Add Windows user"""
        username = user_data['username']
        password = user_data['password']
        full_name = user_data['full_name']
        description = user_data['description']
        try:
            user_info = {
                'name': username,
                'password': password,
                'full_name': full_name,
                'comment': description,
                'flags': win32netcon.UF_NORMAL_ACCOUNT,
                'priv': win32netcon.USER_PRIV_USER
            }

            win32net.NetUserAdd(None, 1, user_info)
            messagebox.showinfo("Success", f"User '{username}' created successfully")
            self.refresh_users()
            self.log_action(f"Created Windows user: {username}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create Windows user: {str(e)}")

    def add_unix_user(self, user_data):
        """Add Unix user"""
        username = user_data['username']
        password = user_data['password']
        home_dir = user_data['home_dir']
        shell = user_data['shell']
        groups = user_data['groups']
        try:
            cmd = ["useradd", "-m"]
            if home_dir:
                cmd.extend(["-d", home_dir])
            if shell:
                cmd.extend(["-s", shell])
            if groups:
                cmd.extend(["-G", groups])
            cmd.append(username)

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                if password:
                    # Set password
                    passwd_proc = subprocess.Popen(["passwd", username], stdin=subprocess.PIPE,
                                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    passwd_proc.communicate(input=f"{password}\n{password}\n")

                messagebox.showinfo("Success", f"User '{username}' created successfully")
                self.refresh_users()
                self.log_action(f"Created Unix user: {username}")
            else:
                messagebox.showerror("Error", f"Failed to create user: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create user: {str(e)}")

    def delete_user(self):
        """Delete selected user"""
        selected = self.users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user to delete")
            return

        username = self.users_tree.item(selected[0])["text"]
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete user '{username}'?"):
            if self.system == "Windows":
                self.delete_windows_user(username)
            else:
                self.delete_unix_user(username)

    def delete_windows_user(self, username):
        """Delete Windows user"""
        try:
            win32net.NetUserDel(None, username)
            messagebox.showinfo("Success", f"User '{username}' deleted successfully")
            self.refresh_users()
            self.log_action(f"Deleted Windows user: {username}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete Windows user: {str(e)}")

    def delete_unix_user(self, username):
        """Delete Unix user"""
        try:
            result = subprocess.run(["userdel", "-r", username], capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Success", f"User '{username}' deleted successfully")
                self.refresh_users()
                self.log_action(f"Deleted Unix user: {username}")
            else:
                messagebox.showerror("Error", f"Failed to delete user: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete user: {str(e)}")

    def toggle_user(self):
        """Enable/Disable selected user"""
        selected = self.users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return

        username = self.users_tree.item(selected[0])["text"]

        if self.system == "Windows":
            self.toggle_windows_user(username)
        else:
            self.toggle_unix_user(username)

    def toggle_windows_user(self, username):
        """Toggle Windows user account status"""
        try:
            user_info = win32net.NetUserGetInfo(None, username, 1)
            current_flags = user_info['flags']

            if current_flags & win32netcon.UF_ACCOUNTDISABLE:
                # Enable account
                new_flags = current_flags & ~win32netcon.UF_ACCOUNTDISABLE
                action = "enabled"
            else:
                # Disable account
                new_flags = current_flags | win32netcon.UF_ACCOUNTDISABLE
                action = "disabled"

            user_info['flags'] = new_flags
            win32net.NetUserSetInfo(None, username, 1, user_info)

            messagebox.showinfo("Success", f"User '{username}' {action}")
            self.refresh_users()
            self.log_action(f"User {username} {action}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to toggle user status: {str(e)}")

    def toggle_unix_user(self, username):
        """Toggle Unix user account status"""
        try:
            # Check if account is locked
            result = subprocess.run(["passwd", "-S", username], capture_output=True, text=True)
            if "L" in result.stdout:
                # Unlock account
                subprocess.run(["usermod", "-U", username], check=True)
                action = "unlocked"
            else:
                # Lock account
                subprocess.run(["usermod", "-L", username], check=True)
                action = "locked"

            messagebox.showinfo("Success", f"User '{username}' {action}")
            self.log_action(f"User {username} {action}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to toggle user status: {str(e)}")

    def change_password(self):
        """Change password for selected user"""
        selected = self.users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user")
            return

        username = self.users_tree.item(selected[0])["text"]
        password = simpledialog.askstring("Change Password", f"Enter new password for {username}:", show='*')

        if password:
            if self.system == "Windows":
                self.change_windows_password(username, password)
            else:
                self.change_unix_password(username, password)

    def change_windows_password(self, username, password):
        """Change Windows user password"""
        try:
            # Level 1003 is for password
            user_info = {'password': password}
            win32net.NetUserSetInfo(None, username, 1003, user_info)
            messagebox.showinfo("Success", f"Password changed for user '{username}'")
            self.log_action(f"Changed password for Windows user: {username}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change Windows password: {str(e)}")

    def change_unix_password(self, username, password):
        """Change Unix user password"""
        try:
            passwd_proc = subprocess.Popen(["passwd", username], stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Send password twice for confirmation
            passwd_proc.communicate(input=f"{password}\n{password}\n")
            messagebox.showinfo("Success", f"Password changed for user '{username}'")
            self.log_action(f"Changed password for Unix user: {username}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change Unix password: {str(e)}")

    def rename_user(self):
        """Rename selected user"""
        selected = self.users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user to rename.")
            return

        old_username = self.users_tree.item(selected[0])["text"]
        new_username = simpledialog.askstring("Rename User", f"Enter new username for '{old_username}':")

        if new_username and new_username != old_username:
            if messagebox.askyesno("Confirm Rename", f"Are you sure you want to rename '{old_username}' to '{new_username}'?"):
                if self.system == "Windows":
                    self.rename_windows_user(old_username, new_username)
                else:
                    self.rename_unix_user(old_username, new_username)

    def rename_windows_user(self, old_username, new_username):
        """Rename Windows user"""
        if not self.is_admin:
            messagebox.showwarning("Warning", "Administrator privileges required to rename users.")
            return
        try:
            # Using wmic command for renaming as win32net doesn't have a direct rename function
            wmi_cmd = f'wmic useraccount where name="{old_username}" rename "{new_username}"'
            result = subprocess.run(wmi_cmd, capture_output=True, text=True, check=True, shell=True)

            messagebox.showinfo("Success", f"User '{old_username}' renamed to '{new_username}' successfully.")
            self.log_action(f"Renamed Windows user from '{old_username}' to '{new_username}'")
            self.refresh_users()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to rename Windows user: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to rename Windows user: {str(e)}")

    def rename_unix_user(self, old_username, new_username):
        """Rename Unix user"""
        try:
          
          # that is a lot of code...
          # usermod -l newname oldname
            result = subprocess.run(["usermod", "-l", new_username, old_username], capture_output=True, text=True, check=True)
            messagebox.showinfo("Success", f"User '{old_username}' renamed to '{new_username}' successfully.")
            self.log_action(f"Renamed Unix user from '{old_username}' to '{new_username}'")
            self.refresh_users()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to rename Unix user: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to rename Unix user: {str(e)}")

    def edit_user_properties(self):
        """Edit properties of selected user"""
        selected = self.users_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a user to edit.")
            return

        username = self.users_tree.item(selected[0])["text"]
        current_values = self.users_tree.item(selected[0])["values"]

        user_data = {'username': username}
        if self.system == "Windows":
            user_data['sid'] = current_values[0]
            user_data['full_name'] = current_values[1]
            user_data['description'] = current_values[2]
            user_data['disabled'] = current_values[3]
        else: # Unix
            user_data['uid'] = current_values[0]
            user_data['gid'] = current_values[1]
            user_data['home_dir'] = current_values[2]
            user_data['shell'] = current_values[3]
            # Need to fetch groups for Unix if not already in treeview
            try:
                user_groups = []
                for g in grp.getgrall():
                    if username in g.gr_mem:
                        user_groups.append(g.gr_name)
                user_data['groups'] = ", ".join(user_groups)
            except Exception:
                user_data['groups'] = ""


        dialog = UserDialog(self.root, f"Edit Properties for {username}", self.system, user_data=user_data, is_edit=True)
        if dialog.result:
            if self.system == "Windows":
                self.edit_windows_user_properties(dialog.result)
            else:
                self.edit_unix_user_properties(dialog.result)

    def edit_windows_user_properties(self, user_data):
        """Edit Windows user properties"""
        username = user_data['username']
        full_name = user_data['full_name']
        description = user_data['description']
        try:
            # Get current info (level 1 for basic properties)
            current_user_info = win32net.NetUserGetInfo(None, username, 1)
            # Update only the fields that can be changed via this dialog
            current_user_info['full_name'] = full_name
            current_user_info['comment'] = description

            # Set the updated info
            win32net.NetUserSetInfo(None, username, 1, current_user_info)
            messagebox.showinfo("Success", f"Properties for user '{username}' updated successfully.")
            self.log_action(f"Updated Windows user properties for: {username}")
            self.refresh_users()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to edit Windows user properties: {str(e)}")

    def edit_unix_user_properties(self, user_data):
        """Edit Unix user properties"""
        username = user_data['username']
        home_dir = user_data['home_dir']
        shell = user_data['shell']
        groups = user_data['groups'] # This is a comma-separated string

        try:
            cmd = ["usermod"]
            if home_dir:
                cmd.extend(["-d", home_dir])
            if shell:
                cmd.extend(["-s", shell])
            # For groups, usermod -G replaces existing supplementary groups.
            # To add/remove specific groups, it's more complex.
            # For simplicity, if groups are provided, we'll set them.
            if groups:
                cmd.extend(["-G", groups])
            cmd.append(username)

            result = subprocess.run(cmd, capture_output=True, text=True, check=True)

            # Handle group changes separately if needed, as -G replaces
            # A more robust solution would involve comparing current groups and adding/removing individually.
            # For now, if the user specifies groups, we set them.

            messagebox.showinfo("Success", f"Properties for user '{username}' updated successfully.")
            self.log_action(f"Updated Unix user properties for: {username}")
            self.refresh_users()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to edit Unix user properties: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to edit Unix user properties: {str(e)}")


    # Group Management Methods
    def refresh_groups(self):
        """Refresh the groups list"""
        for item in self.groups_tree.get_children():
            self.groups_tree.delete(item)

        if self.system == "Windows":
            self.refresh_windows_groups()
        else:
            self.refresh_unix_groups()

    def refresh_windows_groups(self):
        """Refresh Windows groups"""
        if not WINDOWS_MODULES_AVAILABLE:
            return

        try:
            # Level 1 provides name and comment
            groups, total, resume = win32net.NetLocalGroupEnum(None, 1)
            for group in groups:
                group_name = group['name']
                comment = group.get('comment', '')

                try:
                    sid = win32security.LookupAccountName(None, group_name)[0]
                    sid_string = win32security.ConvertSidToStringSid(sid)
                except Exception:
                    sid_string = "Unknown" # Fallback if SID cannot be retrieved

                self.groups_tree.insert("", "end", text=group_name,
                                     values=(sid_string, comment, "Local"))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh Windows groups: {str(e)}")

    def refresh_unix_groups(self):
        """Refresh Unix groups"""
        if not UNIX_MODULES_AVAILABLE:
            return

        try:
            for group in grp.getgrall():
                members = ", ".join(group.gr_mem) if group.gr_mem else "None"
                self.groups_tree.insert("", "end", text=group.gr_name,
                                     values=(group.gr_gid, members))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh Unix groups: {str(e)}")

    def add_group(self):
        """Add a new group"""
        groupname = simpledialog.askstring("Add Group", "Enter group name:")
        if groupname:
            if self.system == "Windows":
                self.add_windows_group(groupname)
            else:
                self.add_unix_group(groupname)

    def add_windows_group(self, groupname):
        """Add Windows group"""
        try:
            group_info = {
                'name': groupname,
                'comment': f'Group created by Admin Tool'
            }
            win32net.NetLocalGroupAdd(None, 1, group_info)
            messagebox.showinfo("Success", f"Group '{groupname}' created successfully")
            self.refresh_groups()
            self.log_action(f"Created Windows group: {groupname}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create Windows group: {str(e)}")

    def add_unix_group(self, groupname):
        """Add Unix group"""
        try:
            result = subprocess.run(["groupadd", groupname], capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Success", f"Group '{groupname}' created successfully")
                self.refresh_groups()
                self.log_action(f"Created Unix group: {groupname}")
            else:
                messagebox.showerror("Error", f"Failed to create group: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create group: {str(e)}")

    def delete_group(self):
        """Delete selected group"""
        selected = self.groups_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a group to delete")
            return

        groupname = self.groups_tree.item(selected[0])["text"]
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete group '{groupname}'?"):
            if self.system == "Windows":
                self.delete_windows_group(groupname)
            else:
                self.delete_unix_group(groupname)

    def delete_windows_group(self, groupname):
        """Delete Windows group"""
        try:
            win32net.NetLocalGroupDel(None, groupname)
            messagebox.showinfo("Success", f"Group '{groupname}' deleted successfully")
            self.refresh_groups()
            self.log_action(f"Deleted Windows group: {groupname}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete Windows group: {str(e)}")

    def delete_unix_group(self, groupname):
        """Delete Unix group"""
        try:
            result = subprocess.run(["groupdel", groupname], capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Success", f"Group '{groupname}' created successfully")
                self.refresh_groups()
                self.log_action(f"Deleted Unix group: {groupname}")
            else:
                messagebox.showerror("Error", f"Failed to delete group: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete group: {str(e)}")

    def add_user_to_group(self):
        """Add user to selected group"""
        selected = self.groups_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a group")
            return

        groupname = self.groups_tree.item(selected[0])["text"]
        username = simpledialog.askstring("Add User to Group", f"Enter username to add to '{groupname}':")

        if username:
            if self.system == "Windows":
                self.add_user_to_windows_group(username, groupname)
            else:
                self.add_user_to_unix_group(username, groupname)

    def add_user_to_windows_group(self, username, groupname):
        """Add user to Windows group"""
        try:
            # Level 3 is for local group members
            win32net.NetLocalGroupAddMembers(None, groupname, 3, [{'domainandname': username}])
            messagebox.showinfo("Success", f"User '{username}' added to group '{groupname}'")
            self.refresh_groups()
            self.log_action(f"Added Windows user '{username}' to group '{groupname}'")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add user to Windows group: {str(e)}")

    def add_user_to_unix_group(self, username, groupname):
        """Add user to Unix group"""
        try:
            # Using 'usermod -aG' to append user to supplementary group
            result = subprocess.run(["usermod", "-aG", groupname, username], capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Success", f"User '{username}' added to group '{groupname}'")
                self.refresh_groups()
                self.log_action(f"Added Unix user '{username}' to group '{groupname}'")
            else:
                messagebox.showerror("Error", f"Failed to add user to Unix group: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add user to Unix group: {str(e)}")

    def remove_user_from_group(self):
        """Remove user from selected group"""
        selected = self.groups_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a group")
            return

        groupname = self.groups_tree.item(selected[0])["text"]
        username = simpledialog.askstring("Remove User from Group", f"Enter username to remove from '{groupname}':")

        if username:
            if messagebox.askyesno("Confirm", f"Are you sure you want to remove user '{username}' from group '{groupname}'?"):
                if self.system == "Windows":
                    self.remove_user_from_windows_group(username, groupname)
                else:
                    self.remove_user_from_unix_group(username, groupname)

    def remove_user_from_windows_group(self, username, groupname):
        """Remove user from Windows group"""
        try:
            # Level 3 is for local group members
            win32net.NetLocalGroupDelMembers(None, groupname, 3, [{'domainandname': username}])
            messagebox.showinfo("Success", f"User '{username}' removed from group '{groupname}'")
            self.refresh_groups()
            self.log_action(f"Removed Windows user '{username}' from group '{groupname}'")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove user from Windows group: {str(e)}")

    def remove_user_from_unix_group(self, username, groupname):
        """Remove user from Unix group"""
        try:
            # Using 'gpasswd -d' to remove user from supplementary group
            result = subprocess.run(["gpasswd", "-d", username, groupname], capture_output=True, text=True)
            if result.returncode == 0:
                messagebox.showinfo("Success", f"User '{username}' removed from group '{groupname}'")
                self.refresh_groups()
                self.log_action(f"Removed Unix user '{username}' from group '{groupname}'")
            else:
                messagebox.showerror("Error", f"Failed to remove user from Unix group: {result.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to remove user from Unix group: {str(e)}")

    # Policies & Permissions Methods
    def browse_file(self):
        """Browse for a file or directory"""
        path = filedialog.askopenfilename() if self.system == "Windows" else filedialog.askdirectory()
        if path:
            self.file_path_var.set(path)
            self.check_permissions() # Automatically check permissions after selecting

    def check_permissions(self):
        """Check permissions for the specified file/directory"""
        path = self.file_path_var.get()
        if not path:
            messagebox.showwarning("Warning", "Please enter a file/directory path.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Error", "Path does not exist.")
            return

        self.permissions_text.delete(1.0, tk.END)
        if self.system == "Windows":
            self.check_windows_permissions(path)
        else:
            self.check_unix_permissions(path)

    def check_windows_permissions(self, path):
        """Check Windows file/directory permissions (ACLs)"""
        if not WINDOWS_MODULES_AVAILABLE:
            messagebox.showerror("Error", "Windows modules not available")
            return
        try:
            # Get the security descriptor for the file/directory
            sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
            dacl = sd.GetSecurityDescriptorDacl() # Get the DACL (Discretionary Access Control List)

            if dacl is None:
                self.permissions_text.insert(tk.END, "No DACL found for this path (permissions might be inherited or default).\n")
                return

            self.permissions_text.insert(tk.END, f"Permissions for: {path}\n\n")

            # Iterate through Access Control Entries (ACEs) in the DACL
            for i in range(dacl.GetAceCount()):
                ace = dacl.GetAce(i)
                try:
                    type, flags, access_mask, sid = ace
                except ValueError:
                    self.permissions_text.insert(tk.END, f"Warning: Could not unpack ACE at index {i}: {ace}\n")
                    continue

                # Convert SID to account name
                try:
                    name, domain, _ = win32security.LookupAccountSid(None, sid)
                    account_name = f"{domain}\\{name}" if domain else name
                except Exception:
                    account_name = str(sid) # Fallback to SID string if lookup fails

                # Determine ACE type (Allow/Deny)
                ace_type = "ALLOW" if type == win32security.ACCESS_ALLOWED_ACE_TYPE else "DENY"

                # Map access mask to human-readable permissions
                perm_strings = []
                # Common permissions for files/directories
                if access_mask & win32con.FILE_GENERIC_READ:
                    perm_strings.append("Read")
                if access_mask & win32con.FILE_GENERIC_WRITE:
                    perm_strings.append("Write")
                if access_mask & win32con.FILE_GENERIC_EXECUTE:
                    perm_strings.append("Execute")
                if access_mask & win32con.FILE_DELETE:
                    perm_strings.append("Delete")
                if access_mask & win32con.DELETE: # Generic delete
                    perm_strings.append("Delete (Generic)")
                if access_mask & win32con.FILE_TRAVERSE:
                    perm_strings.append("Traverse (Folder)")
                if access_mask & win32con.FILE_LIST_DIRECTORY:
                    perm_strings.append("List Directory (Folder)")
                if access_mask & win32con.FILE_ADD_FILE:
                    perm_strings.append("Add File (Folder)")
                if access_mask & win32con.FILE_ADD_SUBDIRECTORY:
                    perm_strings.append("Add Subdirectory (Folder)")
                if access_mask & win32con.FILE_WRITE_ATTRIBUTES:
                    perm_strings.append("Write Attributes")
                if access_mask & win32con.FILE_WRITE_EA:
                    perm_strings.append("Write Extended Attributes")
                if access_mask & win32con.SYNCHRONIZE:
                    perm_strings.append("Synchronize")
                if access_mask & win32con.READ_CONTROL:
                    perm_strings.append("Read Control")
                if access_mask & win32con.WRITE_DAC:
                    perm_strings.append("Write DAC")
                if access_mask & win32con.WRITE_OWNER:
                    perm_strings.append("Write Owner")
                if access_mask & win32con.GENERIC_ALL:
                    perm_strings.append("Full Control")

                permissions_str = ", ".join(perm_strings) if perm_strings else f"Raw Mask: {hex(access_mask)}"

                self.permissions_text.insert(tk.END, f"Account: {account_name}\n")
                self.permissions_text.insert(tk.END, f"  Type: {ace_type}\n")
                self.permissions_text.insert(tk.END, f"  Permissions: {permissions_str}\n\n")

            # Get owner and primary group
            owner_sid = sd.GetSecurityDescriptorOwner()
            group_sid = sd.GetSecurityDescriptorGroup()

            try:
                owner_name, owner_domain, _ = win32security.LookupAccountSid(None, owner_sid)
                owner_display = f"{owner_domain}\\{owner_name}" if owner_domain else owner_name
            except Exception:
                owner_display = str(owner_sid)

            try:
                group_name, group_domain, _ = win32security.LookupAccountSid(None, group_sid)
                group_display = f"{group_domain}\\{group_name}" if group_domain else group_name
            except Exception:
                group_display = str(group_sid)

            self.permissions_text.insert(tk.END, f"Owner: {owner_display}\n")
            self.permissions_text.insert(tk.END, f"Primary Group: {group_display}\n")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to check Windows permissions: {str(e)}")
            self.permissions_text.insert(tk.END, f"Error: {e}\n")
        self.log_action(f"Checked permissions for: {path}")

    def check_unix_permissions(self, path):
        """Check Unix file/directory permissions"""
        try:
            stat_info = os.stat(path)
            mode = stat_info.st_mode
            owner_uid = stat_info.st_uid
            group_gid = stat_info.st_gid

            # Convert UID/GID to names
            owner_name = pwd.getpwuid(owner_uid).pw_name
            group_name = grp.getgrgid(group_gid).gr_name

            # Format permissions
            permissions = oct(mode)[-3:] # Get octal permissions (e.g., 755)
            readable_permissions = self.get_readable_unix_permissions(mode)

            self.permissions_text.insert(tk.END, f"Permissions for: {path}\n")
            self.permissions_text.insert(tk.END, f"Owner: {owner_name} (UID: {owner_uid})\n")
            self.permissions_text.insert(tk.END, f"Group: {group_name} (GID: {group_gid})\n")
            self.permissions_text.insert(tk.END, f"Octal Permissions: {permissions}\n")
            self.permissions_text.insert(tk.END, f"Symbolic Permissions: {readable_permissions}\n")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to check Unix permissions: {str(e)}")
            self.permissions_text.insert(tk.END, f"Error: {e}\n")
        self.log_action(f"Checked permissions for: {path}")

    def get_readable_unix_permissions(self, mode):
        """Convert octal mode to rwx string."""
        import stat
        perm_str = ""
        # Owner
        perm_str += "r" if (mode & stat.S_IRUSR) else "-"
        perm_str += "w" if (mode & stat.S_IWUSR) else "-"
        perm_str += "x" if (mode & stat.S_IXUSR) else "-"
        # Group
        perm_str += "r" if (mode & stat.S_IRGRP) else "-"
        perm_str += "w" if (mode & stat.S_IWGRP) else "-"
        perm_str += "x" if (mode & stat.S_IXGRP) else "-"
        # Others
        perm_str += "r" if (mode & stat.S_IROTH) else "-"
        perm_str += "w" if (mode & stat.S_IWOTH) else "-"
        perm_str += "x" if (mode & stat.S_IXOTH) else "-"
        return perm_str

    def change_owner(self):
        """Change owner of a file/directory (Unix only)"""
        path = self.file_path_var.get()
        if not path:
            messagebox.showwarning("Warning", "Please enter a file/directory path.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Error", "Path does not exist.")
            return

        new_owner = simpledialog.askstring("Change Owner", "Enter new owner username:")
        if new_owner:
            try:
                subprocess.run(["chown", new_owner, path], check=True, capture_output=True, text=True)
                messagebox.showinfo("Success", f"Owner of '{path}' changed to '{new_owner}'")
                self.log_action(f"Changed owner of '{path}' to '{new_owner}'")
                self.check_permissions()
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to change owner: {e.stderr}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to change owner: {str(e)}")

    def change_permissions(self):
        """Change permissions of a file/directory (Unix only)"""
        path = self.file_path_var.get()
        if not path:
            messagebox.showwarning("Warning", "Please enter a file/directory path.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Error", "Path does not exist.")
            return

        new_perms = simpledialog.askstring("Change Permissions", "Enter new octal permissions (e.g., 755):")
        if new_perms:
            try:
                # Validate octal format
                int(new_perms, 8)
                subprocess.run(["chmod", new_perms, path], check=True, capture_output=True, text=True)
                messagebox.showinfo("Success", f"Permissions of '{path}' changed to '{new_perms}'")
                self.log_action(f"Changed permissions of '{path}' to '{new_perms}'")
                self.check_permissions()
            except ValueError:
                messagebox.showerror("Error", "Invalid octal permission format.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to change permissions: {e.stderr}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to change permissions: {str(e)}")

    def take_ownership(self):
        """Take ownership of a file/directory (Windows only)"""
        if not self.is_admin:
            messagebox.showwarning("Warning", "Administrator privileges required to take ownership.")
            return
        if not WINDOWS_MODULES_AVAILABLE:
            messagebox.showerror("Error", "Windows modules not available")
            return

        path = self.file_path_var.get()
        if not path:
            messagebox.showwarning("Warning", "Please enter a file/directory path.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Error", "Path does not exist.")
            return

        try:
            # Get current process token
            h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
            # Get LUID for SeTakeOwnershipPrivilege
            luid = win32security.LookupPrivilegeValue(None, win32con.SE_TAKE_OWNERSHIP_NAME)
            # Enable the privilege
            win32security.AdjustTokenPrivileges(h_token, 0, [(luid, win32con.SE_PRIVILEGE_ENABLED)])

            # Get the current user's SID
            current_user_sid, _, _ = win32security.LookupAccountName(None, win32api.GetUserName())

            # Get the security descriptor for the file/directory
            sd = win32security.GetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION)

            # Set the new owner
            sd.SetSecurityDescriptorOwner(current_user_sid, False) # False means not a default owner

            # Set the updated security descriptor back to the file
            win32security.SetFileSecurity(path, win32security.OWNER_SECURITY_INFORMATION, sd)

            messagebox.showinfo("Success", f"Ownership of '{path}' taken by current user.")
            self.log_action(f"Took ownership of '{path}'")
            self.check_permissions() # Refresh display
        except Exception as e:
            messagebox.showerror("Error", f"Failed to take ownership: {str(e)}")
        finally:
            # Always disable the privilege when done
            if 'h_token' in locals() and h_token:
                win32security.AdjustTokenPrivileges(h_token, 0, [(luid, win32con.SE_PRIVILEGE_REMOVED)])


    def set_windows_permissions(self):
        """
        Opens a dialog to set Windows permissions (ACLs) for the selected file/directory.
        This is a complex operation and will require a more advanced dialog.
        For simplicity, this example will show a placeholder and succulent using `icacls` via subprocess.
        A full GUI for ACL editing is beyond the scope of a simple example.
        """
        path = self.file_path_var.get()
        if not path:
            messagebox.showwarning("Warning", "Please enter a file/directory path.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Error", "Path does not exist.")
            return

        if not self.is_admin:
            messagebox.showwarning("Warning", "Administrator privileges required to set permissions.")
            return

        messagebox.showinfo("Set Windows Permissions",
                             "Modifying Windows ACLs via GUI is complex.\n"
                             "For now, you can use the 'icacls' command in an elevated command prompt.\n\n"
                             "Example: icacls \"C:\\path\\to\\file\" /grant \"Username\":(F)\n"
                             "Or: icacls \"C:\\path\\to\\file\" /inheritance:d /grant \"Username\":(OI)(CI)(F)")
        self.log_action(f"Attempted to set Windows permissions for: {path} (user directed to icacls)")
        # A more advanced implementation would involve:
        # 1. Reading existing DACL.
        # 2. Presenting a GUI to add/remove ACEs, or modify existing ones.
        # 3. Converting user-friendly permissions (Read, Write, Full Control) to access masks.
        # 4. Applying the new DACL using SetFileSecurity.

    # Local Security Policies Methods (New)
    def view_local_policies(self):
        """View local security policies (Windows: net accounts, Unix: placeholder)"""
        self.policy_text.delete(1.0, tk.END)
        if self.system == "Windows":
            self.view_windows_local_policies()
        else:
            self.view_unix_local_policies()

    def view_windows_local_policies(self):
        """View Windows local security policies using 'net accounts'"""
        if not self.is_admin:
            self.policy_text.insert(tk.END, "Administrator privileges required to view all policy details.\n")
            return
        try:
            # Get password policy
            result = subprocess.run(["net", "accounts"], capture_output=True, text=True, check=True)
            self.policy_text.insert(tk.END, "--- Password and Account Lockout Policy ---\n")
            self.policy_text.insert(tk.END, result.stdout)
            self.policy_text.insert(tk.END, "\nFor more detailed policies, use 'secpol.msc'.\n")
            self.log_action("Viewed Windows local security policies.")
        except subprocess.CalledProcessError as e:
            self.policy_text.insert(tk.END, f"Error viewing policies: {e.stderr}\n")
            messagebox.showerror("Error", f"Failed to view Windows local policies: {e.stderr}")
        except Exception as e:
            self.policy_text.insert(tk.END, f"Error viewing policies: {str(e)}\n")
            messagebox.showerror("Error", f"Failed to view Windows local policies: {str(e)}")

    def view_unix_local_policies(self):
        """View Unix local security policies (placeholder)"""
        self.policy_text.insert(tk.END, "Local Security Policies (Unix/Linux):\n\n")
        self.policy_text.insert(tk.END, "Policy management on Unix-like systems is typically done via configuration files (e.g., /etc/login.defs, /etc/pam.d/, /etc/security/limits.conf) and commands like 'chage' for password aging.\n\n")
        self.policy_text.insert(tk.END, "This tool currently provides limited direct policy editing for Unix systems.\n")
        self.log_action("Viewed Unix local security policies (placeholder).")

    def edit_password_policy(self):
        """Edit Windows password policy using 'net accounts' commands"""
        if not self.is_admin:
            messagebox.showwarning("Warning", "Administrator privileges required to edit password policy.")
            return

        max_age = simpledialog.askinteger("Password Policy", "Maximum password age (days, 0 for never expire):")
        min_len = simpledialog.askinteger("Password Policy", "Minimum password length:")
        min_age = simpledialog.askinteger("Password Policy", "Minimum password age (days):")
        # password_req = simpledialog.askstring("Password Policy", "Password complexity (Yes/No):").lower() # net accounts doesn't directly control this
        # enforce_history = simpledialog.askinteger("Password Policy", "Enforce password history (passwords remembered):") # net accounts doesn't directly control this

        if max_age is not None:
            try:
                subprocess.run(["net", "accounts", f"/maxpwage:{max_age}"], check=True, capture_output=True, text=True)
                self.log_action(f"Set max password age to {max_age} days.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to set max password age: {e.stderr}")
                return

        if min_len is not None:
            try:
                subprocess.run(["net", "accounts", f"/minpwlen:{min_len}"], check=True, capture_output=True, text=True)
                self.log_action(f"Set min password length to {min_len}.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to set min password length: {e.stderr}")
                return

        if min_age is not None:
            try:
                subprocess.run(["net", "accounts", f"/minpwage:{min_age}"], check=True, capture_output=True, text=True)
                self.log_action(f"Set min password age to {min_age} days.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to set min password age: {e.stderr}")
                return

        messagebox.showinfo("Success", "Password policy settings updated.")
        self.view_local_policies() # Refresh display

    def edit_account_lockout_policy(self):
        """Edit Windows account lockout policy using 'net accounts' commands"""
        if not self.is_admin:
            messagebox.showwarning("Warning", "Administrator privileges required to edit account lockout policy.")
            return

        threshold = simpledialog.askinteger("Account Lockout Policy", "Lockout threshold (failed logon attempts, 0 for never lockout):")
        duration = simpledialog.askinteger("Account Lockout Policy", "Lockout duration (minutes):")
        reset_counter = simpledialog.askinteger("Account Lockout Policy", "Reset lockout counter after (minutes):")

        if threshold is not None:
            try:
                subprocess.run(["net", "accounts", f"/lockoutthreshold:{threshold}"], check=True, capture_output=True, text=True)
                self.log_action(f"Set lockout threshold to {threshold}.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to set lockout threshold: {e.stderr}")
                return

        if duration is not None:
            try:
                subprocess.run(["net", "accounts", f"/lockoutduration:{duration}"], check=True, capture_output=True, text=True)
                self.log_action(f"Set lockout duration to {duration} minutes.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to set lockout duration: {e.stderr}")
                return

        if reset_counter is not None:
            try:
                subprocess.run(["net", "accounts", f"/lockoutwindow:{reset_counter}"], check=True, capture_output=True, text=True)
                self.log_action(f"Set lockout reset counter to {reset_counter} minutes.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to set lockout reset counter: {e.stderr}")
                return

        messagebox.showinfo("Success", "Account lockout policy settings updated.")
        self.view_local_policies() # Refresh display

    def open_secpol_msc(self):
        """Open the Local Security Policy Editor (Windows only)"""
        if self.system == "Windows":
            try:
                subprocess.Popen(["secpol.msc"])
                self.log_action("Opened Local Security Policy Editor (secpol.msc).")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open Local Security Policy Editor: {str(e)}")
        else:
            messagebox.showwarning("Not Available", "Local Security Policy Editor is a Windows-specific tool.")


    def add_program_restriction(self):
        """Adds a program restriction for the selected user."""
        if not self.selected_user_for_policies:
            messagebox.showwarning("No User Selected", "Please select a user in the 'Users' tab first.")
            return
        if self.system != "Windows":
            messagebox.showwarning("Not Supported", "Program restrictions are currently only supported on Windows.")
            return
        if not self.is_admin:
            messagebox.showwarning("Permission Denied", "Administrator privileges are required to add program restrictions.")
            return

        program_path = self.program_path_var.get().strip()
        if not program_path:
            messagebox.showerror("Input Error", "Please enter a program path.")
            return
        if not os.path.exists(program_path):
            messagebox.showerror("Error", "Program path does not exist.")
            return
        if not os.path.isfile(program_path):
            messagebox.showerror("Error", "The specified path is not a file.")
            return

        user_data = self.user_policies.setdefault(self.selected_user_for_policies, {'program_restrictions': [], 'folder_restrictions': [], 'logon_hours': 'All'})
        if program_path not in user_data['program_restrictions']:
            user_data['program_restrictions'].append(program_path)
            self.apply_program_restriction_os(self.selected_user_for_policies, program_path)
            self.save_user_policies()
            self.refresh_user_policies_display()
            self.log_action(f"Added program restriction for {self.selected_user_for_policies}: {program_path}")
        else:
            messagebox.showinfo("Already Exists", "This program restriction already exists for the selected user.")

    def remove_program_restriction(self):
        """Removes a program restriction for the selected user."""
        if not self.selected_user_for_policies:
            messagebox.showwarning("No User Selected", "Please select a user in the 'Users' tab first.")
            return
        if self.system != "Windows":
            messagebox.showwarning("Not Supported", "Program restrictions are currently only supported on Windows.")
            return
        if not self.is_admin:
            messagebox.showwarning("Permission Denied", "Administrator privileges are required to remove program restrictions.")
            return

        selected_item = self.program_rules_tree.selection()
        if not selected_item:
            messagebox.showwarning("No Rule Selected", "Please select a program restriction to remove.")
            return

        program_path = self.program_rules_tree.item(selected_item[0])["values"][0]

        if messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove the restriction for '{program_path}' for user '{self.selected_user_for_policies}'?"):
            user_data = self.user_policies.get(self.selected_user_for_policies)
            if user_data and program_path in user_data['program_restrictions']:
                user_data['program_restrictions'].remove(program_path)
                self.remove_program_restriction_os(self.selected_user_for_policies, program_path)
                self.save_user_policies()
                self.refresh_user_policies_display()
                self.log_action(f"Removed program restriction for {self.selected_user_for_policies}: {program_path}")
            else:
                messagebox.showinfo("Not Found", "The selected program restriction was not found.")

    def apply_program_restriction_os(self, username, path):
        """Applies a program restriction using icacls (Windows)."""
        try:
            # Deny execute permission for the user on the executable
            cmd = ['icacls', path, '/deny', f'{username}:(X)']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            messagebox.showinfo("Success", f"Applied program restriction for '{username}' on '{path}'.\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to apply program restriction: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred applying program restriction: {str(e)}")

    def remove_program_restriction_os(self, username, path):
        """Removes a program restriction using icacls (Windows)."""
        try:
            # Remove the deny rule for the user on the executable
            cmd = ['icacls', path, '/remove', f'{username}']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            messagebox.showinfo("Success", f"Removed program restriction for '{username}' on '{path}'.\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to remove program restriction: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred removing program restriction: {str(e)}")

    def add_folder_restriction(self):
        """Adds a folder restriction for the selected user."""
        if not self.selected_user_for_policies:
            messagebox.showwarning("No User Selected", "Please select a user in the 'Users' tab first.")
            return
        if self.system != "Windows":
            messagebox.showwarning("Not Supported", "Folder restrictions are currently only supported on Windows.")
            return
        if not self.is_admin:
            messagebox.showwarning("Permission Denied", "Administrator privileges are required to add folder restrictions.")
            return

        folder_path = self.folder_path_var.get().strip()
        if not folder_path:
            messagebox.showerror("Input Error", "Please enter a folder path.")
            return
        if not os.path.exists(folder_path):
            messagebox.showerror("Error", "Folder path does not exist.")
            return
        if not os.path.isdir(folder_path):
            messagebox.showerror("Error", "The specified path is not a directory.")
            return

        user_data = self.user_policies.setdefault(self.selected_user_for_policies, {'program_restrictions': [], 'folder_restrictions': [], 'logon_hours': 'All'})
        if folder_path not in user_data['folder_restrictions']:
            user_data['folder_restrictions'].append(folder_path)
            self.apply_folder_restriction_os(self.selected_user_for_policies, folder_path)
            self.save_user_policies()
            self.refresh_user_policies_display()
            self.log_action(f"Added folder restriction for {self.selected_user_for_policies}: {folder_path}")
        else:
            messagebox.showinfo("Already Exists", "This folder restriction already exists for the selected user.")

    def remove_folder_restriction(self):
        """Removes a folder restriction for the selected user."""
        if not self.selected_user_for_policies:
            messagebox.showwarning("No User Selected", "Please select a user in the 'Users' tab first.")
            return
        if self.system != "Windows":
            messagebox.showwarning("Not Supported", "Folder restrictions are currently only supported on Windows.")
            return
        if not self.is_admin:
            messagebox.showwarning("Permission Denied", "Administrator privileges are required to remove folder restrictions.")
            return

        selected_item = self.folder_rules_tree.selection()
        if not selected_item:
            messagebox.showwarning("No Rule Selected", "Please select a folder restriction to remove.")
            return

        folder_path = self.folder_rules_tree.item(selected_item[0])["values"][0]

        if messagebox.askyesno("Confirm Removal", f"Are you sure you want to remove the restriction for '{folder_path}' for user '{self.selected_user_for_policies}'?"):
            user_data = self.user_policies.get(self.selected_user_for_policies)
            if user_data and folder_path in user_data['folder_restrictions']:
                user_data['folder_restrictions'].remove(folder_path)
                self.remove_folder_restriction_os(self.selected_user_for_policies, folder_path)
                self.save_user_policies()
                self.refresh_user_policies_display()
                self.log_action(f"Removed folder restriction for {self.selected_user_for_policies}: {folder_path}")
            else:
                messagebox.showinfo("Not Found", "The selected folder restriction was not found.")

    def apply_folder_restriction_os(self, username, path):
        """Applies a folder restriction using icacls (Windows)."""
        try:
            # Deny read, write, execute, delete for the user on the folder and its contents (OI)(CI)
            # (OI) - Object Inherit: applies to files and subfolders
            # (CI) - Container Inherit: applies to subfolders
            cmd = ['icacls', path, '/deny', f'{username}:(OI)(CI)(RX)'] # Deny Read/Execute
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            messagebox.showinfo("Success", f"Applied folder restriction for '{username}' on '{path}'.\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to apply folder restriction: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred applying folder restriction: {str(e)}")

    def remove_folder_restriction_os(self, username, path):
        """Removes a folder restriction using icacls (Windows)."""
        try:
            # Remove the deny rule for the user on the folder
            cmd = ['icacls', path, '/remove', f'{username}']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            messagebox.showinfo("Success", f"Removed folder restriction for '{username}' on '{path}'.\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to remove folder restriction: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred removing folder restriction: {str(e)}")

    def set_logon_hours(self):
        """Opens a dialog to set logon hours for the selected user (Windows only)."""
        if not self.selected_user_for_policies:
            messagebox.showwarning("No User Selected", "Please select a user in the 'Users' tab first.")
            return
        if self.system != "Windows":
            messagebox.showwarning("Not Supported", "Logon hours are only supported on Windows.")
            return
        if not self.is_admin:
            messagebox.showwarning("Permission Denied", "Administrator privileges are required to set logon hours.")
            return

        # Days of the week (Mon-Sun)
        days = ["M", "Tu", "W", "Th", "F", "Sa", "Su"]
        # Hours of the day (0-23)
        hours = [str(i) for i in range(24)]

        # Create a Toplevel window for logon hours selection
        logon_hours_window = tk.Toplevel(self.root)
        logon_hours_window.title(f"Set Logon Hours for {self.selected_user_for_policies}")
        logon_hours_window.transient(self.root) # Make it appear on top of the main window
        logon_hours_window.grab_set() # Make it modal

        selected_hours = {} # {day: [hour1, hour2, ...]}

        # Initialize with current settings if available
        current_logon_hours_str = self.user_policies.get(self.selected_user_for_policies, {}).get('logon_hours', 'All')
        if current_logon_hours_str != 'All':
            # Parse the string back into a usable format
            try:
                # Example format: "M-F,8am-5pm;Sa,9am-12pm"
                day_hour_pairs = current_logon_hours_str.split(';')
                for pair in day_hour_pairs:
                    if ',' in pair:
                        day_part, time_part = pair.split(',', 1)
                        # Handle day ranges like M-F
                        if '-' in day_part:
                            start_day_abbr, end_day_abbr = day_part.split('-')
                            start_index = days.index(start_day_abbr)
                            end_index = days.index(end_day_abbr)
                            current_days = days[start_index : end_index + 1]
                        else:
                            current_days = [day_part]

                        # Handle time ranges like 8am-5pm
                        if '-' in time_part:
                            start_time_str, end_time_str = time_part.split('-')
                            start_hour = int(start_time_str.replace('am', '').replace('pm', ''))
                            end_hour = int(end_time_str.replace('am', '').replace('pm', ''))
                            if 'pm' in start_time_str and start_hour != 12: start_hour += 12
                            if 'pm' in end_time_str and end_hour != 12: end_hour += 12
                            if end_hour == 0: end_hour = 24 # Midnight
                            current_hours = list(range(start_hour, end_hour))
                        else: # Specific hour like "8am"
                            hr = int(time_part.replace('am', '').replace('pm', ''))
                            if 'pm' in time_part and hr != 12: hr += 12
                            current_hours = [hr]

                        for d in current_days:
                            selected_hours.setdefault(d, []).extend(current_hours)
            except Exception as e:
                print(f"Error parsing logon hours string: {e}")
                selected_hours = {} # Reset if parsing fails

        # Create a grid of checkboxes for each day and hour
        checkbox_vars = {} # Store IntVar for each checkbox

        # Header for hours
        for col, hour in enumerate(hours):
            ttk.Label(logon_hours_window, text=hour, relief="solid", width=3, anchor="center").grid(row=0, column=col+1, padx=1, pady=1)

        for row, day in enumerate(days):
            ttk.Label(logon_hours_window, text=day, relief="solid", width=5, anchor="w").grid(row=row+1, column=0, padx=1, pady=1)
            for col, hour in enumerate(hours):
                var = tk.IntVar(value=1 if int(hour) in selected_hours.get(day, []) else 0) # Pre-select if already in policy
                chk = ttk.Checkbutton(logon_hours_window, variable=var, command=lambda d=day, h=int(hour), v=var: self.toggle_hour_selection(d, h, v, selected_hours))
                chk.grid(row=row+1, column=col+1, padx=1, pady=1)
                checkbox_vars[(day, int(hour))] = var

        # Function to update selected_hours based on checkbox clicks
        def toggle_hour_selection(day, hour, var, selected_hours_dict):
            if var.get() == 1:
                selected_hours_dict.setdefault(day, []).append(hour)
                selected_hours_dict[day].sort()
            else:
                if day in selected_hours_dict and hour in selected_hours_dict[day]:
                    selected_hours_dict[day].remove(hour)

        # OK and Cancel buttons
        button_frame = ttk.Frame(logon_hours_window)
        button_frame.grid(row=len(days)+1, columnspan=len(hours)+1, pady=10)

        def on_ok():
            formatted_times = self.format_logon_hours(selected_hours)
            self.apply_logon_hours_os(self.selected_user_for_policies, formatted_times)
            self.user_policies.setdefault(self.selected_user_for_policies, {}).update({'logon_hours': formatted_times})
            self.save_user_policies()
            self.refresh_user_policies_display()
            self.log_action(f"Set logon hours for {self.selected_user_for_policies}: {formatted_times}")
            logon_hours_window.destroy()

        ttk.Button(button_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=logon_hours_window.destroy).pack(side=tk.LEFT, padx=5)

        self.root.wait_window(logon_hours_window) # Wait for the dialog to close

    def toggle_hour_selection(self, day, hour, var, selected_hours_dict):
        """Helper for the logon hours dialog to update selected_hours."""
        if var.get() == 1:
            selected_hours_dict.setdefault(day, []).append(hour)
            selected_hours_dict[day].sort()
        else:
            if day in selected_hours_dict and hour in selected_hours_dict[day]:
                selected_hours_dict[day].remove(hour)

    def format_logon_hours(self, selected_hours):
        """Formats the selected hours into the 'net user /times' string format."""
        # Example: "M-F,8am-5pm;Sa,9am-12pm"
        formatted_parts = []
        days_map = {"M": 0, "Tu": 1, "W": 2, "Th": 3, "F": 4, "Sa": 5, "Su": 6}
        inverse_days_map = {v: k for k, v in days_map.items()}

        # Sort days for consistent output
        sorted_days = sorted(selected_hours.keys(), key=lambda d: days_map[d])

        for day in sorted_days:
            hours_list = sorted(list(set(selected_hours[day]))) # Remove duplicates and sort
            if not hours_list:
                continue

            # Group consecutive hours
            ranges = []
            if hours_list:
                start = hours_list[0]
                end = hours_list[0]
                for i in range(1, len(hours_list)):
                    if hours_list[i] == end + 1:
                        end = hours_list[i]
                    else:
                        ranges.append((start, end))
                        start = hours_list[i]
                        end = hours_list[i]
                ranges.append((start, end)) # Add the last range

            day_parts = []
            for start_hour, end_hour in ranges:
                # Convert 24-hour to 12-hour format with am/pm
                def format_hour(h):
                    if h == 0: return "12am"
                    if h == 12: return "12pm"
                    if h < 12: return f"{h}am"
                    return f"{h-12}pm"

                # net user /times uses 24-hour format for ranges
                # M,8-17;Tu,8-17
                # Or M-F,8-17
                day_parts.append(f"{start_hour}-{end_hour + 1}") # End hour is exclusive in net user

            formatted_parts.append(f"{day},{','.join(day_parts)}")

        if not formatted_parts:
            return "All" # If no hours selected, allow all

        # Attempt to consolidate day ranges (e.g., M,8-17;Tu,8-17 -> M-Tu,8-17)
        final_parts = []
        i = 0
        while i < len(formatted_parts):
            current_day_str, current_hours_str = formatted_parts[i].split(',', 1)
            current_day_abbr = current_day_str
            current_day_index = days_map[current_day_abbr]

            j = i + 1
            while j < len(formatted_parts):
                next_day_str, next_hours_str = formatted_parts[j].split(',', 1)
                next_day_abbr = next_day_str
                next_day_index = days_map[next_day_abbr]

                if next_day_index == current_day_index + 1 and next_hours_str == current_hours_str:
                    current_day_index = next_day_index
                    j += 1
                else:
                    break

            if i == j - 1: # No consolidation
                final_parts.append(formatted_parts[i])
            else:
                start_day_abbr = formatted_parts[i].split(',')[0]
                end_day_abbr = formatted_parts[j-1].split(',')[0]
                final_parts.append(f"{start_day_abbr}-{end_day_abbr},{current_hours_str}")
            i = j

        return ";".join(final_parts)


    def apply_logon_hours_os(self, username, formatted_times):
        """Applies logon hours using 'net user /times' (Windows)."""
        try:
            cmd = ['net', 'user', username, f'/times:{formatted_times}']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            messagebox.showinfo("Success", f"Logon hours set for '{username}': {formatted_times}.\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to set logon hours: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred setting logon hours: {str(e)}")

    def clear_logon_hours(self):
        """Sets logon hours to 'All' for the selected user (Windows only)."""
        if not self.selected_user_for_policies:
            messagebox.showwarning("No User Selected", "Please select a user in the 'Users' tab first.")
            return
        if self.system != "Windows":
            messagebox.showwarning("Not Supported", "Logon hours are only supported on Windows.")
            return
        if not self.is_admin:
            messagebox.showwarning("Permission Denied", "Administrator privileges are required to clear logon hours.")
            return

        if messagebox.askyesno("Confirm Clear Logon Hours", f"Are you sure you want to allow user '{self.selected_user_for_policies}' to log on at all times?"):
            self.apply_logon_hours_os(self.selected_user_for_policies, "All")
            self.user_policies.setdefault(self.selected_user_for_policies, {}).update({'logon_hours': 'All'})
            self.save_user_policies()
            self.refresh_user_policies_display()
            self.log_action(f"Cleared logon hours for {self.selected_user_for_policies} (set to All).")


    def setup_processes_tab(self):
        """Setup the Processes management tab"""
        self.processes_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.processes_frame, text="Processes")

        # Processes list frame
        processes_list_frame = ttk.LabelFrame(self.processes_frame, text="Running Processes")
        processes_list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Treeview for processes
        columns = ("PID", "User", "Memory (MB)", "CPU (%)", "Command")
        self.processes_tree = ttk.Treeview(processes_list_frame, columns=columns, show="headings")

        for col in columns:
            self.processes_tree.heading(col, text=col)
            self.processes_tree.column(col, width=100)

        # Adjust column widths for better readability
        self.processes_tree.column("PID", width=60)
        self.processes_tree.column("User", width=100)
        self.processes_tree.column("Memory (MB)", width=100)
        self.processes_tree.column("CPU (%)", width=80)
        self.processes_tree.column("Command", width=300, stretch=tk.YES)


        # Scrollbar for processes tree
        processes_scrollbar = ttk.Scrollbar(processes_list_frame, orient=tk.VERTICAL, command=self.processes_tree.yview)
        self.processes_tree.configure(yscrollcommand=processes_scrollbar.set)

        self.processes_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        processes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Processes control frame
        processes_control_frame = ttk.Frame(self.processes_frame)
        processes_control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(processes_control_frame, text="Kill Process", command=self.kill_process).pack(side=tk.LEFT, padx=2)
        ttk.Button(processes_control_frame, text="Refresh", command=self.refresh_processes).pack(side=tk.RIGHT, padx=2)

    # Process Management Methods
    def refresh_processes(self):
        """Refresh the processes list"""
        for item in self.processes_tree.get_children():
            self.processes_tree.delete(item)

        if self.system == "Windows":
            self.refresh_windows_processes()
        else:
            self.refresh_unix_processes()

    def refresh_windows_processes(self):
        """Refresh Windows processes using WMI"""
        if not WINDOWS_MODULES_AVAILABLE or not self.wmi_conn:
            messagebox.showerror("Error", "WMI connection or Windows modules not available.")
            return

        try:
            # Using a dictionary to store process info for easier updates/calculations
            processes_info = {}
            for process in self.wmi_conn.Win32_Process():
                try:
                    owner = process.GetOwner()
                    username = f"{owner[1]}\\{owner[0]}" if owner[1] else owner[0]
                except Exception:
                    username = "N/A"

                memory_mb = round(int(process.WorkingSetSize) / (1024 * 1024), 2) if process.WorkingSetSize else 0

                # Store initial CPU times for later calculation if needed
                # For a single snapshot, CPU % is hard to get accurately from WMI directly
                processes_info[process.ProcessId] = {
                    'username': username,
                    'memory_mb': memory_mb,
                    'cpu_percent': "N/A", # Placeholder for now
                    'command': process.CommandLine or process.Name,
                    'kernel_time': process.KernelModeTime,
                    'user_time': process.UserModeTime
                }

            for pid, info in processes_info.items():
                self.processes_tree.insert("", "end",
                                           values=(pid, info['username'], info['memory_mb'], info['cpu_percent'], info['command']))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh Windows processes: {str(e)}")

    def refresh_unix_processes(self):
        """Refresh Unix processes using ps command"""
        try:
            # Use 'ps aux' for detailed process information
            # PID, USER, %CPU, %MEM, COMMAND
            result = subprocess.run(["ps", "aux"], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            # Skip header line
            if len(lines) > 1:
                for line in lines[1:]:
                    parts = line.split(None, 10) # Split by whitespace, max 10 times to keep command intact
                    if len(parts) >= 11:
                        pid = parts[1]
                        user = parts[0]
                        cpu = parts[2]
                        mem = parts[3]
                        command = parts[10] # The rest is the command

                        # Convert memory to MB for consistency (ps aux gives %MEM, but some tools give actual usage)
                        # For now, we'll just display %MEM as is.
                        memory_display = f"{mem}%"

                        self.processes_tree.insert("", "end",
                                                   values=(pid, user, cpu, memory_display, command))
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to refresh Unix processes: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh Unix processes: {str(e)}")

    def kill_process(self):
        """Kill selected process"""
        selected = self.processes_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a process to kill.")
            return

        pid = self.processes_tree.item(selected[0])["values"][0] # PID is the first value
        command = self.processes_tree.item(selected[0])["values"][4] # Command is the last value

        if messagebox.askyesno("Confirm Kill", f"Are you sure you want to kill process PID: {pid} ({command})?"):
            if self.system == "Windows":
                self.kill_windows_process(pid)
            else:
                self.kill_unix_process(pid)

    def kill_windows_process(self, pid):
        """Kill Windows process"""
        if not self.is_admin:
            messagebox.showwarning("Warning", "Administrator privileges required to kill processes.")
            return
        if not WINDOWS_MODULES_AVAILABLE or not self.wmi_conn:
            messagebox.showerror("Error", "WMI connection or Windows modules not available.")
            return

        try:
            # Find the process by PID using WMI
            process_to_kill = self.wmi_conn.Win32_Process(ProcessId=pid)
            if process_to_kill:
                # Terminate the process
                process_to_kill[0].Terminate()
                messagebox.showinfo("Success", f"Process PID {pid} killed successfully.")
                self.log_action(f"Killed Windows process PID: {pid}")
                self.refresh_processes()
            else:
                messagebox.showwarning("Not Found", f"Process with PID {pid} not found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to kill Windows process: {str(e)}")

    def kill_unix_process(self, pid):
        """Kill Unix process"""
        try:
            # Use 'kill -9' for forceful termination
            result = subprocess.run(["kill", "-9", str(pid)], capture_output=True, text=True, check=True)
            messagebox.showinfo("Success", f"Process PID {pid} killed successfully.")
            self.log_action(f"Killed Unix process PID: {pid}")
            self.refresh_processes()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to kill Unix process: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to kill Unix process: {str(e)}")

    def setup_logs_tab(self):
        """Setup the Logs and Events tab"""
        self.logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_frame, text="Logs & Events")

        # Log display area
        log_display_frame = ttk.LabelFrame(self.logs_frame, text="Activity Log")
        log_display_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.log_text = tk.Text(log_display_frame, wrap=tk.WORD, height=15)
        log_scroll = ttk.Scrollbar(log_display_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Log controls
        log_control_frame = ttk.Frame(self.logs_frame)
        log_control_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(log_control_frame, text="Clear Display", command=self.clear_log_display).pack(side=tk.LEFT, padx=2)
        ttk.Button(log_control_frame, text="Save Log", command=self.save_log).pack(side=tk.LEFT, padx=2)

        # System Event Logs section
        event_log_frame = ttk.LabelFrame(self.logs_frame, text="System Event Logs")
        event_log_frame.pack(fill=tk.X, padx=5, pady=5)

        if self.system == "Windows":
            ttk.Button(event_log_frame, text="View Windows Event Log", command=self.view_event_log).pack(side=tk.LEFT, padx=2)
        else:
            ttk.Button(event_log_frame, text="View Auth Log", command=self.view_auth_log).pack(side=tk.LEFT, padx=2)
            ttk.Button(event_log_frame, text="View System Log", command=self.view_system_log).pack(side=tk.LEFT, padx=2)

    # Logging Methods
    def log_action(self, action_message):
        """Log an administrative action with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {action_message}\n"
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END) # Scroll to the end

        # Also write to file
        with open(self.log_file, "a") as f:
            f.write(log_entry)

    def load_log(self):
        """Load existing log entries into the display"""
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                self.log_text.insert(tk.END, f.read())
            self.log_text.see(tk.END)

    def clear_log_display(self):
        """Clear the log display area"""
        if messagebox.askyesno("Confirm Clear", "Are you sure you want to clear the displayed log? This does NOT delete the log file."):
            self.log_text.delete(1.0, tk.END)
            self.log_action("Log display cleared.")

    def save_log(self):
        """Save the current log display to a file (already saved incrementally, but good for explicit save)"""
        try:
            content = self.log_text.get(1.0, tk.END)
            file_path = filedialog.asksaveasfilename(defaultextension=".log",
                                                      filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")])
            if file_path:
                with open(file_path, "w") as f:
                    f.write(content)
                messagebox.showinfo("Save Log", f"Log saved to: {file_path}")
                self.log_action(f"Log saved to: {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def view_event_log(self):
        """View Windows Event Log (Security, System, Application)"""
        if not WINDOWS_MODULES_AVAILABLE:
            messagebox.showerror("Error", "Windows modules not available")
            return

        # Simple dialog to choose log type
        log_type = simpledialog.askstring("View Event Log", "Enter log type (e.g., 'System', 'Application', 'Security'):", initialvalue="System")
        if not log_type:
            return

        try:
            # Using subprocess to open Event Viewer is often more user-friendly
            # than parsing raw event logs via pywin32evtlog for a GUI tool.
            # 'eventvwr.msc' is the command to open Event Viewer.
            # You can specify a log by using a custom view XML, but that's complex.
            # For simplicity, we'll just open the main Event Viewer.
            subprocess.Popen(["eventvwr.msc"])
            messagebox.showinfo("Event Log", f"Opening Windows Event Viewer. Please navigate to '{log_type}' log manually.")
            self.log_action(f"Opened Windows Event Viewer to view '{log_type}' log.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open Event Viewer: {str(e)}")

    def view_auth_log(self):
        """View Unix authentication log"""
        log_path = "/var/log/auth.log" # Common path for Debian/Ubuntu
        if platform.system() == "Darwin": # macOS
            log_path = "/var/log/system.log" # macOS auth logs are often in system.log or unified log
            messagebox.showinfo("Note", "On macOS, authentication logs are typically part of the unified log system. This will show /var/log/system.log.")
        elif os.path.exists("/var/log/secure"): # RHEL/CentOS/Fedora
            log_path = "/var/log/secure"

        if not os.path.exists(log_path):
            messagebox.showerror("Error", f"Authentication log not found at {log_path}")
            return

        try:
            # Read last 50 lines for brevity
            result = subprocess.run(["tail", "-n", "50", log_path], capture_output=True, text=True, check=True)
            self.log_text.insert(tk.END, f"\n--- Last 50 lines from {log_path} ---\n")
            self.log_text.insert(tk.END, result.stdout)
            self.log_text.see(tk.END)
            self.log_action(f"Viewed last 50 lines of Unix auth log: {log_path}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to read auth log: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read auth log: {str(e)}")

    def view_system_log(self):
        """View Unix system log"""
        log_path = "/var/log/syslog" # Common path for Debian/Ubuntu
        if platform.system() == "Darwin": # macOS
            log_path = "/var/log/system.log" # macOS system logs are often in system.log or unified log
            messagebox.showinfo("Note", "On macOS, system logs are typically part of the unified log system. This will show /var/log/system.log.")
        elif os.path.exists("/var/log/messages"): # RHEL/CentOS/Fedora
            log_path = "/var/log/messages"

        if not os.path.exists(log_path):
            messagebox.showerror("Error", f"System log not found at {log_path}")
            return

        try:
            # Read last 50 lines for brevity
            result = subprocess.run(["tail", "-n", "50", log_path], capture_output=True, text=True, check=True)
            self.log_text.insert(tk.END, f"\n--- Last 50 lines from {log_path} ---\n")
            self.log_text.insert(tk.END, result.stdout)
            self.log_text.see(tk.END)
            self.log_action(f"Viewed last 50 lines of Unix system log: {log_path}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to read system log: {e.stderr}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read system log: {str(e)}")

    def refresh_all_data(self):
        """Refreshes data in all relevant tabs."""
        self.refresh_users()
        self.refresh_groups()
        self.refresh_processes()
        self.refresh_user_policies_display() # Ensure this is called to update the policies tab


if __name__ == "__main__":
    root = tk.Tk()
    app = SystemAdminGUI(root)
    root.mainloop()

# fuck it...