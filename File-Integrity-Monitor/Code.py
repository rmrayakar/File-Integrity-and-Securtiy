import glob
import hashlib
import os
import tkinter as tk
from tkinter.filedialog import askdirectory
import customtkinter as ctk
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import base64
import secrets
from fpdf import FPDF
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import shutil
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

baselines = r"C:\Users\ankit\Desktop\Cryptography"#Baseline.txt will be at this specified path
versions_dir = r"C:\Users\ankit\Desktop\Cryptography\versions"#Versions will be stored here
secure_path = ""

name_hash=""
baseline_path=""

files_changed = []
files_added = []
files_removed = []
files_all = []

spaces = "                                                                        \n"

# Advanced encryption key management
def generate_salt():
    """Generate a random salt for key derivation"""
    return get_random_bytes(16)

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a key using PBKDF2"""
    return PBKDF2(
        password.encode(),
        salt,
        dkLen=32,  # 256 bits
        count=100000,  # High iteration count for security
        hmac_hash_module=hashlib.sha256
    )

def save_key(key: bytes, salt: bytes, key_file: str = "encryption_key.key"):
    """Save the encryption key and salt to a file"""
    with open(key_file, "wb") as f:
        f.write(salt + key)

def load_key(key_file: str = "encryption_key.key") -> tuple[bytes, bytes]:
    """Load the encryption key and salt from a file"""
    try:
        with open(key_file, "rb") as f:
            data = f.read()
            salt = data[:16]  # First 16 bytes are salt
            key = data[16:]   # Rest is the key
            return salt, key
    except FileNotFoundError:
        return None, None

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypt data using AES-256-CBC"""
    # Generate a random IV
    iv = get_random_bytes(16)
    
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad and encrypt the data
    padded_data = pad(data.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # Combine IV and ciphertext
    return base64.b64encode(iv + ciphertext)

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypt data using AES-256-CBC"""
    # Decode from base64
    data = base64.b64decode(encrypted_data)
    
    # Split IV and ciphertext
    iv = data[:16]
    ciphertext = data[16:]
    
    # Create AES cipher
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Decrypt and unpad the data
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext.decode()

# Initialize encryption with a secure password
def initialize_encryption():
    """Initialize encryption with a secure password"""
    # You should store this password securely in a real application
    # For demonstration, we'll use a hardcoded password
    # In production, you should use a secure password manager or environment variables
    password = "YourSecurePassword123!"  # Change this to a secure password
    
    salt, key = load_key()
    if salt is None or key is None:
        # Generate new salt and key
        salt = generate_salt()
        key = derive_key(password, salt)
        save_key(key, salt)
    
    return key

# Initialize encryption
encryption_key = initialize_encryption()

#Calculate hash from data in a file 
def CalculateSha512Hash(file_name):
    # BUF_SIZE is totally arbitrary, change as per your requirement
    BUF_SIZE = 65536  # 65536 lets read stuff in 64kb chunks!
    sha = hashlib.sha512()
    
    with open(file_name,'rb') as file:
        while True:
            data = file.read(BUF_SIZE)
            if not data:
                break
            sha.update(data)
            # print("SHA: {0}".format(sha.hexdigest()))
        return sha.hexdigest()
    
#Calculate hash from name of a file 
def CalculateNameHash(filename):
    md5 = hashlib.md5()
    md5.update(filename.encode())
    return md5.hexdigest()

#Updates baseline
def UpdateBaseline(dir,mode):
    if dir=="":
        label3.configure(text="Error : Folder not selected")

    elif os.path.isdir(baselines)==False:
        label3.configure(text="Message : Baselines Folder doesn't exists, so creating it")
        os.makedirs(baselines)
        label3.configure(text="Message : Updating Baseline...")
        UpdateBaselineHelper(dir,mode)
        label3.configure(text="Message : Updated Baseline Successfully")
        
    else:
        label3.configure(text="Message : Updating Baseline...")
        UpdateBaselineHelper(dir,mode)
        label3.configure(text="Message : Updated Baseline Successfully")

#Update Baseline Helper for [files in a folder] and [files in subfolders]
def UpdateBaselineHelper(dir,mode):
    global name_hash,baseline_path
    if(mode=='w'):
        name_hash = CalculateNameHash(dir)    
        baseline_path = os.path.join(baselines,(name_hash+'.txt'))
    
    files = [os.path.abspath(f) for f in glob.glob(os.path.join(dir,'*')) if os.path.isfile(f)]
    
    # Create temporary file to store baseline data
    temp_data = ""
    for f in files:
        hash = CalculateSha512Hash(os.path.join(dir,f))
        temp_data += f"{f}={str(hash)}\n"
    
    # Encrypt the data before writing to file
    encrypted_data = encrypt_data(temp_data, encryption_key)
    with open(baseline_path, 'wb') as baseline:
        baseline.write(encrypted_data)
    
    directories = [d for d in glob.glob(os.path.join(dir,'*')) if os.path.isdir(d)]
    for d in directories:
        UpdateBaselineHelper(d,'a')

#Returns dictionary containing keys as file name and values as their hashes
def getKeyHashesFromBaseline():
    global name_hash,baseline_path
    dict = {}

    try:
        with open(baseline_path, 'rb') as baseline:
            encrypted_data = baseline.read()
            decrypted_data = decrypt_data(encrypted_data, encryption_key)
            
            for line in decrypted_data.splitlines():
                if line.strip():  # Skip empty lines
                    key, value = line.split('=')
                    dict[key] = value
    except Exception as e:
        label3.configure(text=f"Error reading baseline: {str(e)}")
        return {}
   
    return dict

#clears data in all 4 lists
def ClearData():
    files_changed.clear()
    files_added.clear()
    files_removed.clear()
    files_all.clear()

    changed_text.delete("1.0", "end")
    added_text.delete("1.0", "end")
    removed_text.delete("1.0", "end")
    status_bar.configure(text="Data cleared")

#Calculates hashes and Checks with the baseline
def CheckIntegrity(dir, number):
    ClearData()  # Clear data in all 4 lists

    if dir == "":
        label3.configure(text="Error : Folder not selected")
    else:
        CheckIntegrityHelper(dir, number)
        
        # Update text areas with new content
        if files_changed:
            changed_text.delete("1.0", "end")
            changed_text.insert("1.0", "\n".join(files_changed))
        else:
            changed_text.delete("1.0", "end")
            changed_text.insert("1.0", "No changes detected")
            
        if files_added:
            added_text.delete("1.0", "end")
            added_text.insert("1.0", "\n".join(files_added))
        else:
            added_text.delete("1.0", "end")
            added_text.insert("1.0", "No new files")
            
        if files_removed:
            removed_text.delete("1.0", "end")
            removed_text.insert("1.0", "\n".join(files_removed))
        else:
            removed_text.delete("1.0", "end")
            removed_text.insert("1.0", "No files removed")

        # Generate PDF report
        try:
            report_path = generate_pdf_report()
            label3.configure(text=f"Message : Integrity Checked Successfully. Report saved to {report_path}")
        except Exception as e:
            label3.configure(text=f"Message : Integrity Checked Successfully. Failed to generate report: {str(e)}")

#Helper () for Check Integrity
def CheckIntegrityHelper(dir,number):
    global name_hash,baseline_path

    if(number):
        name_hash = CalculateNameHash(dir)
        baseline_path = os.path.join(baselines,(name_hash+'.txt'))
        try:
            with open(baseline_path,'r') as baseline:
                random=99
        except IOError:
            label3.configure(text='Error : Baseline file for specified folder not present')
            return
        
    files = [os.path.abspath(f) for f in glob.glob(os.path.join(dir,'*')) if os.path.isfile(f)]
    for x in files:
        files_all.append(x)
    dict = getKeyHashesFromBaseline()
    
    for f in files:
        current_hash = CalculateSha512Hash(f)
        file_path = str(f)
        
        # Checking for changed files
        if file_path in dict:
            if current_hash != dict[file_path]:
                relative_path = os.path.abspath(f).replace(os.path.abspath(folder), ".")
                if relative_path not in files_changed:
                    files_changed.append(relative_path)
        else:
            # Checking for added files
            relative_path = os.path.abspath(f).replace(os.path.abspath(folder), ".")
            if relative_path not in files_added:
                files_added.append(relative_path)
    
    
    directories = [d for d in glob.glob(os.path.join(dir,'*')) if os.path.isdir(d)]
    for d in directories:
        CheckIntegrityHelper(d,0)
    
    if number==1:
        #checking for removed files
        for x in list(dict.keys()):
            if x not in files_all:
                relative_path = os.path.abspath(x).replace(os.path.abspath(folder), ".")
                if relative_path not in files_removed:
                    files_removed.append(relative_path)

def send_email_alert(subject, body):
    """Send an email alert using SMTP. Fill in the placeholders below."""
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = 'ankit.p.patil06@gmail.com'
    sender_password = 'nmvhckzfsbcssobd'
    receiver_email = 'ankitpatil.cs22@rvce.edu.in'

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Create SMTP connection with timeout
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
        server.set_debuglevel(1)  # Enable debug output
        
        # Start TLS connection
        server.starttls()
        
        # Login with error handling
        try:
            server.login(sender_email, sender_password)
        except smtplib.SMTPAuthenticationError:
            print("Error: SMTP Authentication failed. Please check your email and app password.")
            return False
        except Exception as e:
            print(f"Error during login: {str(e)}")
            return False

        # Send email with error handling
        try:
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print(f"Email alert sent successfully: {subject}")
            return True
        except Exception as e:
            print(f"Error sending email: {str(e)}")
            return False
        finally:
            server.quit()
            
    except smtplib.SMTPConnectError:
        print("Error: Could not connect to SMTP server. Please check your internet connection.")
        return False
    except smtplib.SMTPTimeoutError:
        print("Error: Connection to SMTP server timed out. Please check your internet connection.")
        return False
    except Exception as e:
        print(f"Unexpected error while sending email: {str(e)}")
        return False

def get_next_version_number(file_path):
    """Get the next version number for a file"""
    base_name = os.path.basename(file_path)
    name, ext = os.path.splitext(base_name)
    
    # Create versions directory if it doesn't exist
    if not os.path.exists(versions_dir):
        os.makedirs(versions_dir)
    
    # Get all existing versions of this file
    version_pattern = os.path.join(versions_dir, f"{name}_v*{ext}")
    existing_versions = glob.glob(version_pattern)
    
    if not existing_versions:
        return 1
    
    # Extract version numbers and find the highest
    version_numbers = []
    for version in existing_versions:
        try:
            version_num = int(version.split('_v')[1].split(ext)[0])
            version_numbers.append(version_num)
        except ValueError:
            continue
    
    return max(version_numbers) + 1 if version_numbers else 1

def create_version_backup(file_path):
    """Create a version backup of the modified file"""
    try:
        if not os.path.exists(versions_dir):
            os.makedirs(versions_dir)
            
        base_name = os.path.basename(file_path)
        name, ext = os.path.splitext(base_name)
        version_num = get_next_version_number(file_path)
        
        # Create version file name
        version_file = os.path.join(versions_dir, f"{name}_v{version_num}{ext}")
        
        # Copy the file to versions directory
        shutil.copy2(file_path, version_file)
        print(f"Created version backup: {version_file}")
        return True
    except Exception as e:
        print(f"Error creating version backup: {e}")
        return False

# Add these as global variables at the top with other globals
last_modified_file = ""
last_deleted_file = ""
last_created_file = ""

class FileChangeHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            global last_created_file
            last_created_file = event.src_path
            print(f"File created: {event.src_path}")
            # Update UI
            root.after(0, lambda: update_ui_for_creation(event.src_path))
            # Try to send email, but don't block UI if it fails
            try:
                send_email_alert(
                    subject="File Created Alert",
                    body=f"A new file was created: {event.src_path}"
                )
            except Exception as e:
                print(f"Failed to send email alert: {e}")
            
    def on_modified(self, event):
        if not event.is_directory:
            global last_modified_file
            last_modified_file = event.src_path
            print(f"File modified: {event.src_path}")
            # Create version backup before sending alert
            if create_version_backup(event.src_path):
                # Update UI
                root.after(0, lambda: update_ui_for_modification(event.src_path))
                # Try to send email, but don't block UI if it fails
                try:
                    send_email_alert(
                        subject="File Modified Alert",
                        body=f"A file was modified: {event.src_path}\nVersion backup created successfully."
                    )
                except Exception as e:
                    print(f"Failed to send email alert: {e}")
            else:
                # Update UI even if backup fails
                root.after(0, lambda: update_ui_for_modification(event.src_path))
                # Try to send email, but don't block UI if it fails
                try:
                    send_email_alert(
                        subject="File Modified Alert",
                        body=f"A file was modified: {event.src_path}\nFailed to create version backup."
                    )
                except Exception as e:
                    print(f"Failed to send email alert: {e}")
                
    def on_deleted(self, event):
        if not event.is_directory:
            global last_deleted_file
            last_deleted_file = event.src_path
            print(f"File deleted: {event.src_path}")
            # Update UI
            root.after(0, lambda: update_ui_for_deletion(event.src_path))
            # Try to send email, but don't block UI if it fails
            try:
                send_email_alert(
                    subject="File Deleted Alert",
                    body=f"A file was deleted: {event.src_path}"
                )
            except Exception as e:
                print(f"Failed to send email alert: {e}")

def update_ui_for_creation(file_path):
    """Update UI when a file is created"""
    relative_path = os.path.abspath(file_path).replace(os.path.abspath(folder), ".")
    if relative_path not in files_added:
        files_added.append(relative_path)
        added_text.delete("1.0", "end")
        added_text.insert("1.0", "\n".join(files_added))
    label3.configure(text=f"Message: New file created: {relative_path}")
    status_bar.configure(text=f"File created: {relative_path}")

def update_ui_for_modification(file_path):
    """Update UI when a file is modified"""
    relative_path = os.path.abspath(file_path).replace(os.path.abspath(folder), ".")
    if relative_path not in files_changed:
        files_changed.append(relative_path)
        changed_text.delete("1.0", "end")
        changed_text.insert("1.0", "\n".join(files_changed))
    label3.configure(text=f"Message: File modified: {relative_path}")
    status_bar.configure(text=f"File modified: {relative_path}")

def update_ui_for_deletion(file_path):
    """Update UI when a file is deleted"""
    relative_path = os.path.abspath(file_path).replace(os.path.abspath(folder), ".")
    if relative_path not in files_removed:
        files_removed.append(relative_path)
        removed_text.delete("1.0", "end")
        removed_text.insert("1.0", "\n".join(files_removed))
    label3.configure(text=f"Message: File deleted: {relative_path}")
    status_bar.configure(text=f"File deleted: {relative_path}")

# Global variables for monitoring
observer = None
is_monitoring = False

################################# GUI #################################

ctk.set_appearance_mode("dark")  # Modes: system (default), light, dark
ctk.set_default_color_theme("dark-blue")  # Themes: blue (default), dark-blue, green

# Custom colors and styles
COLORS = {
    'primary': "#1f538d",
    'secondary': "#2d7dd2",
    'accent': "#00ff9f",
    'warning': "#ff9f1c",
    'error': "#e63946",
    'success': "#2a9d8f",
    'background': "#1a1a1a",
    'text': "#ffffff",
    'text_secondary': "#b3b3b3"
}

# Font configurations
FONTS = {
    'title': ("Helvetica", 24, "bold"),
    'heading': ("Helvetica", 18, "bold"),
    'subheading': ("Helvetica", 14, "bold"),
    'body': ("Helvetica", 12),
    'button': ("Helvetica", 12, "bold")
}

# Initialize root window with improved styling
root = ctk.CTk()
root.title("HashLine - File Integrity Monitor")
root.geometry("800x900")
root.configure(fg_color=COLORS['background'])

# Create main frame
main_frame = ctk.CTkFrame(root, fg_color=COLORS['background'])
main_frame.pack(fill="both", expand=True, padx=20, pady=20)

# Title
title_label = ctk.CTkLabel(
    main_frame,
    text="HashLine",
    font=FONTS['title'],
    text_color=COLORS['accent']
)
title_label.pack(pady=(0, 20))

# Subtitle
subtitle_label = ctk.CTkLabel(
    main_frame,
    text="File Integrity Monitoring System",
    font=FONTS['subheading'],
    text_color=COLORS['text_secondary']
)
subtitle_label.pack(pady=(0, 30))

# Directory Selection Frame
dir_frame = ctk.CTkFrame(main_frame, fg_color=COLORS['primary'])
dir_frame.pack(fill="x", padx=20, pady=10)

# Directory Selection Label
label1 = ctk.CTkLabel(
    dir_frame,
    text="Select a Folder",
    font=FONTS['heading'],
    text_color=COLORS['text']
)
label1.pack(side="left", padx=20, pady=15)

# Add this before the browse button definition
def open_file():
    label3.configure(text="Message: ")
    label2.configure(text="(Selected Folder path will appear here)")
    global folder
    if is_monitoring:
        stop_monitoring()
    folder = askdirectory(parent=root, title="Choose a folder")
    if folder:
        label3.configure(text="Message: Folder Selected Successfully")
        label2.configure(text=folder)
        ClearData()
        status_bar.configure(text=f"Selected folder: {folder}")

# Browse Button
browse_btn = ctk.CTkButton(
    dir_frame,
    text="Browse",
    command=open_file,
    font=FONTS['button'],
    fg_color=COLORS['accent'],
    text_color=COLORS['background'],
    hover_color=COLORS['success'],
    height=40,
    width=120
)
browse_btn.pack(side="right", padx=20, pady=15)

# Selected Path Label
label2 = ctk.CTkLabel(
    main_frame,
    text="(Selected Folder path will appear here)",
    font=FONTS['body'],
    text_color=COLORS['text_secondary'],
    wraplength=700
)
label2.pack(pady=10)

# Action Buttons Frame
action_frame = ctk.CTkFrame(main_frame, fg_color=COLORS['background'])
action_frame.pack(fill="x", padx=20, pady=20)

# Update Baseline Button
update_baseline_btn = ctk.CTkButton(
    action_frame,
    text="Update Baseline",
    command=lambda: UpdateBaseline(folder, 'w'),
    font=FONTS['button'],
    fg_color=COLORS['secondary'],
    text_color=COLORS['text'],
    hover_color=COLORS['primary'],
    height=45,
    width=180
)
update_baseline_btn.pack(pady=10)

# Check Integrity Button
check_integrity_btn = ctk.CTkButton(
    action_frame,
    text="Check Integrity",
    command=lambda: CheckIntegrity(folder, 1),
    font=FONTS['button'],
    fg_color=COLORS['secondary'],
    text_color=COLORS['text'],
    hover_color=COLORS['primary'],
    height=45,
    width=180
)
check_integrity_btn.pack(pady=10)

# Monitor Button
monitor_btn = ctk.CTkButton(
    action_frame,
    text="Start Monitoring",
    command=lambda: start_monitoring(folder),
    font=FONTS['button'],
    fg_color=COLORS['secondary'],
    text_color=COLORS['text'],
    hover_color=COLORS['primary'],
    height=45,
    width=180
)
monitor_btn.pack(pady=10)

# Status Message Label
label3 = ctk.CTkLabel(
    main_frame,
    text="Message: ",
    font=FONTS['body'],
    text_color=COLORS['warning']
)
label3.pack(pady=10)

# Changes Display Frame
changes_frame = ctk.CTkFrame(main_frame, fg_color=COLORS['primary'])
changes_frame.pack(fill="both", expand=True, padx=20, pady=20)

# Create a frame for the three columns
columns_frame = ctk.CTkFrame(changes_frame, fg_color=COLORS['primary'])
columns_frame.pack(fill="both", expand=True, padx=10, pady=10)

# Changed Files Column
changed_frame = ctk.CTkFrame(columns_frame, fg_color=COLORS['primary'])
changed_frame.pack(side="left", fill="both", expand=True, padx=5)

fc = ctk.CTkLabel(
    changed_frame,
    text="Files Changed",
    font=FONTS['subheading'],
    text_color=COLORS['text']
)
fc.pack(pady=(10, 5))

changed_text = ctk.CTkTextbox(
    changed_frame,
    height=200,
    font=FONTS['body'],
    text_color=COLORS['text'],
    fg_color=COLORS['background'],
    border_color=COLORS['accent'],
    border_width=1
)
changed_text.pack(fill="both", expand=True, padx=5, pady=5)

# Added Files Column
added_frame = ctk.CTkFrame(columns_frame, fg_color=COLORS['primary'])
added_frame.pack(side="left", fill="both", expand=True, padx=5)

fa = ctk.CTkLabel(
    added_frame,
    text="Files Added",
    font=FONTS['subheading'],
    text_color=COLORS['text']
)
fa.pack(pady=(10, 5))

added_text = ctk.CTkTextbox(
    added_frame,
    height=200,
    font=FONTS['body'],
    text_color=COLORS['text'],
    fg_color=COLORS['background'],
    border_color=COLORS['accent'],
    border_width=1
)
added_text.pack(fill="both", expand=True, padx=5, pady=5)

# Removed Files Column
removed_frame = ctk.CTkFrame(columns_frame, fg_color=COLORS['primary'])
removed_frame.pack(side="left", fill="both", expand=True, padx=5)

fr = ctk.CTkLabel(
    removed_frame,
    text="Files Removed",
    font=FONTS['subheading'],
    text_color=COLORS['text']
)
fr.pack(pady=(10, 5))

removed_text = ctk.CTkTextbox(
    removed_frame,
    height=200,
    font=FONTS['body'],
    text_color=COLORS['text'],
    fg_color=COLORS['background'],
    border_color=COLORS['accent'],
    border_width=1
)
removed_text.pack(fill="both", expand=True, padx=5, pady=5)

# Add a status bar at the bottom
status_bar = ctk.CTkLabel(
    root,
    text="Ready",
    font=FONTS['body'],
    text_color=COLORS['text_secondary'],
    height=25
)
status_bar.pack(side="bottom", fill="x", padx=10, pady=5)

# Add cleanup when closing the window
def on_closing():
    if is_monitoring:
        stop_monitoring()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

def start_monitoring(path):
    global observer, is_monitoring
    if not is_monitoring and path:
        # Clear previous data when starting new monitoring
        ClearData()
        event_handler = FileChangeHandler()
        observer = Observer()
        observer.schedule(event_handler, path, recursive=True)
        observer.start()
        is_monitoring = True
        label3.configure(text="Message : Monitoring Started")
        monitor_btn.configure(text="Stop Monitoring")
    elif is_monitoring:
        stop_monitoring()
    else:
        label3.configure(text="Error : Please select a folder first")

def stop_monitoring():
    global observer, is_monitoring
    if observer:
        observer.stop()
        observer.join()
        is_monitoring = False
        label3.configure(text="Message : Monitoring Stopped")
        monitor_btn.configure(text="Start Monitoring")
        # Clear the change lists when stopping monitoring
        ClearData()

def generate_pdf_report():
    """Generate a PDF report of file changes"""
    pdf = FPDF()
    pdf.add_page()
    
    # Set font
    pdf.set_font("Arial", "B", 16)
    
    # Title
    pdf.cell(200, 10, "File Integrity Monitor Report", ln=True, align="C")
    pdf.ln(10)
    
    # Date and Time
    pdf.set_font("Arial", "", 12)
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(200, 10, f"Generated on: {current_time}", ln=True)
    pdf.ln(10)
    
    # Changed Files
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "Changed Files:", ln=True)
    pdf.set_font("Arial", "", 12)
    for file in files_changed:
        pdf.cell(200, 10, f"- {file}", ln=True)
    pdf.ln(10)
    
    # Added Files
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "Added Files:", ln=True)
    pdf.set_font("Arial", "", 12)
    for file in files_added:
        pdf.cell(200, 10, f"- {file}", ln=True)
    pdf.ln(10)
    
    # Removed Files
    pdf.set_font("Arial", "B", 14)
    pdf.cell(200, 10, "Removed Files:", ln=True)
    pdf.set_font("Arial", "", 12)
    for file in files_removed:
        pdf.cell(200, 10, f"- {file}", ln=True)
    
    # Save the PDF
    report_path = os.path.join(os.path.dirname(os.path.abspath(_file_)), "report.pdf")
    pdf.output(report_path)
    return report_path

root.mainloop()