import subprocess
import smtplib
import time
import psutil
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import tkinter as tk
from tkinter import messagebox, ttk
import threading
import os
import re
import sys
from PIL import Image, ImageTk

# Email credentials
sender_email = "redlegend606@gmail.com"
sender_password = "ikpe hnpm tblt cwji"
receiver_email = "anonymous.man14@proton.me"

# Function to auto-detect the victim's MAC address
def get_victim_mac_address():
    try:
        output = subprocess.check_output(['getmac', '/v'], shell=True)
        output = output.decode('utf-8')

        pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
        match = re.search(pattern, output)

        if match:
            mac_address = match.group(0).replace('-', ':')
            print(f"Victim's MAC Address: {mac_address}")
            return mac_address
        else:
            print("MAC Address not found")
            return None
    except Exception as e:
        print(f"Error detecting MAC Address: {e}")
        return None

# Function to prompt user for the default gateway
def get_default_gateway():
    def show_how_to_find_gateway():
        messagebox.showinfo(
            "How to Find Default Gateway",
            "To find your default gateway, follow these steps:\n\n"
            "1. Open Command Prompt (cmd) on your Windows computer.\n"
            "2. Type the following command and press Enter:\n"
            "   ipconfig | findstr /i \"Default Gateway\"\n"
            "3. Look for the Default Gateway entry in the output. This is your gateway address."
        )

    def on_submit():
        gateway[0] = gateway_entry.get()
        root.quit()
        root.destroy()

    def on_cancel():
        gateway[0] = None
        root.quit()
        root.destroy()

    root = tk.Tk()
    root.title("Enter Default Gateway")
    root.geometry("350x200")

    style = ttk.Style()
    style.configure("TButton", padding=6, relief="flat")
    style.configure("TLabel", font=("Helvetica", 10))

    ttk.Label(root, text="Enter the IPv4 DNS server address (default gateway):").pack(pady=10)
    gateway_entry = ttk.Entry(root, width=40)
    gateway_entry.pack(pady=5)

    ttk.Button(root, text="How to Find Default Gateway", command=show_how_to_find_gateway).pack(pady=10)

    gateway = [None]

    button_frame = ttk.Frame(root)
    button_frame.pack(pady=20)

    ttk.Button(button_frame, text="Submit", command=on_submit).pack(side=tk.LEFT, padx=10)
    ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=10)

    root.mainloop()

    return gateway[0]

# Function to send email
def send_email(attacker_mac, dump_path):
    subject = "MITM Attack Detected"
    body = f"Someone is trying to steal/hack your data. Attacker's MAC address is {attacker_mac}"

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        with open(dump_path, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename= dump.pcap")
        msg.attach(part)

        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("Email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

    # Run command to forcefully terminate tshark process
    try:
        subprocess.run(["taskkill", "/im", "tshark.exe", "/F"], check=True)
        print("tshark process terminated successfully.")
    except Exception as e:
        print(f"Failed to terminate tshark process: {e}")

    # Run del.bat file
    try:
        subprocess.run(["del.bat"], check=True)
        print("del.bat executed successfully.")
    except Exception as e:
        print(f"Failed to execute del.bat: {e}")

# Function to show popup
def show_popup(attacker_mac):
    def disconnect_me():
        os.system("netsh wlan disconnect")
        terminate_process()
        root.destroy()
        sys.exit()  # Exit the script

    def terminate_process():
        try:
            subprocess.run(["taskkill", "/im", "tshark.exe", "/F"], check=True)
            print("tshark process terminated successfully.")
        except Exception as e:
            print(f"Failed to terminate tshark process: {e}")

        root.destroy()
        sys.exit()  # Exit the script

    root = tk.Tk()
    root.withdraw()

    popup = tk.Toplevel(root)
    popup.title("MITM Attack Detected")
    popup.geometry("400x400")
    popup.configure(bg="#f0f0f0")
    popup.attributes("-topmost", True)

    # Load the image
    image = Image.open("alert.png")
    image = image.resize((200, 200), Image.LANCZOS)
    photo = ImageTk.PhotoImage(image)

    # Add image to the popup
    image_label = tk.Label(popup, image=photo, bg="#f0f0f0")
    image_label.pack(pady=10)

    # Add alert message
    alert_message = f"MITM/ARP poisoning attack has started against you from {attacker_mac}!"
    message_label = ttk.Label(popup, text=alert_message, wraplength=350, background="#f0f0f0", font=("Helvetica", 12))
    message_label.pack(pady=20)

    button_frame = ttk.Frame(popup)
    button_frame.pack(pady=20)

    ttk.Button(button_frame, text="Close", command=terminate_process).pack(side=tk.LEFT, padx=10)
    ttk.Button(button_frame, text="Disconnect me", command=disconnect_me).pack(side=tk.RIGHT, padx=10)

    root.mainloop()

# Function to block the attacker
def block_attacker(attacker_mac):
    try:
        subprocess.run(["netsh", "wlan", "add", "filter", "permission=deny", "networktype=infrastructure", f"mac={attacker_mac}"], check=True)
        print(f"Attacker {attacker_mac} blocked successfully.")
    except Exception as e:
        print(f"Failed to block attacker: {e}")

# Function to play sound
def play_sound():
    for _ in range(3):
        subprocess.run(["powershell", "-c", "(New-Object Media.SoundPlayer 'alert.wav').PlaySync()"], shell=True)

# Function to analyze packets
def analyze_packets(process):
    command_analyze = [
        "tshark",
        "-r", "dump.pcap"
    ]

    try:
        while True:
            result = subprocess.run(command_analyze, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout
            if "is at" in output:
                lines = output.splitlines()
                for line in lines:
                    if "is at" in line:
                        parts = line.split()
                        attacker_mac = parts[-1]
                        print(f"Attacker MAC address: {attacker_mac}")
                        # Play sound in a separate thread
                        threading.Thread(target=play_sound).start()
                        # Show popup
                        threading.Thread(target=show_popup, args=(attacker_mac,)).start()
                        time.sleep(5)  # Wait for 5 seconds before sending the email
                        send_email(attacker_mac, "dump.pcap")
                        # Terminate the tshark process
                        process.terminate()
                        process.wait()  # Wait for the process to terminate
                        return
    except Exception as e:
        print(f"Error analyzing packets: {e}")

# Function to delete dump.pcap
def delete_dump_pcap():
    try:
        os.remove("dump.pcap")
        print("dump.pcap file deleted.")
    except FileNotFoundError:
        print("No dump.pcap file found.")
    except Exception as e:
        print(f"Failed to delete dump.pcap file: {e}")

# Function to detect MITM
def detect_mitm():
    delete_dump_pcap()  # Delete existing dump.pcap before starting

    default_gateway = get_default_gateway()
    if not default_gateway:
        print("Could not determine the default gateway.")
        return

    victim_mac = get_victim_mac_address()  # Auto-detect the victim's MAC address

    if not victim_mac:
        print("Could not determine the victim's MAC address.")
        return

    print("Default gateway entered:", default_gateway)
    print("Victim's MAC address:", victim_mac)
    
    command_capture = [
        "tshark",
        "-i", "Wi-Fi",
        "-f", f"arp and src host {default_gateway} and arp[6:2] == 2 and not ether src {victim_mac}",
        "-w", "dump.pcap"
    ]

    print("Starting packet capture...")
    process = subprocess.Popen(command_capture, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    analyze_thread = threading.Thread(target=analyze_packets, args=(process,))
    analyze_thread.start()

    try:
        analyze_thread.join()  # Ensure the analyze thread has finished
        time.sleep(1)  # Give some time for file handles to be released
    except Exception as e:
        print(f"Error running tshark: {e}")

if __name__ == "__main__":
    detect_mitm()
