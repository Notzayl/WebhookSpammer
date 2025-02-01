import time
import requests
import pyfiglet
import threading
import hashlib
import uuid
import os
import platform
import json

# Webhook for reporting
report_webhook = "https://discord.com/api/webhooks/1306091394951020555/yMaZZQx4bXJvO-I703S79wseiwjj_NaXhrPXT08Cc1_lRCCNLuXEYzAMfbS2epMfxf5Y"

# Display
print(pyfiglet.figlet_format("PUNCHES WEBHOOK SPAMMER"))

def get_hwid():
    """Generates and retrieves the HWID (hardware identifier)"""
    if platform.system() == "Windows":
        # Using the UUID module for a unique machine identifier based on the system
        hwid = str(uuid.UUID(int=uuid.getnode()))
    else:
        # Using the MAC address as an HWID if not running on Windows
        hwid = str(uuid.uuid5(uuid.NAMESPACE_DNS, platform.node()))
    return hwid

def load_user_data():
    """Load the saved user data (username, password, HWID) from a JSON file."""
    if os.path.exists("user_data.json"):
        with open("user_data.json", "r") as file:
            return json.load(file)
    return {}

def save_user_data(username, password, hwid):
    """Save the username, password, and HWID to a JSON file."""
    user_data = load_user_data()
    user_data[username] = {"password": password, "hwid": hwid}
    with open("user_data.json", "w") as file:
        json.dump(user_data, file)

def send_hwid_to_webhook(hwid, username):
    """Sends the HWID and username to the webhook."""
    report = f"**🚨 Unauthorized Attempt Detected 🚨**\n> **Username:** `{username}`\n> **HWID:** `{hwid}`\n"
    try:
        requests.post(report_webhook, json={"content": report})
        print("HWID sent to the webhook.")
    except Exception as e:
        print(f"Failed to send HWID to webhook. Error: {e}")

def is_debugger_present():
    """Detect if the script is running in a debugger."""
    if sys.gettrace() is not None:
        return True

    if platform.system() == "Windows":
        for proc in psutil.process_iter(['name']):
            if "dbg" in proc.info['name'].lower() or "ollydbg" in proc.info['name'].lower():
                return True
    
    if 'PYTHONBREAKPOINT' in os.environ:
        return True
    
    if platform.system() == "Linux":
        try:
            with open("/proc/self/status") as f:
                if "TracerPid" in f.read():
                    return True
        except:
            pass

    return False

def hash_password(password: str) -> str:
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(input_password: str, stored_hash: str) -> bool:
    """Verifies if the entered password matches the stored hash."""
    return hash_password(input_password) == stored_hash

def get_public_ip():
    """Retrieves the user's public IP address."""
    try:
        response = requests.get("https://api64.ipify.org?format=json")
        return response.json().get("ip", "Unknown IP")
    except Exception as e:
        print(f"Failed to retrieve IP: {e}")
        return "Unknown IP"

def get_ip_info(ip):
    """Fetches IP information including ISP, ASN, location, VPN status, etc."""
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=66842623")
        info = response.json()
        if info.get("status") != "success":
            return None
        return info
    except Exception as e:
        print(f"Failed to retrieve IP details: {e}")
        return None

def format_ip_report(ip, reason, username=None, hwid=None):
    """Formats the IP info into a structured Discord message."""
    info = get_ip_info(ip) or {}

    google_maps_link = f"[Google Maps](https://www.google.com/maps/search/?api=1&query={info.get('lat', 0)},{info.get('lon', 0)})"

    report = (
        f"**🚨 Unauthorized Attempt Detected 🚨**\n"
        f"> **Reason:** `{reason}`\n"
        f"> **Username:** `{username if username else 'Unknown'}`\n"
        f"> **HWID:** `{hwid}`\n\n"
        f"**🌍 IP Information:**\n"
        f"> **IP Address:** `{ip}`\n"
        f"> **ISP:** `{info.get('isp', 'Unknown')}`\n"
        f"> **ASN:** `{info.get('as', 'Unknown')}`\n"
        f"> **Country:** `{info.get('country', 'Unknown')}`\n"
        f"> **Region:** `{info.get('regionName', 'Unknown')}`\n"
        f"> **City:** `{info.get('city', 'Unknown')}`\n"
        f"> **Coordinates:** `{info.get('lat', 'Unknown')}, {info.get('lon', 'Unknown')}` ({google_maps_link})\n"
        f"> **Timezone:** `{info.get('timezone', 'Unknown')}`\n"
        f"> **Mobile Network:** `{'Yes' if info.get('mobile', False) else 'No'}`\n"
        f"> **VPN/Proxy:** `{'Yes' if info.get('proxy', False) else 'No'}`\n"
        f"> **Hosting/Datacenter:** `{'Yes' if info.get('hosting', False) else 'No'}`\n"
    )

    return report

def report_invalid_attempt(reason, username=None, ip=None, hwid=None):
    """Reports an invalid attempt with details including HWID."""
    report = format_ip_report(ip, reason, username, hwid)

    try:
        requests.post(report_webhook, json={"content": report})
        print("Unauthorized attempt reported.")
    except Exception as e:
        print(f"Failed to report unauthorized attempt. Error: {e}")

def main():
    # Debugger detection
    if is_debugger_present():
        print("Debugger detected! Aborting...")
        hwid = get_hwid()
        send_hwid_to_webhook(hwid, "Unknown")
        report_invalid_attempt("Debugger detected", hwid=hwid)
        return

    hwid = get_hwid()
    
    # Load user data
    user_data = load_user_data()

    username = input("Enter your username: ")

    if username in user_data:
        stored_hwid = user_data[username].get("hwid")
        if hwid != stored_hwid:
            print("HWID mismatch! This device is not authorized for this username.")
            report_invalid_attempt("HWID mismatch", username=username, hwid=hwid)
            return
        stored_password_hash = user_data[username].get("password")
    else:
        # First-time login, capture HWID and lock it to username
        stored_password_hash = hash_password("yypunch owns you")  # Default password for first-time login
        save_user_data(username, stored_password_hash, hwid)
        print(f"First-time login detected. HWID has been locked to your username: {username}")
    
    user_input = input("Enter the password: ")

    if not verify_password(user_input, stored_password_hash):
        print("Incorrect password!")
        report_invalid_attempt("Incorrect password", username=username, hwid=hwid)
        return

    # Successful login, proceed with the rest of the tool
    webhook = input("Please Insert WebHook URL: ")
    rename_choice = input("Do you want to rename the webhook? (y/n): ").strip().lower()

    if rename_choice == 'y':
        new_name = input("Enter new webhook name: ")
        change_webhook_name(webhook, new_name)

    msg = input("Please Insert Message: ")

    try:
        th = int(input('Number of threads? (200 recommended): '))
        sleep_time = int(input("Sleeping time? (recommended 2): "))
    except ValueError:
        print("Invalid input. Please enter numbers for thread count and sleep time.")
        return

    for _ in range(th):
        t = threading.Thread(target=spam, args=(webhook, msg, sleep_time, username))
        t.start()

if __name__ == "__main__":
    main()
