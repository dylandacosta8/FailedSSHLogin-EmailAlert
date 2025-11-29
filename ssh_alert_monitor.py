#!/usr/bin/env python3
"""
SSH Failed Login Monitor - Real-time monitoring
Monitors /var/log/auth.log for failed SSH login attempts and sends immediate email notifications
"""

import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Configuration
AUTH_LOG = "/var/log/auth.log"
FAILED_LOG = "/var/log/failed_ssh_attempts.log"
MONITOR_LOG = "/var/log/ssh-monitor.log"
EMAIL_TO = "EMAIL_TO"  # Change this to your email
EMAIL_FROM_NAME = "EMAIL_FROM_NAME"  # Sender name that will appear in email
EMAIL_FROM_ADDRESS = "EMAIL_FROM_ADDRESS"  # Sender email address
CHECK_INTERVAL = 1  # Check every 1 second

# Regex pattern for failed SSH attempts (timestamp agnostic)
# Captures everything before hostname as timestamp, works with any timestamp format
FAILED_PATTERN = re.compile(
    r'^(.+?)\s+(\S+)\s+sshd\[\d+\]:\s*Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)'
)


def log_message(message, level="INFO"):
    """Log messages to the monitor log file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] {message}\n"
    try:
        with open(MONITOR_LOG, "a") as f:
            f.write(log_entry)
        # Also print to stdout for systemd journal
        print(log_entry.strip())
    except Exception as e:
        print(f"Error writing to monitor log: {e}", file=sys.stderr)


def log_failed_attempt(attempt):
    """Log failed attempt to dedicated log file"""
    try:
        log_entry = (
            f"Failed SSH Login Attempt: Time: {attempt['timestamp']}, "
            f"User: {attempt['user']}, Hostname: {attempt['hostname']}, "
            f"Attacker IP: {attempt['ip']}, Attacker Port: {attempt['port']}\n"
        )
        with open(FAILED_LOG, "a") as f:
            f.write(log_entry)
    except Exception as e:
        log_message(f"Error writing to failed attempts log: {e}", "ERROR")


def format_timestamp(timestamp_str):
    """Convert timestamp to local timezone in readable format"""
    try:
        # Try parsing ISO 8601 format
        if 'T' in timestamp_str:
            # Parse ISO 8601 with timezone
            dt = datetime.fromisoformat(timestamp_str)
            # Convert to local timezone
            local_dt = dt.astimezone()
            return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")
        else:
            # For other formats, return as-is
            return timestamp_str
    except Exception as e:
        # If parsing fails, return original
        return timestamp_str


def send_email(attempt):
    """Send email notification for a single failed login attempt"""
    subject = "Failed SSH Login Alert"
    
    # Format timestamp for better readability
    formatted_time = format_timestamp(attempt['timestamp'])
    
    body = f"""
🚨 SECURITY ALERT

Failed SSH Login Attempt
─────────────────────────

📅 {formatted_time}

🖥️  SERVER
   {attempt['hostname']}

👤 USERNAME
   {attempt['user']}

🌐 SOURCE IP
   {attempt['ip']}

🔌 PORT
   {attempt['port']}


ℹ️  WHAT HAPPENED?
─────────────────────────

An unauthorized login attempt was 
detected on your server. The 
authentication failed and the 
incident has been logged.


✅ NEXT STEPS
─────────────────────────

• Review the source IP for 
  suspicious activity

• Check if this IP should be 
  blocked

• Monitor for repeated attempts

• View full logs at:
  /var/log/failed_ssh_attempts.log


───────────────────────────────
SSH Alert Monitor v1.0
Securing {attempt['hostname']} 24/7
"""
    
    try:
        # Use mail command with custom From header
        from_header = f"{EMAIL_FROM_NAME} <{EMAIL_FROM_ADDRESS}>"
        cmd = ["mail", "-s", subject, "-a", f"From: {from_header}", EMAIL_TO]
        subprocess.run(cmd, input=body.encode(), check=True, timeout=10)
        log_message(f"Email sent for attempt from {attempt['ip']}")
    except subprocess.TimeoutExpired:
        log_message("Email sending timed out", "ERROR")
    except subprocess.CalledProcessError as e:
        log_message(f"Error sending email: {e}", "ERROR")
    except Exception as e:
        log_message(f"Unexpected error sending email: {e}", "ERROR")


def tail_file(filename):
    """
    Generator that yields new lines from a file as they're written (like tail -f)
    """
    try:
        # Get initial inode
        initial_inode = Path(filename).stat().st_ino
        
        # Start at the end of the file
        with open(filename, 'r') as f:
            # Move to end of file
            f.seek(0, 2)
            log_message(f"Started monitoring {filename} from current position (inode: {initial_inode})")
            
            while True:
                line = f.readline()
                if line:
                    yield line
                else:
                    # No new line, sleep briefly
                    time.sleep(CHECK_INTERVAL)
                    
                    # Check if file was rotated (every 10 seconds to reduce overhead)
                    if int(time.time()) % 10 == 0:
                        try:
                            current_inode = Path(filename).stat().st_ino
                            # If inode changed, file was rotated
                            if current_inode != initial_inode:
                                log_message(f"Log file rotated (old inode: {initial_inode}, new inode: {current_inode}), reopening", "INFO")
                                return
                        except:
                            pass
                        
    except FileNotFoundError:
        log_message(f"Auth log file not found: {filename}", "ERROR")
        raise
    except Exception as e:
        log_message(f"Error reading file: {e}", "ERROR")
        raise


def process_line(line):
    """Process a single log line for failed SSH attempts"""
    match = FAILED_PATTERN.search(line)
    if match:
        timestamp, hostname, user, ip, port = match.groups()
        
        attempt = {
            "timestamp": timestamp,
            "hostname": hostname,
            "user": user,
            "ip": ip,
            "port": port
        }
        
        log_message(f"Detected failed login: user={user}, ip={ip}")
        
        # Log to failed attempts file
        log_failed_attempt(attempt)
        
        # Send immediate email notification
        send_email(attempt)


def main():
    """Main execution function"""
    log_message("SSH monitor script started in real-time mode")
    
    # Check if auth.log exists
    if not Path(AUTH_LOG).exists():
        log_message(f"Auth log not found: {AUTH_LOG}", "CRITICAL")
        sys.exit(1)
    
    log_message("Starting real-time monitoring (processing new entries only)")
    
    while True:
        try:
            # Monitor the file
            for line in tail_file(AUTH_LOG):
                process_line(line)
        except KeyboardInterrupt:
            log_message("Received interrupt signal, shutting down")
            break
        except Exception as e:
            log_message(f"Error in monitoring loop: {e}", "ERROR")
            log_message("Restarting monitoring in 5 seconds...", "INFO")
            time.sleep(5)
    
    log_message("SSH monitor script stopped")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log_message(f"Critical error in main execution: {e}", "CRITICAL")
        sys.exit(1)
