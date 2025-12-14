import os

USB_PATH = "/sys/bus/usb/devices"

def get_usb_devices():
    """Scans for connected USB devices."""
    devices = []
    if not os.path.exists(USB_PATH):
        return []

    for device in os.listdir(USB_PATH):
        # We only care about root/hub devices (simplified for stability)
        path = os.path.join(USB_PATH, device)
        if os.path.exists(os.path.join(path, 'product')):
            try:
                with open(os.path.join(path, 'product'), 'r') as f:
                    name = f.read().strip()
                with open(os.path.join(path, 'authorized'), 'r') as f:
                    status = f.read().strip()
                
                devices.append({
                    "id": device,
                    "name": name,
                    "status": "Active" if status == "1" else "Blocked"
                })
            except:
                continue
    return devices

def toggle_usb(device_id, action):
    """Soft blocks (0) or Unblocks (1) a USB device."""
    auth_path = os.path.join(USB_PATH, device_id, 'authorized')
    value = '1' if action == 'unblock' else '0'
    
    try:
        with open(auth_path, 'w') as f:
            f.write(value)
        return True
    except PermissionError:
        return False
