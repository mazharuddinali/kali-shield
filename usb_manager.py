import os
import subprocess

UDEV_RULE_PATH = "/etc/udev/rules.d/99-kali-shield.rules"

def set_global_lockdown(enable):
    """Writes or removes the udev rule to block USBs proactively."""
    try:
        if enable:
            # Create the rule that blocks on arrival
            rule = 'ACTION=="add", SUBSYSTEM=="usb", ATTR{authorized}="0"'
            with open(UDEV_RULE_PATH, "w") as f:
                f.write(rule)
        else:
            # Remove the rule to allow default behavior
            if os.path.exists(UDEV_RULE_PATH):
                os.remove(UDEV_RULE_PATH)
        
        # Tell the kernel to reload the rules immediately
        subprocess.run(["udevadm", "control", "--reload-rules"], check=True)
        subprocess.run(["udevadm", "trigger"], check=True)
        return True
    except Exception as e:
        print(f"Error updating policy: {e}")
        return False
