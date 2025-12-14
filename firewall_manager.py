import subprocess

def rule_exists(port, protocol="tcp"):
    """Checks if a block rule already exists to prevent duplicates."""
    try:
        check_cmd = f"iptables -C INPUT -p {protocol} --dport {port} -j DROP"
        # -C checks if the rule exists. Returns 0 if it does, 1 if it doesn't.
        result = subprocess.run(check_cmd.split(), capture_output=True)
        return result.returncode == 0
    except:
        return False

def add_rule(port, protocol="tcp"):
    """Blocks a port, but only if it's not already blocked."""
    if port in [22, 5000]:
        return "Error: Protection enabled for critical ports."
    
    if rule_exists(port, protocol):
        return f"Port {port} is already blocked."

    try:
        cmd = f"iptables -A INPUT -p {protocol} --dport {port} -j DROP"
        subprocess.run(cmd.split(), check=True)
        return f"Successfully blocked {protocol.upper()} port {port}"
    except Exception as e:
        return f"Error: {str(e)}"

def remove_rule(port, protocol="tcp"):
    """Removes the block rule. Uses a loop to ensure ALL duplicates are gone."""
    try:
        # We loop because iptables might have multiple identical rules
        removed = False
        while rule_exists(port, protocol):
            cmd = f"iptables -D INPUT -p {protocol} --dport {port} -j DROP"
            subprocess.run(cmd.split(), check=True)
            removed = True
        
        if removed:
            return f"Successfully unblocked {protocol.upper()} port {port}"
        else:
            return f"Port {port} was not blocked."
    except Exception as e:
        return f"Error: {str(e)}"
