def analyze_risk(port):

    risks = {
        21: ("FTP is insecure (no encryption)", "HIGH"),
        22: ("SSH brute-force attack possible", "MEDIUM"),
        23: ("Telnet sends data in plaintext", "HIGH"),
        80: ("HTTP not secure (no encryption)", "LOW"),
        445: ("SMB vulnerable to exploits", "HIGH"),
        3389: ("RDP brute-force possible", "MEDIUM")
    }

    return risks.get(port, ("No major risk", "LOW"))