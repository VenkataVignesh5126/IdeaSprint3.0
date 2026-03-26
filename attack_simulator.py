def simulate_attack(port):

    attacks = {
        21: "Attacker can login anonymously using FTP",
        22: "Attacker can try SSH brute-force attack",
        23: "Attacker can sniff credentials (Telnet)",
        80: "Attacker can intercept data (Man-in-the-middle)",
        445: "Attacker can exploit SMB (EternalBlue)",
        3389: "Attacker can brute-force RDP login"
    }

    return attacks.get(port, "No major attack possible")