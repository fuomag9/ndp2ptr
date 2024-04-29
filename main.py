import subprocess
import re
import ipaddress
from time import sleep

# Constants for DNS settings
DNS_SERVER = "192.168.1.1"
KEY_NAME = "key_name"
KEY_SECRET = "abcdefg=="


def format_ipv6_for_arpa(ipv6):
    """ Convert an IPv6 address to the .arpa format for DNS PTR records. """
    ip = ipaddress.ip_address(ipv6)
    reversed_ip = ip.reverse_pointer
    return reversed_ip


def validate_ipv6(ipv6, nofe80=True):
    """ Validate the IPv6 address format. """
    try:
        addr = ipaddress.IPv6Address(ipv6)
        if str(addr)[0:4] == "fe80" and nofe80:
            return False
        return True
    except ipaddress.AddressValueError:
        return False


def get_neighbors():
    """ Retrieve IPv6 neighbors using `ndp -a`. """
    return subprocess.run(["ndp", "-a"], capture_output=True, text=True).stdout


def get_arp(mac):
    """ Retrieve IPv4 address for a given MAC address using `arp -a`. """
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True).stdout
    pattern = re.compile(r"\(([\d\.]+)\)\s+at\s+" + re.escape(mac), re.IGNORECASE)
    match = pattern.search(result)
    return match.group(1) if match else None


def dig_reverse_lookup(ipv4):
    """ Perform reverse DNS lookup using `dig`. """
    return subprocess.run(["dig", "+short", "-x", ipv4, f"@{DNS_SERVER}"], capture_output=True,
                          text=True).stdout.strip()


def add_ptr_record(ptr_record, ipv6):
    """ Update DNS records using `nsupdate` commands. """
    commands = f"""
server {DNS_SERVER}
key {KEY_NAME} {KEY_SECRET}
update add {ptr_record} 86400 AAAA {ipv6}
send
"""
    process = subprocess.run(["nsupdate"], input=commands, text=True, capture_output=True)
    return process.stdout


def add_ipv6_arpa(ptr_record, ipv6_arpa):
    """ Update DNS records using `nsupdate` commands. """
    commands = f"""
server {DNS_SERVER}
key {KEY_NAME} {KEY_SECRET}
update add {ipv6_arpa} 86400 PTR {ptr_record}
send
"""
    process = subprocess.run(["nsupdate"], input=commands, text=True, capture_output=True)
    return process.stdout


def clear_ptr_record(ptr_record):
    """ Update DNS records using `nsupdate` commands. """
    commands = f"""
server {DNS_SERVER}
key {KEY_NAME} {KEY_SECRET}
update delete {ptr_record} AAAA
send
"""
    process = subprocess.run(["nsupdate"], input=commands, text=True, capture_output=True)
    return process.stdout


def clear_ipv6_arpa(ipv6_arpa):
    """ Update DNS records using `nsupdate` commands. """
    commands = f"""
server {DNS_SERVER}
key {KEY_NAME} {KEY_SECRET}
update delete {ipv6_arpa} PTR
send
"""
    process = subprocess.run(["nsupdate"], input=commands, text=True, capture_output=True)
    return process.stdout


class MagicMac:
    def __init__(self, mac):
        self.mac = mac
        self.ipv6s = []
        self.reset = False

    def __str__(self):
        return self.mac


# Main execution starts here
if __name__ == "__main__":
    while True:
        neighbors = get_neighbors()
        mac_ipv6_map = {}

        for line in neighbors.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            maccy = MagicMac(parts[1])
            mac, ipv6 = parts[1], parts[0]
            ipv6 = ipv6.split('%')[0]  # Remove interface index

            if validate_ipv6(ipv6):
                if mac in mac_ipv6_map:
                    mac_ipv6_map[mac].ipv6s.append(ipv6)
                else:
                    mac_ipv6_map[mac] = maccy
                    mac_ipv6_map[mac].ipv6s = [ipv6]
            else:
                print(f"IPv6: {ipv6}, MAC: {mac} (invalid or incomplete), Skipping entry")
            try:
                if not mac_ipv6_map[mac].ipv6s:
                    del mac_ipv6_map[mac]
            except KeyError:
                pass

        for maccy in mac_ipv6_map.values():
            ipv4 = get_arp(maccy.mac)
            if ipv4:
                ptr_record = dig_reverse_lookup(ipv4)
                if ptr_record:
                    for ipv6 in maccy.ipv6s:
                        ipv6_arpa = format_ipv6_for_arpa(ipv6)
                        if not maccy.reset:
                            clear_ptr_record(ptr_record)
                            clear_ipv6_arpa(ipv6_arpa)
                            maccy.reset = True
                        add_ptr_record(ptr_record, ipv6)
                        add_ipv6_arpa(ptr_record, ipv6_arpa)
                else:
                    print(f"IPv4: {ipv4}, PTR: Not found (Skipped)")
            else:
                print(f"MAC: {maccy.mac}, IPv4: Not found (Skipped)")
        sleep(60)
