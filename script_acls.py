import re
import csv
import ipaddress

def wildcard_to_cidr(wildcard):
    binary_wildcard = ''.join([f"{int(octet):08b}" for octet in wildcard.split('.')])
    cidr_prefix = 32 - binary_wildcard.count('1')
    return cidr_prefix

def parse_acl(acl_string):
    acl_regex = r"(\d+)\s+(permit|deny)\s+(\w+)\s+([\d.]+)\s+([\d.]+)(?:\s+eq\s+(\d+))?\s+([\d.]+)\s+([\d.]+)(?:\s+eq\s+(\d+))?"
    acl_string = acl_string.strip()
    match = re.match(acl_regex, acl_string)
    
    if match:
        acl_id = match.group(1)
        action = match.group(2).capitalize()
        protocol = match.group(3).upper()
        src_ip = match.group(4)
        src_wildcard = match.group(5)
        src_port = match.group(6) if match.group(6) else "//"
        dst_ip = match.group(7)
        dst_wildcard = match.group(8)
        dst_port = match.group(9) if match.group(9) else "//"

        src_cidr = f"{src_ip}/{wildcard_to_cidr(src_wildcard)}"
        dst_cidr = f"{dst_ip}/{wildcard_to_cidr(dst_wildcard)}"
        
        src_range = get_ip_range(src_cidr)
        dst_range = get_ip_range(dst_cidr)

        return [acl_id, action, protocol, src_cidr, src_range, src_port, dst_cidr, dst_range, dst_port]
    else:
        print("Format ACL invalide:", acl_string)
        return None

def get_ip_range(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return f"{network.network_address} - {network.broadcast_address}"
    except ValueError as e:
        return str(e)

acl_table = []

with open("ACL_100.txt", "r") as file:
    acl_entries = file.read().strip().splitlines()

for acl_entry in acl_entries:
    parsed_acl = parse_acl(acl_entry)
    if parsed_acl:
        acl_table.append(parsed_acl)

csv_filename = "acls_export.csv"
header = ["ACL ID", "Permit/Deny", "Protocole", "IP Source (CIDR)", "Plage IP Source", "Port Source", "IP Destination (CIDR)", "Plage IP Destination", "Port Destination"]

with open(csv_filename, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(acl_table)

print(f"Tableau ACL exporté dans le fichier '{csv_filename}'.")
