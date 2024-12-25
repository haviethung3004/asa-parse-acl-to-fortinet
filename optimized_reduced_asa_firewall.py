import csv
import os
from collections import defaultdict


def parse_csv(file_path):
    rules = []
    with open(file_path, mode='r', encoding='utf-8-sig') as file:
        reader = csv.DictReader(file)
        for row in reader:
            rules.append({
                "source": row["source"],
                "destination": row["destination"],
                "ports": row["ports"]
            })
    return rules

def convert_to_prefix_length(mask):
    try:
        # Split the mask into octets and convert each to an integer
        mask_octets = mask.split('.')
        
        # Convert the octets to their binary representation
        binary_str = ''.join(format(int(octet), '08b') for octet in mask_octets)
        
        # Count the number of '1' bits to determine the prefix length
        prefix_length = binary_str.count('1')
        
        return prefix_length
    except Exception as e:
        print(f"Error converting mask to prefix length: {mask}. Error: {e}")
        return mask

def parse_access_list(file_path):
    rules = []
    with open(file_path, 'r') as file:
        for line in file:
            if "permit" in line:
                parts = line.split()
                if len(parts) < 7:  # Skip lines with too few tokens
                    continue

                protocol = parts[4]

                # Dynamically parse the source
                source_index = 6
                if parts[source_index - 1] == "object":
                    source = parts[source_index]
                    source_mask = None
                    source_index += 1
                elif parts[source_index - 1] == "object-group":
                    source = parts[source_index]
                    source_mask = None
                    source_index += 1
                elif parts[source_index - 1] == "host":
                    source = parts[source_index]
                    source_mask = None
                    source_index += 1
                elif parts[source_index - 1] == "any" or parts[source_index - 1] == "any4":
                    # source = parts[source_index]
                    source = "all"
                    source_mask = None
                    # source_index += 1
                else:
                    source = parts[source_index - 1]
                    source_mask = parts[source_index]
                    source_index += 1
                # Convert source mask to prefix length
                    if source_mask:
                        source_mask = convert_to_prefix_length(source_mask)
                        source = f"{source}"
                        # e
                # Dynamically parse the destination
                dest_index = source_index
                if dest_index >= len(parts):  # Ensure dest_index is valid
                    continue
                if parts[dest_index] == "object":
                    destination = parts[dest_index + 1]
                    destination_mask = None
                elif parts[dest_index] == "object-group":
                    destination = parts[dest_index + 1]
                    destination_mask = None
                elif parts[dest_index] == "host":
                    destination = parts[dest_index + 1]
                    destination_mask = None
                elif parts[dest_index] == "any" or parts[dest_index] == "any4":
                    destination = "all"
                    destination_mask = None
                else:
                    if dest_index + 1 >= len(parts):  # Ensure destination_mask index is valid
                        continue
                    destination = parts[dest_index]
                    destination_mask = parts[dest_index + 1]
                    dest_index += 1
                    # Convert destination mask to prefix length
                    if destination_mask:
                        destination_mask = convert_to_prefix_length(destination_mask)
                        destination = f"{destination}/{destination_mask}"

                # Dynamically parse the port
                if protocol == "ip":
                    port = "ANY"        
                elif protocol == "icmp":
                    port = "ICMP"
                elif parts[-3] == "range":
                    port = f"{protocol}_{parts[-2]}-{parts[-1]}"
                elif protocol == "tcp" and len(parts) < 10:
                    port = "TCP"
                elif protocol == "udp" and len(parts) < 10:
                    port = "UDP"
                elif parts[-2] == "object-group":
                    port = f"{parts[-1]}"
                elif "object-group" not in parts[-2:]:
                  if parts[-1].isdigit():
                      port = f"{protocol}_{parts[-1]}"
                  else:
                      port = parts[-1].upper()

                rules.append({
                    "protocol": protocol,
                    "source": source if not source_mask else f"{source}/{source_mask}",
                    "destination": destination,
                    "port": port
                })
    return rules

def merge_rules(rules):
    # Grouped by source and destination
    source_dest_group = defaultdict(lambda: defaultdict(set))
    # Grouped by source and port
    source_port_group = defaultdict(lambda: defaultdict(set))
    # Grouped by destination and port
    dest_port_group = defaultdict(lambda: defaultdict(set))


    for rule in rules:
        protocol = rule['protocol']
        source = rule['source']
        destination = rule['destination']
        port = rule['port']

        # Group by source and destination
        source_dest_group[source][destination].add(port)
        # Group by source and port
        source_port_group[source][port].add(destination)
        # # Group by destination and port
        dest_port_group[destination][port].add(source)

    merged_rules = []
    # Create merged rules from source-destination group
    for source, dests in source_dest_group.items():
        for dest, ports in dests.items():
            merged_rules.append({
                "source": source,
                "destination": dest,
                "ports": ','.join(sorted(ports))
            })

    # Create merged rules from source-port group
    for source, ports in source_port_group.items():
        for port, dests in ports.items():
            merged_rules.append({
                "source": source,
                "destination": ','.join(sorted(dests)),
                "ports": port
            })

    # Create merged rules from destination-port group
    for destination, ports in dest_port_group.items():
        for port, sources in ports.items():
            merged_rules.append({
                "source": ','.join(sorted(sources)),
                "destination": destination,
                "ports": port
            })

    return merged_rules

def read_csv(file_path):
    rules = []
    with open(file_path, mode='r', encoding='utf-8-sig') as file:
        reader = csv.DictReader(file)
        for row in reader:
            rules.append(row)
    return rules

def remove_duplicate_rules(rules):
    unique_rules = []
    seen_source_port = set()
    seen_source_dest = set()
    seen_dest_port = set()

    for rule in rules:
        source = rule['source']
        destination = rule['destination']
        ports = rule['ports']

        source_port_key = (source, ports)
        source_dest_key = (source, destination)
        dest_port_key = (destination, ports)

        if source_port_key in seen_source_port or source_dest_key in seen_source_dest or dest_port_key in seen_dest_port:
            continue

        seen_source_port.add(source_port_key)
        seen_source_dest.add(source_dest_key)
        seen_dest_port.add(dest_port_key)
        unique_rules.append(rule)

    return unique_rules


def write_csv(rules, file_path):
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["source", "destination", "ports"])
        writer.writeheader()
        for rule in rules:
            writer.writerow(rule)

def write_fortinet_conf(rules, output_file, start_edit=9211):
    with open(output_file, mode='w') as file:
        edit_number = start_edit
        for rule in rules:
            file.write(f"edit {edit_number}\n")
            file.write(f"    set name merged-{edit_number}\n")
            file.write(f"    set srcintf \"any\"\n")
            file.write(f"    set dstintf \"any\"\n")
            file.write(f"    set action accept\n")
            
            # Handle multiple sources
            sources = rule['source'].split(',')
            srcaddr = ' '.join([f'"{src.strip()}"' for src in sources])
            file.write(f"    set srcaddr {srcaddr}\n")
            
            # Handle multiple destinations
            destinations = rule['destination'].split(',')
            dstaddr = ' '.join([f'"{dst.strip()}"' for dst in destinations])
            file.write(f"    set dstaddr {dstaddr}\n")
            
            file.write(f"    set schedule always\n")
            
            # Handle multiple ports
            ports = rule['ports'].split(',')
            services = ' '.join([f'"{port.strip()}"' for port in ports])
            file.write(f"    set service {services}\n")

            #comment
            file.write(f"    set comments \"{sources[0].strip()}_{destinations[0].strip()}\"\n")

            file.write(f"next\n")
            edit_number += 1
        file.write("end\n")


if __name__ == "__main__":
    # Configuration file for file paths

    # Input file path
    INPUT_FILE = input("Enter the path to the cleaned CSV firewall policy file: ")

    # Extract directory and base name of the input file
    input_dir = os.path.dirname(INPUT_FILE)  # Get the directory of the input file
    base_name = os.path.splitext(os.path.basename(INPUT_FILE))[0]  # Extract base name of the input file

    # Generate dynamic output paths in the same directory
    OUTPUT_FILE = os.path.join(input_dir, f"{base_name}_cleaned_firewall_policy.csv")
    FORTINET_OUTPUT_FILE = os.path.join(input_dir, f"{base_name}_acls.conf")

    # Parse and merge rules
    rules = parse_access_list(INPUT_FILE)
    merged_rules = merge_rules(rules)

    # Remove duplicate rules
    unique_rules = remove_duplicate_rules(merged_rules)

    # Write final rules to CSV
    write_csv(unique_rules, OUTPUT_FILE)

    # Write final rules to Fortinet configuration
    write_fortinet_conf(unique_rules, FORTINET_OUTPUT_FILE)
    
    print(f"Successfully wrote cleaned firewall policy to {OUTPUT_FILE}")
    print(f"Successfully wrote Fortinet configuration to {FORTINET_OUTPUT_FILE}")