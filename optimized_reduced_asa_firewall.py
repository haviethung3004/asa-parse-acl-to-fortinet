import csv
import os
import pandas as pd
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
                else:
                    print(f"Error parsing port: {line}")

                rules.append({
                    "source": source if not source_mask else f"{source}/{source_mask}",
                    "destination": destination,
                    "ports": port
                })
    return rules


def merge_and_remove_duplicate_rule(rules):
    """
    Remove duplicate rules by merging based on specified criteria.
    :param rules: DataFrame containing columns ['source', 'destination', 'ports']
    :return: DataFrame with cleaned and merged rules
    """
    # Step 1: Merge rules with the same source and destination
    merged_source_dest = (
        rules.groupby(['source', 'destination'], as_index=False)
        .agg({'ports': lambda x: ', '.join(sorted(set(x)))})
    )

    # Step 2: Remove the original rules that were merged (by source and destination)
    merged_source_dest_keys = set(zip(merged_source_dest['source'], merged_source_dest['destination']))
    remaining_data = rules[
        ~rules.apply(lambda row: (row['source'], row['destination']) in merged_source_dest_keys, axis=1)
    ]

    # Combine merged source-destination rules with remaining data
    final_cleaned_data = pd.concat([merged_source_dest, remaining_data]).drop_duplicates()

    # Step 3: Merge rules with the same source and ports
    merged_source_ports = (
        final_cleaned_data.groupby(['source', 'ports'], as_index=False)
        .agg({'destination': lambda x: ', '.join(sorted(set(x)))})
    )

    # Remove original rules merged by source and ports
    merged_source_ports_keys = set(zip(merged_source_ports['source'], merged_source_ports['ports']))
    remaining_data_after_source_ports_merge = final_cleaned_data[
        ~final_cleaned_data.apply(
            lambda row: (row['source'], row['ports']) in merged_source_ports_keys, axis=1
        )
    ]

    # Combine merged source-port rules with remaining data
    final_source_ports_cleaned_data = pd.concat(
        [merged_source_ports, remaining_data_after_source_ports_merge]
    ).drop_duplicates()

    # Step 4: Merge rules with the same destination and ports
    merged_dest_ports = (
        final_source_ports_cleaned_data.groupby(['destination', 'ports'], as_index=False)
        .agg({'source': lambda x: ', '.join(sorted(set(x)))})
    )

    # Remove original rules merged by destination and ports
    merged_dest_ports_keys = set(zip(merged_dest_ports['destination'], merged_dest_ports['ports']))
    remaining_data_after_dest_ports_merge = final_source_ports_cleaned_data[
        ~final_source_ports_cleaned_data.apply(
            lambda row: (row['destination'], row['ports']) in merged_dest_ports_keys, axis=1
        )
    ]

    # Combine merged destination-port rules with remaining data
    final_dest_ports_cleaned_data = pd.concat(
        [merged_dest_ports, remaining_data_after_dest_ports_merge]
    ).drop_duplicates()

    # Reformat the final data to source, destination, and ports structure
    # final_dest_ports_csv_format_data = final_dest_ports_cleaned_data.explode('source')
    # write_csv('final_dest_ports_csv_format_data.csv', final_dest_ports_csv_format_data)
    final_output_data = final_dest_ports_cleaned_data[['source', 'destination', 'ports']].drop_duplicates()

    return final_output_data

def read_csv(file_path):
    rules = []
    with open(file_path, mode='r', encoding='utf-8-sig') as file:
        reader = csv.DictReader(file)
        for row in reader:
            rules.append(row)
    return rules


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
    input_file = "EPG_704_access-list.txt"
    intermediate_file = "EPG_704_accesslist_original_rules.csv"
    output_file = "Final_Merged_Rules.csv"

    # Parse access list
    rules = parse_access_list(input_file)

    # Save intermediate rules
    with open(intermediate_file, 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=rules[0].keys())
        writer.writeheader()
        writer.writerows(rules)

    # Remove duplicates
    rules_df = pd.read_csv(intermediate_file)
    cleaned_rules = merge_and_remove_duplicate_rule(rules_df)
    print(cleaned_rules.to_dict('records'))
    write_fortinet_conf(cleaned_rules.to_dict('records'), "fortinet_conf.txt")

    # Save final rules
    cleaned_rules.to_csv(output_file, index=False)
    print(f"Final cleaned rules saved to {output_file}")
