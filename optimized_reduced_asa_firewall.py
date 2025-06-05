import csv
import pandas as pd
from typing import List, Dict, Any, Union, Optional, Set, Tuple, Sequence


def parse_csv(file_path: str) -> List[Dict[str, str]]:
    """
    Parse a CSV file containing firewall rules.
    
    Args:
        file_path: Path to the CSV file
        
    Returns:
        List of dictionaries containing the rules
    """
    rules = []
    try:
        with open(file_path, mode='r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            for row in reader:
                rules.append({
                    "source": row["source"],
                    "destination": row["destination"],
                    "ports": row["ports"]
                })
    except FileNotFoundError:
        print(f"File '{file_path}' not found. Please check the file name and try again.")
    except Exception as e:
        print(f"Error reading CSV file '{file_path}': {e}")
    
    return rules

def convert_to_prefix_length(mask: str) -> Union[int, str]:
    """
    Convert a subnet mask to CIDR prefix length.
    
    Args:
        mask: Subnet mask in dotted decimal notation (e.g. "255.255.255.0")
        
    Returns:
        CIDR prefix length as an integer, or the original mask if conversion fails
    """
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

def parse_access_list(file_path: str, action_type: str = "permit") -> List[Dict[str, str]]:
    """
    Parse an access list file for rules matching the specified action_type.
    
    Args:
        file_path: Path to the access list file
        action_type: Type of action to filter for (default: "permit")
        
    Returns:
        List of dictionaries containing the parsed rules
    """
    rules = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if action_type in line:
                    # Parse the rule
                    rule = parse_access_list_line(line)
                    if rule:
                        rules.append(rule)
    except FileNotFoundError:
        print(f"File '{file_path}' not found. Please check the file name and try again.")
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}")
    
    return rules

def parse_access_list_line(line: str) -> Optional[Dict[str, str]]:
    """
    Parse a single line from an access list.
    
    Args:
        line: A line from an access list file
        
    Returns:
        Dictionary containing the parsed rule, or None if parsing fails
    """
    parts = line.split()
    if len(parts) < 7:  # Skip lines with too few tokens
        return None

    protocol = parts[4]

    # Dynamically parse the source
    source_index = 6
    source, source_mask, source_index = parse_address(parts, source_index - 1)

    # Dynamically parse the destination
    dest_index = source_index
    if dest_index >= len(parts):  # Ensure dest_index is valid
        return None
    
    destination, destination_mask, _ = parse_address(parts, dest_index)

    # Parse the port information
    port = parse_port_info(parts, protocol)

    # Build the rule dictionary
    return {
        "source": source if not source_mask else f"{source}/{source_mask}",
        "destination": destination,
        "ports": port
    }

def parse_address(parts: List[str], index: int) -> Tuple[str, Optional[Union[int, str]], int]:
    """
    Parse an address specification from the parts of an access list line.
    
    Args:
        parts: Split line parts
        index: Index to start parsing from
        
    Returns:
        Tuple of (address, mask, next_index)
    """
    if parts[index] == "object":
        return parts[index + 1], None, index + 2
    elif parts[index] == "object-group":
        return parts[index + 1], None, index + 2
    elif parts[index] == "host":
        return parts[index + 1] + "/32", None, index + 2
    elif parts[index] == "any" or parts[index] == "any4":
        return "all", None, index + 1
    else:
        if index + 1 >= len(parts):  # Ensure mask index is valid
            return parts[index], None, index + 1
        
        addr = parts[index]
        mask = parts[index + 1]
        
        # Convert mask to prefix length if possible
        if mask and '.' in mask:
            mask = convert_to_prefix_length(mask)
        
        return addr, mask, index + 2

def parse_port_info(parts: List[str], protocol: str) -> str:
    """
    Parse port information from the parts of an access list line.
    
    Args:
        parts: Split line parts
        protocol: Protocol (e.g. "tcp", "udp")
        
    Returns:
        Port specification as a string
    """
    if protocol == "ip":
        return "all"        
    elif protocol == "icmp":
        return "ICMP"
    elif parts[-3] == "range":
        return f"{protocol}_{parts[-2]}-{parts[-1]}"
    elif protocol == "tcp" and len(parts) < 10:
        return "TCP"
    elif protocol == "udp" and len(parts) < 10:
        return "UDP"
    elif parts[-2] == "object-group":
        return f"{parts[-1]}"
    elif parts[-1] == "disable" and parts[-5] == "range":
        return f"{protocol}_{parts[-4]}-{parts[-3]}"
    elif parts[-1] == "disable":
        return f"{protocol}_{parts[-3]}"
    elif "object-group" not in parts[-2:]:
        if parts[-1].isdigit():
            return f"{protocol}_{parts[-1]}"
        else:
            return parts[-1].upper()
    else:
        print(f"Error parsing port: {' '.join(parts)}")
        return "unknown"

# Keep backward compatibility with old function names
def parse_access_list_permit(file_path: str) -> List[Dict[str, str]]:
    """Wrapper for backward compatibility"""
    return parse_access_list(file_path, "permit")

def parse_access_list_deny(file_path: str) -> List[Dict[str, str]]:
    """Wrapper for backward compatibility"""
    return parse_access_list(file_path, "deny")

def merge_and_remove_duplicate_rule(rules: pd.DataFrame) -> pd.DataFrame:
    """
    Remove duplicate rules by merging based on specified criteria.
    
    Args:
        rules: DataFrame containing columns ['source', 'destination', 'ports']
        
    Returns:
        DataFrame with cleaned and merged rules
    """
    try:
        # Step 1: Merge rules with the same source and destination
        merged_source_dest = (
            rules.groupby(['source', 'destination'], as_index=False)
            .agg({'ports': lambda x: ','.join(sorted(set(x)))})
        )

        # Step 2: Extract the merged keys for filtering
        merged_source_dest_keys = set(zip(merged_source_dest['source'], merged_source_dest['destination']))
        
        # Filter out the rules that were already merged
        remaining_data = rules[
            ~rules.apply(lambda row: (row['source'], row['destination']) in merged_source_dest_keys, axis=1)
        ]

        # Combine merged source-destination rules with remaining data
        final_cleaned_data = pd.concat([merged_source_dest, remaining_data]).drop_duplicates()

        # Step 3: Merge rules with the same source and ports
        merged_source_ports = (
            final_cleaned_data.groupby(['source', 'ports'], as_index=False)
            .agg({'destination': lambda x: ','.join(sorted(set(x)))})
        )

        # Extract the merged keys for filtering
        merged_source_ports_keys = set(zip(merged_source_ports['source'], merged_source_ports['ports']))
        
        # Filter out the rules that were already merged
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
            .agg({'source': lambda x: ','.join(sorted(set(x)))})
        )

        # Extract the merged keys for filtering
        merged_dest_ports_keys = set(zip(merged_dest_ports['destination'], merged_dest_ports['ports']))
        
        # Filter out the rules that were already merged
        remaining_data_after_dest_ports_merge = final_source_ports_cleaned_data[
            ~final_source_ports_cleaned_data.apply(
                lambda row: (row['destination'], row['ports']) in merged_dest_ports_keys, axis=1
            )
        ]

        # Combine merged destination-port rules with remaining data
        final_dest_ports_cleaned_data = pd.concat(
            [merged_dest_ports, remaining_data_after_dest_ports_merge]
        ).drop_duplicates()

        # Return the final cleaned data
        return final_dest_ports_cleaned_data[['source', 'destination', 'ports']].drop_duplicates()
    except Exception as e:
        print(f"Error during merging and removing duplicates: {e}")
        return pd.DataFrame(columns=['source', 'destination', 'ports'])

def read_csv(file_path: str) -> List[Dict[str, str]]:
    """
    Read a CSV file containing firewall rules.
    
    Args:
        file_path: Path to the CSV file
        
    Returns:
        List of dictionaries containing the rules
    """
    try:
        rules = []
        with open(file_path, mode='r', encoding='utf-8-sig') as file:
            reader = csv.DictReader(file)
            for row in reader:
                rules.append(row)
    except FileNotFoundError:
        print(f"File '{file_path}' not found. Please check the file name and try again.")
        return []
    except Exception as e:
        print(f"Error reading CSV file '{file_path}': {e}")
        return []
        
    return rules

def write_csv(rules: List[Dict[str, str]], file_path: str) -> None:
    """
    Write firewall rules to a CSV file.
    
    Args:
        rules: List of dictionaries containing the rules
        file_path: Path to the output CSV file
    """
    try:
        with open(file_path, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["source", "destination", "ports"])
            writer.writeheader()
            for rule in rules:
                writer.writerow(rule)
        print(f"Rules successfully written to {file_path}")
    except Exception as e:
        print(f"Error writing to file '{file_path}': {e}")

def write_fortinet_conf(rules: Any, output_file: str, start_edit: int = 1, action: Optional[str] = None) -> None:
    """
    Write firewall rules to a Fortinet configuration file.
    
    Args:
        rules: List of dictionaries containing the rules
        output_file: Path to the output configuration file
        start_edit: Starting edit number (default: 1)
        action: Action to set for the rules (default: None)
    """
    try:
        with open(output_file, mode='w') as file:
            edit_number = start_edit
            for rule in rules:
                file.write(f"edit {edit_number}\n")
                file.write(f"    set name merged-{edit_number}\n")
                file.write(f"    set srcintf \"any\"\n")
                file.write(f"    set dstintf \"any\"\n")

                if action:
                    file.write(f"    set action \"{action}\"\n")
                
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

                # Add comment
                file.write(f"    set comments \"{sources[0].strip()}_{destinations[0].strip()}\"\n")

                file.write(f"next\n")
                edit_number += 1
            file.write("end\n")
        print(f"Fortinet configuration successfully written to {output_file}")
    except Exception as e:
        print(f"Error writing to file '{output_file}': {e}")


if __name__ == "__main__":
    # This section will only run when the script is executed directly
    # It's a simple example of how to use the functions in this module
    import sys
    
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        action_type = sys.argv[2] if len(sys.argv) > 2 else "permit"
        
        print(f"Processing {input_file} for {action_type} rules...")
        
        # Parse access list
        if action_type.lower() == "permit":
            rules = parse_access_list_permit(input_file)
        else:
            rules = parse_access_list_deny(input_file)
        
        if not rules:
            print("No rules found or error processing the file.")
            sys.exit(1)
            
        # Save intermediate rules
        intermediate_file = f"{input_file.split('.')[0]}_original_rules.csv"
        write_csv(rules, intermediate_file)
        
        # Remove duplicates
        rules_df = pd.read_csv(intermediate_file)
        cleaned_rules = merge_and_remove_duplicate_rule(rules_df)
        
        # Save final rules
        output_file = f"{input_file.split('.')[0]}_merged_rules.csv"
        cleaned_rules.to_csv(output_file, index=False)
        
        # Generate Fortinet config
        conf_file = f"{input_file.split('.')[0]}_fortinet.conf"
        write_fortinet_conf(cleaned_rules.to_dict('records'), conf_file, action=action_type.lower())
        
        print("Processing complete!")
    else:
        print("Usage: python optimized_reduced_asa_firewall.py <input_file> [permit|deny]")
