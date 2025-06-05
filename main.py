import argparse
import os
import sys
import pandas as pd
from optimized_reduced_asa_firewall import (
    parse_access_list_permit, 
    parse_access_list_deny, 
    merge_and_remove_duplicate_rule, 
    write_fortinet_conf
)
import csv


def get_output_filenames(input_file: str, action_type: str) -> tuple:
    """
    Generate output filenames based on the input filename and action type.
    
    Args:
        input_file: Input file path
        action_type: Action type (permit/deny)
        
    Returns:
        Tuple of (intermediate_file, output_file, fortinet_format)
    """
    # Extract the base filename without extension
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    
    # Map permit/deny to accept/deny for output files
    output_action = "accept" if action_type == "permit" else action_type
    
    # Generate output filenames
    intermediate_file = f"{base_name}_repo_{output_action}.csv"
    output_file = f"{base_name}_final_{output_action}.csv"
    fortinet_format = f"{base_name}_{output_action}.conf"
    
    return intermediate_file, output_file, fortinet_format


def process_rules(input_file: str, action_type: str) -> None:
    """
    Process firewall rules from the input file.
    
    Args:
        input_file: Input file path
        action_type: Action type (permit/deny)
    """
    # Get output filenames
    intermediate_file, output_file, fortinet_format = get_output_filenames(input_file, action_type)
    
    # Print information about output files
    print(f"\nRepo rules will be saved to: {intermediate_file}")
    print(f"Final cleaned rules will be saved to: {output_file}")
    print(f"Fortinet format will be saved to: {fortinet_format}")
    
    # Parse access list based on action type
    if action_type == "permit":
        rules = parse_access_list_permit(input_file)
        output_action = "accept"
    elif action_type == "deny":
        rules = parse_access_list_deny(input_file)
        output_action = "deny"
    else:
        print(f"Invalid action type: {action_type}. Must be 'permit' or 'deny'.")
        sys.exit(1)
    
    # Check if any rules were found
    if not rules:
        print("No rules found or error processing the file.")
        sys.exit(1)
    
    # Save intermediate rules
    try:
        with open(intermediate_file, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=rules[0].keys())
            writer.writeheader()
            writer.writerows(rules)
            print(f"Intermediate rules saved to {intermediate_file}")
    except Exception as e:
        print(f"Error writing to file {intermediate_file}: {e}")
        sys.exit(1)
    
    # Process and merge rules
    try:
        print("Processing rules...")
        rule_df = pd.read_csv(intermediate_file)
        print(f"Loaded {len(rule_df)} rules from {intermediate_file}")
        
        cleaned_rules = merge_and_remove_duplicate_rule(rule_df)
        print(f"After merging and removing duplicates: {len(cleaned_rules)} rules")
        
        # Write Fortinet configuration
        write_fortinet_conf(
            cleaned_rules.to_dict('records'), 
            fortinet_format, 
            start_edit=1, 
            action=output_action
        )
        
        # Save final rules
        cleaned_rules.to_csv(output_file, index=False)
        print(f"\nFinal cleaned rules saved to {output_file}")
        print("\nProcessing complete!")
    except Exception as e:
        print(f"Error processing rules: {e}")
        sys.exit(1)


def main():
    # Create argument parser
    parser = argparse.ArgumentParser(
        description='ASA Firewall ACL Parser and Cleaner',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Add command line arguments
    parser.add_argument(
        '-i', '--input', 
        help='Input file containing access list rules'
    )
    parser.add_argument(
        '-a', '--action',
        choices=['permit', 'deny'],
        default='permit',
        help='Type of rules to process (permit or deny)'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # If input file is not provided, prompt the user
    input_file = args.input
    if not input_file:
        input_file = input('Enter the file name: ').strip()
    
    # Check if file exists
    if not os.path.isfile(input_file):
        print(f"File '{input_file}' not found. Please check the file name and try again.")
        sys.exit(1)
    
    # If action is not provided, prompt the user
    action_type = args.action
    if not action_type:
        action_type = input('Choose deny or permit: ').strip().lower()
        if action_type not in ['permit', 'deny']:
            print(f"Invalid action type: {action_type}. Must be 'permit' or 'deny'.")
            sys.exit(1)
    
    # Process the rules
    process_rules(input_file, action_type)


if __name__ == "__main__":
    main()