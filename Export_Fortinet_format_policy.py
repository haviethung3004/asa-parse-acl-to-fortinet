from optimized_reduced_asa_firewall import parse_csv, write_fortinet_conf
import os

# Get the input file path
INPUT_FILE = input("Enter the path to the cleaned CSV firewall policy file: ")

# Extract directory and base name of the input file
input_dir = os.path.dirname(INPUT_FILE)  # Get the directory of the input file
base_name = os.path.splitext(os.path.basename(INPUT_FILE))[0]  # Extract base name of the input file

# Generate dynamic output path for the Fortinet configuration file
FORTINET_OUTPUT_FILE = os.path.join(input_dir, f"{base_name}_acl_conf")

# Parse the cleaned CSV file into a list of rules
rules = parse_csv(INPUT_FILE)

# Write the rules to Fortinet configuration
write_fortinet_conf(rules, FORTINET_OUTPUT_FILE)

print(f"Fortinet configuration successfully written to {FORTINET_OUTPUT_FILE}")
