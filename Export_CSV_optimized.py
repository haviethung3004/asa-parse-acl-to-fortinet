from optimized_reduced_asa_firewall import parse_access_list, merge_rules, remove_duplicate_rules, write_csv
import os

# Get the input file path using the dialog box
INPUT_FILE = input("Enter the path to the ASA firewall policy file: ")

# Extract directory and base name of the input file
input_dir = os.path.dirname(INPUT_FILE)  # Get the directory of the input file
base_name = os.path.splitext(os.path.basename(INPUT_FILE))[0]  # Extract base name of the input file

# Generate dynamic output paths in the same directory
OUTPUT_FILE = os.path.join(input_dir, f"{base_name}_cleaned_firewall_policy.csv")

# Parse and merge rules
rules = parse_access_list(INPUT_FILE)
merged_rules = merge_rules(rules)

# Remove duplicate rules
unique_rules = remove_duplicate_rules(merged_rules)

# Write final rules to CSV
write_csv(unique_rules, OUTPUT_FILE)

print(f"Successfully wrote cleaned firewall policy to {OUTPUT_FILE}")
