# ASA Firewall ACL Parser and Cleaner

This tool parses Cisco ASA firewall access control lists (ACLs) and converts them to Fortinet configuration format. It also optimizes the rules by merging duplicate or similar rules.

## Features

- Parse Cisco ASA access lists from text files
- Extract permit and deny rules separately
- Optimize rules by merging duplicates
- Convert subnet masks to CIDR notation
- Generate Fortinet-compatible configuration files
- Export rules to CSV format

## Requirements

- Python 3.6 or higher
- pandas library

## Installation

1. Clone this repository:

```
git clone https://github.com/yourusername/ASA-acl-parser-and-cleaner.git
cd ASA-acl-parser-and-cleaner
```

2. Install dependencies:

```
pip install pandas
```

## Usage

### Using main.py (Command-line Interface)

```
python main.py -i <input_file> -a <action>
```

Arguments:
- `-i, --input`: Input file containing ACL rules
- `-a, --action`: Type of rules to process ('permit' or 'deny', default: 'permit')

If you don't provide arguments, the script will prompt you for them.

Example:
```
python main.py -i sample.txt -a permit
```

### Using the Python API

```python
import pandas as pd
from optimized_reduced_asa_firewall import (
    parse_access_list_permit, 
    parse_access_list_deny,
    merge_and_remove_duplicate_rule,
    write_fortinet_conf
)

# Parse ACL file
rules = parse_access_list_permit("sample.txt")

# Save intermediate rules
import csv
with open("intermediate_rules.csv", 'w', newline='') as file:
    writer = csv.DictWriter(file, fieldnames=rules[0].keys())
    writer.writeheader()
    writer.writerows(rules)

# Process and merge rules
rule_df = pd.read_csv("intermediate_rules.csv")
cleaned_rules = merge_and_remove_duplicate_rule(rule_df)

# Write Fortinet configuration
write_fortinet_conf(
    cleaned_rules.to_dict('records'), 
    "fortinet_config.conf", 
    action="accept"
)

# Save final rules to CSV
cleaned_rules.to_csv("final_rules.csv", index=False)
```

## Output Files

The script generates three output files:
1. `{input_filename}_repo_{action}.csv`: Intermediate file with parsed rules
2. `{input_filename}_final_{action}.csv`: Final file with optimized rules
3. `{input_filename}_{action}.conf`: Fortinet configuration file

## Recent Optimizations

1. **Code Structure**:
   - Refactored duplicate functions into a single implementation
   - Added proper type hints for better code readability and error checking
   - Improved documentation with docstrings

2. **Performance**:
   - Optimized file I/O operations
   - Improved error handling with detailed error messages
   - Enhanced CSV processing

3. **User Interface**:
   - Added command-line argument parsing
   - Improved progress and status messages
   - Better error reporting

4. **Maintainability**:
   - Separated concerns into modular functions
   - Added validation and error checking throughout the code
   - Improved naming conventions for clarity

## License

[Your license information]
