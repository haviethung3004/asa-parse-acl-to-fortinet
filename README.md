## Access List Parser and Converter

## Overview
This Python script is designed to parse access lists from a text file, convert them into CSV format, remove duplicate rules, and generate configurations compatible with Fortinet devices. The tool is highly customizable and modular, allowing easy integration into network management workflows.

---

## Features
1. **Access List Parsing**:
   - Parses ACL files containing permit rules.
   - Dynamically interprets source, destination, and ports.

2. **Duplicate Rule Management**:
   - Identifies and removes duplicate rules based on source, destination, and ports.
   - Groups and merges rules with shared attributes.

3. **File Conversion**:
   - Converts access lists into a structured CSV format.
   - Supports re-saving cleaned data as CSV.

4. **Fortinet Configuration Generator**:
   - Outputs configuration files in Fortinet-compatible syntax.
   - Supports bulk edit numbering and multiple attributes.

---

## Prerequisites
### Software Requirements:
- Python 3.7 or higher
- Required Python Libraries:
  - `pandas`
  - `csv`

### Installation:
1. Install Python from [python.org](https://www.python.org/).
2. Install the required libraries by running:
   ```bash
   pip install pandas
   ```

---

## Usage

### Input Files:
1. **Access List File** (`EPG_704_access-list.txt`):
   - Contains access list rules in plain text format.

### Generated Files:
1. **Intermediate Rules** (`EPG_704_accesslist_original_rules.csv`):
   - A raw CSV representation of parsed rules.

2. **Final Merged Rules** (`Final_Merged_Rules.csv`):
   - The deduplicated and cleaned rules in CSV format.

3. **Fortinet Configuration** (`fortinet_conf.txt`):
   - Fortinet-compatible configuration file.

### Running the Script
1. Ensure the input file is located in the working directory.
2. Execute the script:
   ```bash
   python script_name.py
   ```
3. The script processes the access list and produces the output files in the current directory.

---

## Functionality Breakdown

### Key Functions:

#### `parse_csv(file_path)`
- Reads CSV files and extracts source, destination, and ports as rules.

#### `convert_to_prefix_length(mask)`
- Converts a subnet mask into a prefix length.

#### `parse_access_list(file_path)`
- Parses access list text files and generates structured rules.
- Dynamically identifies attributes like `object`, `host`, and `any`.

#### `merge_and_remove_duplicate_rule(rules)`
- Deduplicates and merges rules based on:
  - Source and destination.
  - Source and ports.
  - Destination and ports.

#### `write_csv(rules, file_path)`
- Writes structured rules to a CSV file.

#### `write_fortinet_conf(rules, output_file, start_edit=9211)`
- Generates Fortinet-compatible configuration syntax from rules.

---

## Example

### Input Access List:
```
permit ip any host 192.168.1.1 eq 80
permit tcp object-group NET_1 host 10.0.0.1 range 1024 2048
```

### Generated Fortinet Configuration:
```
edit 9211
    set name merged-9211
    set srcintf "any"
    set dstintf "any"
    set action accept
    set srcaddr "all"
    set dstaddr "192.168.1.1"
    set schedule always
    set service "TCP_80"
    set comments "all_192.168.1.1"
next
```

---

## Customization
- Modify input and output file paths by changing these variables in the script:
  ```python
  input_file = "EPG_704_access-list.txt"
  intermediate_file = "EPG_704_accesslist_original_rules.csv"
  output_file = "Final_Merged_Rules.csv"
  ```
- Adjust the starting edit number for Fortinet configurations via the `start_edit` parameter in `write_fortinet_conf()`.

---

## Troubleshooting
- **Error: `ModuleNotFoundError: No module named 'pandas'`**
  - Solution: Install the pandas library using:
    ```bash
    pip install pandas
    ```

- **Error: FileNotFoundError**
  - Solution: Verify that the input file path is correct and the file exists in the directory.

---

## Contribution
Contributions to improve parsing logic, extend compatibility, or enhance functionality are welcome. Submit issues or pull requests via GitHub.

---

## License
This project is licensed under the MIT License.

