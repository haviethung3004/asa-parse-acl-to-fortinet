# ASA ACL Parser and Cleaner

This repository provides a set of Python scripts to parse, clean, merge, and export Access Control List (ACL) policies for Cisco ASA and Fortinet devices. The tools simplify firewall rule management by automating redundant rule detection, merging overlapping rules, and generating Fortinet-compatible configuration files.

## Files in the Repository

1. **`optimized_reduced_asa_firewall.py`**:

   - Provides core functions to parse and clean ASA firewall rules.
   - Merges overlapping or redundant rules.
   - Exports the cleaned data for further processing or configuration generation.

2. **`Export_CSV_optimized.py`**:

   - Converts cleaned and optimized rules into CSV format.
   - Useful for archival or further analysis of firewall policies.

3. **`Export_Fortinet_format_policy.py`**:

   - Generates Fortinet-compatible configuration files based on the cleaned CSV rules.
   - Simplifies deployment by creating ready-to-use configuration scripts.

## Features

- **ACL Parsing**: Extracts relevant details from raw ACL configuration files (e.g., source, destination, ports, and protocols).
- **Rule Merging**: Combines rules with the same source, destination, and ports to optimize the configuration.
- **Duplicate Removal**: Identifies and removes redundant rules based on specific criteria.
- **Fortinet Configuration Generation**: Automatically generates Fortinet-compatible ACL configurations.
- **CSV Export**: Outputs cleaned and merged rules into CSV format for further analysis or archival.

## Requirements

This project requires Python 3.x and the following libraries:

- `csv`
- `collections` (default library)
- `os` (default library)

Ensure Python is installed and accessible from your system.

## Installation

1. Clone the repository:

   ```bash
   git clone https://git.dision.office/dsu979/ASA-acl-parser-and-cleaner.git
   cd ASA-acl-parser-and-cleaner
   ```

2. Ensure Python is installed:

   ```bash
   python3 --version
   ```

## Usage

1. **Optimize ASA Firewall Rules**:
   Import and use `optimized_reduced_asa_firewall.py` to parse and clean ASA firewall rules.

   Example:
   ```python
   from optimized_reduced_asa_firewall import parse_access_list, clean_rules

   rules = parse_access_list("/path/to/input/acl.txt")
   cleaned_rules = clean_rules(rules)
   print(cleaned_rules)
   ```

2. **Export to CSV**:
   Use the `Export_CSV_optimized.py` script to generate a CSV file with the cleaned rules.

   ```bash
   python3 Export_CSV_optimized.py
   ```
   When prompted, provide the path to the raw ACL input file.

3. **Generate Fortinet Configuration**:
   Use the `Export_Fortinet_format_policy.py` script to generate a Fortinet-compatible configuration file from the cleaned CSV.

   ```bash
   python3 Export_Fortinet_format_policy.py
   ```
   When prompted, provide the path to the cleaned CSV file.

### Outputs

- **Cleaned CSV File**: Contains the deduplicated and merged ACL rules in CSV format.
- **Fortinet Configuration File**: A Fortinet-compatible configuration script ready for deployment.

## Configuration

Update these variables in the respective scripts as needed:

- **Input File**:
  The raw ACL configuration file to process:

  ```python
  INPUT_FILE 'Select your path file here'
  ```

- **Output Files**:
  These are dynamically generated based on the input file's name and directory:

  - `cleaned_firewall_policy.csv`
  - `acl_conf`

## Example Workflow

1. Input File:
   A raw ACL configuration file like this:

   ```plaintext
   permit tcp host 192.168.1.1 host 192.168.2.2 eq 80
   permit udp any any eq 53
   ```

2. Cleaned Rules CSV:
   Run `Export_CSV_optimized.py` to generate the cleaned CSV file:

   ```csv
   source,destination,ports
   192.168.1.1,192.168.2.2,tcp_80
   all,all,udp_53
   ```

3. Fortinet Configuration File:
   Use `Export_Fortinet_format_policy.py` to generate the configuration file:

   ```plaintext
   edit 9211
       set name merged-9211
       set srcintf "any"
       set dstintf "any"
       set srcaddr "192.168.1.1"
       set dstaddr "192.168.2.2"
       set service "tcp_80"
       set action accept
       set schedule always
       set comments "192.168.1.1_192.168.2.2"
   next
   ```

## License

This project is licensed under the MIT License. See `LICENSE` for details.

## Author

For support or queries, contact dsu979 or create an issue in this repository.

