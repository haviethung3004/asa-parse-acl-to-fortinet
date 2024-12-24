# ASA ACL Parser and Cleaner

This repository provides a script to parse, clean, merge, and export Access Control List (ACL) policies for Cisco ASA and Fortinet devices. The tool simplifies firewall rule management by automating redundant rule detection, merging overlapping rules, and generating Fortinet-compatible configuration files.

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

1. Place your raw ACL configuration file in the same directory or specify its full path.
2. Modify the script's `INPUT_FILE` variable with the path to your ACL configuration file.

### Running the Script

Execute the script to clean and export rules:
```bash
python3 acl_parser.py
```

### Outputs
- **Cleaned CSV File**: Contains the deduplicated and merged ACL rules in CSV format.
- **Fortinet Configuration File**: A Fortinet-compatible configuration script ready for deployment.

## Configuration

Update these variables in `acl_parser.py` as needed:

- **Input File**:
  The raw ACL configuration file to process:
  ```python
  INPUT_FILE = '/path/to/your/input/file.txt'
  ```

- **Output Files**:
  These are dynamically generated based on the input file's name and directory:
  - `cleaned_firewall_policy.csv`
  - `acls.conf`

## Example Workflow

1. Input File:  
   A raw ACL configuration file like this:
   ```plaintext
   permit tcp host 192.168.1.1 host 192.168.2.2 eq 80
   permit udp any any eq 53
   ```

2. Output (Cleaned Rules CSV):
   ```csv
   source,destination,ports
   192.168.1.1,192.168.2.2,tcp_80
   all,all,udp_53
   ```

3. Output (Fortinet Configuration File):
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
   next
   ```

## Contribution

Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a new branch for your feature/bugfix.
3. Submit a pull request for review.

## License

This project is licensed under the MIT License. See `LICENSE` for details.

## Author

Developed by [dsu979](mailto:your-email@example.com). For support or queries, contact the author or create an issue in this repository.

