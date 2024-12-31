import csv

def calculate_subnet_from_prefix(prefix):
    if not (0 <= prefix <= 32):
        raise ValueError("Prefix must be in the range 0 to 32")
    
    # Create a 32-bit binary mask with `prefix` ones followed by zeros
    binary_mask = (1 << 32) - (1 << (32 - prefix))
    
    # Convert to IPv4 format
    subnet_mask = [
        (binary_mask >> (8 * i)) & 0xFF for i in range(3, -1, -1)
    ]
    
    # Join as a dotted string
    return ".".join(map(str, subnet_mask))

def dst_src_address(file):
  with open(file, 'r') as f:
    reader = csv.DictReader(f)
    dst_list = []
    for row in reader:
      dst_list.append(row['destination'])
      dst_list.append(row['source'])
    unique_dst = []
    for dest in dst_list:
      if "," in dest:
        dest = dest.split(",")
        for d in dest:
          unique_dst.append(d)
      else:
        unique_dst.append(dest)
    unique_dst = set(unique_dst)
    return unique_dst

def service_addr(file):
    with open(file, mode='r') as f:
        reader = csv.DictReader(f)
        service_list = []
        unique_service = []
        for row in reader:
            service_list.append(row['ports'])
        for service in service_list:
            if "," in service:
                service = service.split(",")
                for s in service:
                    unique_service.append(s)
            else:
                unique_service.append(service)
    unique_service = set(unique_service)
    return unique_service            
    


def Compare_and_remove_src_dst_duplicates(file, unique_dst):
   with open(file, mode='r') as f:
    for line in f:
        if 'edit' in line:
            ip = line.split("\"")[1]
            if ip in unique_dst:
              unique_dst.remove(ip)
            elif '/' in ip:
              if ip.split('/')[0] in unique_dst:
                  unique_dst.remove(ip.split('/')[0])
    return unique_dst


def Compare_and_remove_service_duplicates(file, unique_service):
    with open(file, mode='r') as f:
        for line in f:
            if 'edit' in line:
                service = line.split("\"")[1]
                if service in unique_service:
                    unique_service.remove(service)
    print(unique_service)
    return unique_service


def Fortinet_dest_src_address_format(file_path, unique_dst):
    with open(file_path, mode='w', newline='') as f:
        f.write("config firewall address\n")
        
        for dest in unique_dst:
            try:
                if '/' in dest:
                    ip, prefix = dest.split('/')
                    subnet = calculate_subnet_from_prefix(int(prefix))
                else:
                    ip, subnet = dest, calculate_subnet_from_prefix(32)
                    prefix = 32
                
                # Write Fortinet address configuration
                f.write(f"  edit \"{ip}/{prefix}\"\n")
                f.write(f"     set subnet {ip} {subnet}\n")
                f.write("  next\n")
            except Exception as inner_e:
                pass
        f.write("end")


if __name__ == "__main__":
    file_path = 'Final_Merged_Rules.csv'

    extract_serivce = service_addr(file_path)    
    #  Extract destination addresses
    extract_destination  = dst_src_address(file_path)

        
    # Save the unique destinations to a CSV file
    output_file = 'unique_destinations.csv'
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['destination'])  # Write header
        writer.writerows([[dest] for dest in extract_destination])  # Write data rows
    # Compare_and_remove_duplicates
    unique_dst = Compare_and_remove_src_dst_duplicates('/home/dsu979/Downloads/Telegram Desktop/address_and_addressgrp.txt', extract_destination)

    unique_service = Compare_and_remove_service_duplicates('/home/dsu979/Downloads/Telegram Desktop/config firewall service custom (3).bat', extract_serivce)

    output_file_2 = 'unique_services.csv'
    with open(output_file_2, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['service'])
        writer.writerows([[service] for service in unique_service])

    
    # Fortinet_address_format
    Fortinet_dest_src_address_format('Fortinet_addr_format_missing.txt', unique_dst)