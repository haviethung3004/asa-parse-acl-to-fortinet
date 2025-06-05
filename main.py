from optimized_reduced_asa_firewall import *
import pandas as pd

def main():
    try:
        input_file = input('Enter the file name: ').strip()
            
        choose_case = input('Choose deny or permit: ').strip()
        if choose_case == 'permit':
            rules = parse_access_list_permit(input_file)
            print(rules)
            choose_case = 'accept'
        elif choose_case == 'deny':
            rules = parse_access_list_deny(input_file)

        intermediate_file = f"{input_file.split('.')[0]}_repo_{choose_case}.csv"
        print(f"\nRepo rules saved to {intermediate_file}")

        output_file = f"{input_file.split('.')[0]}_final_{choose_case}.csv"
        print(f"\nFinal cleaned rules saved to {output_file}")

        Fortinet_fortmat = f"{input_file.split('.')[0]}_{choose_case}.conf"
        print(f"\nFortinet format saved to {Fortinet_fortmat}")  


        # Save intermediate rules
        with open(intermediate_file, 'w', newline='') as file:
            try:
                writer = csv.DictWriter(file, fieldnames=rules[0].keys())
                writer.writeheader()
                writer.writerows(rules)

                print(f"Intermediate rules saved to {intermediate_file}")
            except Exception as e:
                print(f"Error writing to file {intermediate_file}: {e}")


        print("Processing rules...")
        # Remove duplicate and merge rules
        rule_df = pd.read_csv(intermediate_file)
        print(f"Rule df: {rule_df.head()}")
        cleaned_rules = merge_and_remove_duplicate_rule(rule_df)
        write_fortinet_conf(cleaned_rules.to_dict('records'), Fortinet_fortmat, start_edit=1, action=choose_case)

        # Save final rules
        cleaned_rules.to_csv(output_file, index=False)
        print(f"\nFinal cleaned rules saved to {output_file}")
    except FileNotFoundError:
        print(f"File '{input_file}' not found. Please check the file name and try again.")

if __name__ == "__main__":
    main()