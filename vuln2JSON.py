import argparse
import os
import re
import json

cve_pattern = r'\[ CVSS:v([23]) \] \[([HCMLI])\] (\d+\.\d+) / (CVE-\d+-\d+)'
exploitable_pattern = r'Exploitable:\s+(.*)'
description_pattern = r"Description:\s+(.*?)(?:Detections|Suppressed|Current date|$)"

def parse_detections(text):
    results = []
    # Does the CVE contain Detections
    if "Detections ---------------------------------------------------------------------" in text:
        detectSection = text.split("Detections ---------------------------------------------------------------------")

        # Check to see if the string split includes Suppressed content as well
        if "Suppressed ---------------------------------------------------------------------" in detectSection[1]:
            cleanDetectSection = detectSection[1].split("Suppressed ---------------------------------------------------------------------" )

            # Create a list and interate through applying the Regex
            lines = cleanDetectSection[0].splitlines()
            pattern = r'^\s*\d+\)\s*(.*)$'
            for line in lines:
                match = re.match(pattern, line)
                if match:
                    # Extract the data after 1) or 2)
                    results.append(match.group(1))
        else:
            # Create a list and interate through applying the Regex
            lines = detectSection[1].splitlines()
            pattern = r'^\s*\d+\)\s*(.*)$'
            for line in lines:
                match = re.match(pattern, line)
                if match:
                    # Extract the data after 1) or 2)
                    results.append(match.group(1))
        # Return the list 
        return results
    else:
        # No detections so return None (null)
        return None


def parse_suppressed(text):
    results = []
    if "Suppressed ---------------------------------------------------------------------" in text:
        suppressedSection = text.split("Suppressed ---------------------------------------------------------------------" )

        lines = suppressedSection[1].splitlines()
        pattern = r'^\s*\d+\)\s*(.*)$'
        for line in lines:
                match = re.match(pattern, line)
                if match:
                    # Extract the data after 1) or 2)
                    results.append(match.group(1))

        return results
    else:
        return None

def parse_input(input_text):
    # Initialize the result dictionary
    result = []

    # Split the input into sections
    sections = input_text.split('--------------------------------------------------------------------------------')

    # Parse the main section
    for i, section in enumerate(sections[1:]):
        parsed = {}
        temp = section.strip()


        # Get CVE Name
        cve_name = re.search(cve_pattern, temp).group(4)
        parsed['cve_name']= cve_name
        
        # Get CVSS Score
        cvss_score = re.search(cve_pattern, temp).group(3)
        parsed['cve_score']=float(cvss_score)

        # Get Exploitable
        exploitable = re.search(exploitable_pattern, temp)
        parsed["exploitable"] = exploitable.group(1)

        # Get Description
        description = re.search(description_pattern, temp, re.DOTALL)
        #print(description.group(1).strip().replace("\n", "").replace("\t", ""))
        description = description.group(1).strip().replace("\n", "").replace("\t", "")
        description = re.sub(r'\s+', ' ', description)
        parsed['description'] = description

        parsed['detections']=parse_detections(temp)
        parsed['suppressed']=parse_suppressed(temp)
    
        result.append(parsed)
        


    return result

def main():

    # Set up argument parser
    parser = argparse.ArgumentParser(description="Process a file with an optional file path.")
    parser.add_argument("file_path", nargs="?", default="default_file.txt", help="Path to the file to process")

    # Parse arguments
    args = parser.parse_args()
    file_path = args.file_path

    # If the file path is not provided, prompt user
    if file_path == "default_file.txt" and not os.path.exists(file_path):
        # Prompt the user to enter the file path
        file_path = input("Enter the path to the input text file: ")

    try:
        # Read the content of the file
        with open(file_path, 'r', encoding='utf-8') as file:
            input_text = file.read()
        file.close()

        # Parse input and convert to JSON
        parsed_data = parse_input(input_text)
        json_output = json.dumps(parsed_data, indent=2)

        # Output JSON output
        with open("vulns.json", "w", encoding='utf-8') as out:
            out.write(json_output)
        out.close()
        
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
