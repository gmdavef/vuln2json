import re
import json

cve_pattern = r'\[ CVSS:v([23]) \] \[([HCMLI])\] (\d+\.\d+) / (CVE-\d+-\d+)'
exploitable_pattern = r'Exploitable:\s+(.*)'

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
            pattern = r'^\s*[12]\)\s*(.*)$'
            for line in lines:
                match = re.match(pattern, line)
                if match:
                    # Extract the data after 1) or 2)
                    results.append(match.group(1))
        else:
            # Create a list and interate through applying the Regex
            lines = detectSection[1].splitlines()
            pattern = r'^\s*[12]\)\s*(.*)$'
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
        return results
    else:
        return None

def parse_input(input_text):
    # Initialize the result dictionary
    result = []

    # Split the input into sections
    sections = input_text.split('--------------------------------------------------------------------------------')

    # Parse the main section
    for i, section in enumerate(sections[1:4]):
        parsed = {}
        temp = section.strip()
        #print(temp)

        # Get CVE Name
        cve_name = re.search(cve_pattern, temp).group(4)
        parsed['cve_name']= cve_name
        
        # Get CVSS Score
        cvss_score = re.search(cve_pattern, temp).group(3)
        parsed['cve_score']=float(cvss_score)

        parsed['detections']=parse_detections(temp)
        parsed['suppressed']=parse_suppressed(temp)
    
        result.append(parsed)
        


    return result

def main():
    # Prompt the user to enter the file path
    #file_path = input("Enter the path to the input text file: ")

    file_path = "Examples/vulns.txt"
    try:
        # Read the content of the file
        with open(file_path, 'r') as file:
            input_text = file.read()

        # Parse input and convert to JSON
        parsed_data = parse_input(input_text)
        json_output = json.dumps(parsed_data, indent=2)

        # Print JSON output
        print("\nJSON Output:")
        print(json_output)

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
