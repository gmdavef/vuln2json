import re
import json

def remove_ansi_escape(text):
    ansi_escape = re.compile(r'\x1B\[[0-9;]*[mK]')
    return ansi_escape.sub('', text)

def parse_vulns(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = remove_ansi_escape(file.read())

    entries = data.split('[ MATCHED ] ')[1:]
    vulns = []

    for entry in entries:
        vuln = {}
        lines = entry.strip().split('\n')

        # Project name from first line
        vuln['project'] = lines[0].strip()

        # CVSS version, severity, score, CVE
        cvss_match = re.search(r'\[ (CVSS:v[23]) \] \[(H|M|C)\] ([\d\.]+) / (CVE-\d{4}-\d+)', entry)
        if cvss_match:
            vuln['cvss_version'] = cvss_match.group(1)
            vuln['severity'] = cvss_match.group(2)
            vuln['cvss_score'] = float(cvss_match.group(3))
            vuln['cve'] = cvss_match.group(4)

        # Extract fields like Exploitable, Introduced in, Resolved in, Patch mandate, Sourced from
        fields = ['Exploitable', 'Introduced in', 'Resolved in', 'Patch mandate', 'Sourced from']
        for field in fields:
            match_field = re.search(rf'{field}:\s+(.*)', entry)
            if match_field:
                vuln[field.lower().replace(' ', '_')] = match_field.group(1).strip()

        # Extract description
        desc_match = re.search(r'Description:\s+((?:.+\n)+?)(?:Detections|Suppressed|-{5,})', entry)
        if desc_match:
            vuln['description'] = ' '.join(desc_match.group(1).strip().splitlines())

        # Extract detections
        detections_match = re.search(r'Detections -+\n((?:\s*\d+\)\s*.+\n?)+)', entry)
        if detections_match:
            detections_text = detections_match.group(1).strip()
            detections = [line.split(') ', 1)[1].strip() for line in detections_text.split('\n') if ') ' in line]
            vuln['detections'] = detections
        else:
            vuln['detections'] = []

        # Extract suppressed info if present
        suppressed_section = re.search(
            r'Suppressed -+\n\s+Author:\s+(.+)\n\s+Date:\s+(.+)\n\s+Reason:\s+(.+)',
            entry
        )
        if suppressed_section:
            vuln['suppressed'] = {
                'author': suppressed_section.group(1).strip(),
                'date': suppressed_section.group(2).strip(),
                'reason': suppressed_section.group(3).strip()
            }
        else:
            vuln['suppressed'] = None

        vulns.append(vuln)

    return vulns

# Parse the file and convert to JSON
vulnerabilities = parse_vulns('vulns.txt')

# Save to JSON file
with open('vulns.json', 'w', encoding='utf-8') as json_file:
    json.dump(vulnerabilities, json_file, indent=2)

print(json.dumps(vulnerabilities, indent=2))
