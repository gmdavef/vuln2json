# vuln2json
Python script to convert RL-Secure find CVE* command into JSON

## Background
Running the rl-secure find CVE* command outputs non-standard but semi-structucure text. This script uses RegEx to pull out all of the information and creates a JSON file. 

## Example Usage
#### Get the output of the rl-secure command
```
./rl-secure find CVE* --no-color >> vulns.txt
```

In Windows PowerShell:
```
rl-secure find CVE* --no-color | Out-File vulns.txt -Encoding utf8
```

#### Convert to JSON
```
python3 vuln2JSON.py
```
