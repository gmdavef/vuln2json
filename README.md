# vuln2json
Python script to convert RL-Secure find CVE* command into JSON

## Background
Running the rl-secure find CVE* command outputs non-standard but semi-structucure text. This script uses RegEx to pull out all of the information and creates a JSON file. 

## Usage
#### Get the output of the rl-secure command
```
./rl-secure find CVE* >> vulns.txt
```
#### Convert to JSON
```
python3 vuln2JSON.py
```
