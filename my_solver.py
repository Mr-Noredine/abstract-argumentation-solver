import sys
import re

if sys.argv[1] == "-p":
    semantics = sys.argv[2]
if sys.argv[3] == "-f":
    file_name = sys.argv[4]
if sys.argv[5] == "-a":
    args_to_check = sys.argv[6].split(",")


print(f"Request: {semantics}")
print(f"File name: {file_name}")
print(f"Arguments to verify: {args_to_check}")


with open(file_name, 'r') as fd:
    lines = fd.readlines()

arguments = set()
attacks = set()
attacks_from = {}
attacks_by = {}

for line in lines:
    regex1 = re.fullmatch(r"^arg\(([A-Za-z][A-Za-z0-9_]*)\)\.$", line.strip())
    regex2 = re.fullmatch(r"^att\(([A-Za-z][A-Za-z0-9_]*),([A-Za-z][A-Za-z0-9_]*)\)\.$", line.strip())
    if regex1:
        arguments.add(regex1.group(1))
    elif regex2:
        attacks.add((regex2.group(1), regex2.group(2)))
        if regex2.group(1) not in attacks_from:
            attacks_from[regex2.group(1)] = set()
        if regex2.group(2) not in attacks_by:
            attacks_by[regex2.group(2)] = set()
        attacks_from[regex2.group(1)].add(regex2.group(2))
        attacks_by[regex2.group(2)].add(regex2.group(1))
 
print(f"Arguments: {arguments}")
print(f"Attacks: {attacks}")
print(f"Attacks from: {attacks_from}")
print(f"Attacks by: {attacks_by}")
