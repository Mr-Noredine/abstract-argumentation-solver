import sys
import re

if sys.argv[1] == "-p":
    request = sys.argv[2]
if sys.argv[3] == "-f":
    file_name = sys.argv[4]
if sys.argv[5] == "-a":
    args_to_check = set(sys.argv[6].split(","))


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
 


def est_sans_conflit(ensemble):
    for a in ensemble:
        for b in ensemble:
            if a != b and (a, b) in attacks:
                return False
    return True


def est_extension_stable(ensemble):
    if not(est_sans_conflit(ensemble)):
        return False
    for arg in arguments:
        if arg not in ensemble:
            attackers = attacks_by.get(arg, set())
            if ensemble.isdisjoint(attackers):
                return False
    return True
   


if (request == "VE-PR"):
    pass
elif (request == "VE-ST"):
    if est_extension_stable(args_to_check):
        print("YES")
elif (request == "DC-PR"):
    pass
elif (request == "DC-ST"):
    pass
elif (request == "DS-PR"):
    pass
elif (request == "DS-ST"):
    pass
