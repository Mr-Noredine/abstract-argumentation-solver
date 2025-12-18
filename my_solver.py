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
    regex_arg = re.fullmatch(r"^arg\(([A-Za-z][A-Za-z0-9_]*)\)\.$", line.strip())
    regex_att = re.fullmatch(r"^att\(([A-Za-z][A-Za-z0-9_]*),([A-Za-z][A-Za-z0-9_]*)\)\.$", line.strip())
    if regex_arg:
        arguments.add(regex_arg.group(1))
    elif regex_att:
        attacks.add((regex_att.group(1), regex_att.group(2)))
        if regex_att.group(1) not in attacks_from:
            attacks_from[regex_att.group(1)] = set()
        if regex_att.group(2) not in attacks_by:
            attacks_by[regex_att.group(2)] = set()
        attacks_from[regex_att.group(1)].add(regex_att.group(2))
        attacks_by[regex_att.group(2)].add(regex_att.group(1))
 
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
   
def est_extension_preferee(ensemble):
    if not(est_sans_conflit(ensemble)):
        return False
    
def labeling_est_valide(labeling):
    args_in, args_out, args_undec = labeling
    for a in args_in:
        for attacker in attacks_by.get(a, []):
            if attacker not in args_out:
                return False
            
    for a in args_out:
        has_attacker_in = False
        for attacker in attacks_by.get(a, []):
            if attacker in args_in:
                has_attacker_in = True
                break 
        if not(has_attacker_in):
            return False 
               
    for a in args_undec:
        attackers = attacks_by.get(a, [])
        for arg in attackers:
            if arg in args_in:
                return False
        un_pas_out = False
        for arg in attackers:
            if arg not in args_out:
                un_pas_out = True
        if (not un_pas_out):
            return False
    return True
    
''' 
1- Initialiser IN avec tous les non attaqués
2- Mettre OUT tous leurs successeurs directs
3- Répéter :
    Si un argument a tous ses attaquants dans OUT → IN
    Si un argument a un attaquant dans IN → OUT

4- Continuer jusqu'à stabilisation (fixpoint)
5- Tous les arguments restants (non étiquetés) → à combiner (IN/OUT/UNDEC) avec brute-force réduite
'''

from itertools import product

def propagate_labels(arguments, attacks_by, attacks_from):
    args_in = set()
    args_out = set()
    undecided = set(arguments)  # tous au début

    # Étape 1 : non attaqués → IN
    for arg in arguments:
        if arg not in attacks_by or not attacks_by[arg]:
            args_in.add(arg)

    # Étape 2 : propagation
    changed = True
    while changed:
        changed = False
        for arg in list(undecided):
            if arg in args_in or arg in args_out:
                continue
            attackers = attacks_by.get(arg, set())
            if attackers.issubset(args_out):
                # Tous ses attaquants sont OUT → arg est IN
                args_in.add(arg)
                changed = True
            elif any(att in args_in for att in attackers):
                # Un attaquant est IN → arg est OUT
                args_out.add(arg)
                changed = True
        # Update undecided set
        undecided = undecided - args_in - args_out

    return args_in, args_out, undecided

def generate_valid_labelings(arguments, attacks_by):
    labelings = []
    labels = ["IN", "OUT", "UNDEC"]

    # Construction de l'inverse : attacks_from
    attacks_from = {}
    for attacker, targets in attacks_by.items():
        for target in targets:
            if attacker not in attacks_from:
                attacks_from[attacker] = set()
            attacks_from[attacker].add(target)

    # Propagation initiale
    args_in, args_out, remaining_args = propagate_labels(arguments, attacks_by, attacks_from)

    # Générer les combinaisons seulement sur les indécis restants
    remaining_args = list(remaining_args)
    for combo in product(labels, repeat=len(remaining_args)):
        in_set = set(args_in)
        out_set = set(args_out)
        undec_set = set()

        for arg, label in zip(remaining_args, combo):
            if label == "IN":
                in_set.add(arg)
            elif label == "OUT":
                out_set.add(arg)
            else:
                undec_set.add(arg)

        labeling = (in_set, out_set, undec_set)
        if labeling_est_valide(labeling):
            labelings.append(labeling)

    return labelings


def get_extensions_preferee(labels_valides):
    extension_complete = [label[0] for label in labels_valides]
    extension_maximales = []
    
    for ext in extension_complete:
        est_maximale = True
        for reste in extension_maximales:
            if (ext < reste):
                est_maximale = False
                break
        if est_maximale:
            extension_maximales.append(ext)
    return extension_maximales
    

# Verify Extension
if (request == "VE-PR"):
    valids = generate_valid_labelings(arguments, attacks_by)
    extensions_preferee = get_extensions_preferee(valids)
    result = False
    for ext in extensions_preferee:
        if args_to_check == ext:
            result = True
    if result: 
        print("YES")
    else:
        print("NO")
            
        
elif (request == "VE-ST"):
    if est_extension_stable(args_to_check):
        print("YES")
    else:
        print("NO") 
        
# Decide the Credulous acceptability de l’argument
elif (request == "DC-PR"):
    valids = generate_valid_labelings(arguments, attacks_by)
    extensions_preferee = get_extensions_preferee(valids)
    result = False
    for ext in extensions_preferee:
        if args_to_check <= ext:
            result = True
            break
    if result:
        print("YES")
    else:
        print("NO")
        
elif (request == "DC-ST"):
    valids = generate_valid_labelings(arguments, attacks_by)
    extensions_stable = [label[0] for label in valids if label[2] == set()]
    result = False
    for ext in extensions_stable:
        if args_to_check <= ext:
            result = True
    if result:
        print("YES")
    else:
        print("NO")

#Decide the Skeptical acceptability de l’argument
elif (request == "DS-PR"):
    valids = generate_valid_labelings(arguments, attacks_by)
    extensions_preferee = get_extensions_preferee(valids)
    result = True
    if extensions_preferee == []:
        result = False
    for ext in extensions_preferee:
        if args_to_check < ext:
            result = False
    if result:
        print("YES")
    else:
        print("NO")
    
elif (request == "DS-ST"):
    valids = generate_valid_labelings(arguments, attacks_by)
    extensions_stable = [label[0] for label in valids if label[2] == set()]
    
    result = True
    if extensions_stable == []:
        result = False
        
    for ext in extensions_stable:
        if not(args_to_check <= ext):
            result = False
    if result:
        print("YES")
    else:
        print("NO")
