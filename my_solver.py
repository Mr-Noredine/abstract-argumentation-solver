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
        
# - VE_ST  Vérifier si un extension est stable 
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
    
def get_arguemnts_without_attakers(arguments, attacks_by):
    args_without_attackers = []
    for arg in arguments:
        attackers = attacks_by.get(arg, [])  
        if attackers == []:
            args_without_attackers.append(arg)
    return args_without_attackers

def transform_as_in(label, arg, labeled):
    if (not(labeled.get(arg))):
        label[2].discard(arg)
        label[0].add(arg)
        labeled[arg] = True

def transform_as_out(label, arg, labeled):
    if (not(labeled.get(arg))):
        label[2].discard(arg)
        label[1].add(arg)
        labeled[arg] = True

    
def is_out(arg, label):
    return arg in label[1]

def is_in(arg, label):
    return arg in label[0]


def propagate(label, start, labeled):
    blockage = []
    visited = set()
    stack = [start]

    while stack:
        u = stack.pop()
        if u in visited:
            continue
        visited.add(u)
        
        if not(labeled[u]):
            attackers = attacks_by.get(u, set())
            if attackers and all(is_out(b, label) for b in attackers):
                transform_as_in(label, u, labeled)
            elif attackers and any(is_in(b, label) for b in attackers):
                transform_as_out(label, u, labeled)
            else:
                blockage.append(u)
                continue
        for v in attacks_from.get(u, set()):
            if v not in visited:
                stack.append(v)
    return visited, blockage

def generate_valide_labelings(arguments, attacks_by, attacks_from):
    labelings = []
    arguments = list(arguments)
    labeled = {arg: False for arg in arguments}
    label = (set(), set(), set(arguments))
    visited = set()
    blockage = []
    
    args_without_attakers = get_arguemnts_without_attakers(arguments, attacks_by)
    
    if args_without_attakers != []:
        for a in args_without_attakers:
            transform_as_in(label, a, labeled)
            v, b = propagate(label, a , labeled)
            visited |= v
            blockage += b
    def explore(label, labeled, visited, blockage): 
        if not (set(arguments) - visited) and labeling_est_valide(label):
            labelings.append((set(label[0]), set(label[1]), set(label[2])))
            return
        
        if blockage:
            u = blockage.pop()
        else:
            u = next(iter(set(arguments) - visited)) 
        
        # branche 1 : IN  
        visited1 = set(visited)
        blockage1 = list(blockage)
        label1 = (set(label[0]), set(label[1]), set(label[2]))
        labeled1 = dict(labeled)
        
        transform_as_in(label1, u, labeled1)
        v1, b1 = propagate(label1, u, labeled1)
        visited1 |= v1
        blockage1 += b1
        explore(label1, labeled1, visited1, blockage1)
        
        # branche 2: OUT
        blockage2 = list(blockage)
        visited2 = set(visited)
        label2 = (set(label[0]), set(label[1]), set(label[2]))
        labeled2 = dict(labeled)
                
        transform_as_out(label2, u, labeled2)
        v2, b2 = propagate(label2, u, labeled2)
        visited2 |= v2
        blockage2 += b2
        explore(label2, labeled2, visited2, blockage2)
        
    explore(label, labeled, visited, blockage)
    return labelings

     
def labeling_est_valide(labeling):
    args_in, args_out, args_undec = labeling
    for a in args_in:
        for attacker in attacks_by.get(a, set()):
            if attacker not in args_out:
                return False
            
    for a in args_out:
        has_attacker_in = False
        for attacker in attacks_by.get(a, set()):
            if attacker in args_in:
                has_attacker_in = True
                break 
        if not(has_attacker_in):
            return False 
               
    for a in args_undec:
        attackers = attacks_by.get(a, set())
        if not attackers:
            return False
        
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


def get_extensions_preferee(labels_valides):
    extension_complete = [label[0] for label in labels_valides]
    extension_maximales = []

    for ext in extension_complete:
        est_maximale = True
        for autre in extension_complete:
            if ext < autre:          
                est_maximale = False
                break
        if est_maximale:
            extension_maximales.append(ext)
    return extension_maximales
    

# Verify Extension
if (request == "VE-PR"):
    valids = generate_valide_labelings(arguments, attacks_by, attacks_from)
    extensions_preferee = get_extensions_preferee(valids)
    print("Extension preferee: ")
    for ext in extensions_preferee:
        print(ext, end="\n")
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
    valids = generate_valide_labelings(arguments, attacks_by, attacks_from)
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
    valids = generate_valide_labelings(arguments, attacks_by, attacks_from)
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
    valids = generate_valide_labelings(arguments, attacks_by, attacks_from)
    extensions_preferee = get_extensions_preferee(valids)
    result = True
    if extensions_preferee == []:
        result = False
        
    for ext in extensions_preferee:
        if not(args_to_check <= ext):
            result = False
    if result:
        print("YES")
    else:
        print("NO")
    
elif (request == "DS-ST"):
    valids = generate_valide_labelings(arguments, attacks_by, attacks_from)
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
