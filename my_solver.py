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
from collections import deque

IN, OUT, UNDEC = "IN", "OUT", "UNDEC"

def _build_attacks_from(arguments, attacks_by):
    """Construit attacks_from (attaquant -> cibles) à partir de attacks_by (cible -> attaquants)."""
    attacks_from = {a: set() for a in arguments}
    for target, attackers in attacks_by.items():
        for attacker in attackers:
            attacks_from.setdefault(attacker, set()).add(target)
    return attacks_from


def propagate_labels(arguments, attacks_by, attacks_from, init_labels=None):
    """
    Propagation forte (fixpoint) avec déductions:
    - si a est IN => tous ses attaquants OUT + toutes ses cibles OUT
    - si a est OUT => au moins un attaquant IN (force si unique possibilité)
    - si a est UNDEC => aucun attaquant IN et au moins un attaquant pas OUT (force UNDEC si unique possibilité)

    Retour:
      (labels_dict) si cohérent, sinon None
    labels_dict: arg -> "IN"/"OUT"/"UNDEC" (pour ceux déjà décidés)
    """
    labels = {} if init_labels is None else dict(init_labels)  # copie
    q = deque()

    # On met tout dans la queue pour appliquer les règles "non étiqueté => déduction"
    for a in arguments:
        q.append(a)

    def assign(a, v):
        cur = labels.get(a)
        if cur is None:
            labels[a] = v
            q.append(a)
            # Les voisins impactés (ceux qui dépendent de a comme attaquant)
            for t in attacks_from.get(a, ()):
                q.append(t)
            # Et ceux qui impactent a (ses attaquants) peuvent être forcés
            for b in attacks_by.get(a, ()):
                q.append(b)
            return True
        return cur == v  # False si contradiction

    while q:
        a = q.popleft()
        attackers = attacks_by.get(a, set())
        targets = attacks_from.get(a, set())
        la = labels.get(a)

        # --- Déductions même si a n'est pas encore labelisé ---
        if la is None:
            # Non-attaqué => IN
            if not attackers:
                if not assign(a, IN):
                    return None
                continue

            # Si un attaquant est IN => a doit être OUT
            if any(labels.get(b) == IN for b in attackers):
                if not assign(a, OUT):
                    return None
                continue

            # Si tous les attaquants sont OUT => a doit être IN
            if all(labels.get(b) == OUT for b in attackers):
                if not assign(a, IN):
                    return None
                continue

            # Sinon, pas de déduction immédiate
            continue

        # --- Contraintes selon le label de a ---
        if la == IN:
            # Tous les attaquants doivent être OUT
            for b in attackers:
                lb = labels.get(b)
                if lb is None:
                    if not assign(b, OUT):
                        return None
                elif lb != OUT:
                    return None

            # Tous les successeurs (cibles) doivent être OUT (car attaqués par un IN)
            for t in targets:
                lt = labels.get(t)
                if lt is None:
                    if not assign(t, OUT):
                        return None
                elif lt != OUT:
                    return None

        elif la == OUT:
            # OUT => doit avoir au moins un attaquant IN
            if not attackers:
                return None  # impossible d'être OUT sans attaquant

            if any(labels.get(b) == IN for b in attackers):
                continue  # déjà satisfait

            # candidats possibles pour devenir IN : ceux non assignés uniquement
            candidates = [b for b in attackers if labels.get(b) is None]
            if not candidates:
                return None  # tous assignés, aucun IN => contradiction

            # Si un seul candidat reste, on le force IN
            if len(candidates) == 1:
                if not assign(candidates[0], IN):
                    return None

        else:  # la == UNDEC
            # UNDEC => pas d'attaquant IN
            if not attackers:
                return None  # UNDEC impossible si aucun attaquant (ta règle "un_pas_out" échoue)

            for b in attackers:
                if labels.get(b) == IN:
                    return None

            # UNDEC => au moins un attaquant "pas OUT"
            # Comme aucun attaquant IN autorisé, il faut au moins un attaquant UNDEC
            if any(labels.get(b) == UNDEC for b in attackers):
                continue  # satisfait

            # candidats pouvant devenir UNDEC: ceux non assignés
            candidates = [b for b in attackers if labels.get(b) is None]
            # si tous OUT => contradiction
            if not candidates:
                return None

            # si un seul candidat, force UNDEC
            if len(candidates) == 1:
                if not assign(candidates[0], UNDEC):
                    return None

    return labels


def generate_valid_labelings(arguments, attacks_by, attacks_from=None, max_solutions=None):
    """
    Génère les labelings valides via backtracking + propagation + mémoïsation (DP).
    Retourne une liste de tuples: (in_set, out_set, undec_set)

    max_solutions: int ou None (si tu veux stopper après K solutions)
    """
    if attacks_from is None:
        attacks_from = _build_attacks_from(arguments, attacks_by)

    arguments = set(arguments)
    results = []
    dead_cache = set()  # DP : états sans solution (nogoods)

    def state_key(labels):
        in_s = frozenset(a for a, v in labels.items() if v == IN)
        out_s = frozenset(a for a, v in labels.items() if v == OUT)
        undec_s = frozenset(a for a, v in labels.items() if v == UNDEC)
        return (in_s, out_s, undec_s)

    def pick_var(labels):
        """Heuristique: choisir un argument non assigné le plus contraint (le plus d'attaquants)."""
        unassigned = [a for a in arguments if a not in labels]
        # plus il a d'attaquants, plus c'est contraint (bonne heuristique)
        return max(unassigned, key=lambda a: len(attacks_by.get(a, set())))

    def dfs(labels):
        # Stop si on a assez de solutions
        if max_solutions is not None and len(results) >= max_solutions:
            return

        key = state_key(labels)
        if key in dead_cache:
            return

        # Propagation
        propagated = propagate_labels(arguments, attacks_by, attacks_from, init_labels=labels)
        if propagated is None:
            dead_cache.add(key)
            return

        # Terminé ?
        if len(propagated) == len(arguments):
            in_set = {a for a, v in propagated.items() if v == IN}
            out_set = {a for a, v in propagated.items() if v == OUT}
            undec_set = {a for a, v in propagated.items() if v == UNDEC}
            labeling = (in_set, out_set, undec_set)

            # Optionnel: double-check avec ta fonction
            if labeling_est_valide(labeling):
                results.append(labeling)
            return

        # Choix / backtracking
        a = pick_var(propagated)

        # Ordre des essais (souvent IN/OUT d’abord pour propager fort)
        for v in (IN, OUT, UNDEC):
            new_labels = dict(propagated)
            new_labels[a] = v
            dfs(new_labels)

            if max_solutions is not None and len(results) >= max_solutions:
                return

        # Si aucune solution trouvée depuis cet état propagé, mémoriser
        if len(results) == 0 or (max_solutions is None):
            # Nogood utile surtout quand on explore "tout"
            dead_cache.add(state_key(propagated))

    dfs({})
    return results
##=================================================================================================


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
    valids = generate_valid_labelings(arguments, attacks_by, attacks_from, max_solutions=1)
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
    valids = generate_valid_labelings(arguments, attacks_by, attacks_from, max_solutions=1)
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
    valids = generate_valid_labelings(arguments, attacks_by, attacks_from, max_solutions=1)
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
    valids = generate_valid_labelings(arguments, attacks_by, attacks_from, max_solutions=1)
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
    valids = generate_valid_labelings(arguments, attacks_by, attacks_from, max_solutions=1)
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
