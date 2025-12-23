import random
import sys

def make_easy_af(n=50, seed=42,
                 chain_edges=True,          # une chaîne simple a0->a1->...->a(n-1)
                 few_random_edges=20,       # quelques attaques aléatoires (faible)
                 no_self_attacks=True):     # pas d'auto-attaques
    """
    AF "easy" :
    - une chaîne (DAG) + un petit bruit aléatoire
    - pas de gros cycles, très peu de contraintes
    """
    random.seed(seed)

    args = [f"a{i}" for i in range(n)]
    attacks = set()

    # Chaîne principale (acyclique)
    if chain_edges:
        for i in range(n - 1):
            attacks.add((i, i + 1))

    # Quelques attaques aléatoires (sans trop de cycles)
    for _ in range(few_random_edges):
        u = random.randrange(n - 1)
        v = random.randrange(u + 1, n)  # v > u pour rester acyclique
        attacks.add((u, v))

    # optionnel : auto-attaques
    if not no_self_attacks:
        for _ in range(max(1, n // 20)):
            u = random.randrange(n)
            attacks.add((u, u))

    return args, attacks


def write_apx(filename, args, attacks):
    with open(filename, "w") as f:
        for a in args:
            f.write(f"arg({a}).\n")
        for (u, v) in sorted(attacks):
            f.write(f"att(a{u},a{v}).\n")


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50
    args, attacks = make_easy_af(n=n, seed=42, few_random_edges=n // 2)
    out = f"easy_{n}.apx"
    write_apx(out, args, attacks)
    print("OK ->", out, "| args:", len(args), "| attacks:", len(attacks))
