import random

def make_hard_af(n=50, k=10, seed=42,
                 intra_cycle_chords=3,      # densifie chaque cycle
                 intra_random_edges=8,       # edges aléatoires intra-cluster par noeud (moyenne)
                 inter_ring_links=6,         # liens entre clusters pour créer cycles globaux
                 inter_random_edges=40,    # edges aléatoires inter-clusters
                 self_attacks=50):           # quelques auto-attaques
    """
    Génère un AF "dur" :
    - k clusters de taille ~n/k
    - dans chaque cluster: un grand cycle + chords + bruit aléatoire
    - entre clusters: connexions en anneau + connexions aléatoires (crée gros SCC)
    - optionnel: quelques self-attacks
    """
    random.seed(seed)

    args = [f"a{i}" for i in range(n)]
    clusters = []
    base = 0
    size = n // k
    for ci in range(k):
        # répartit le reste dans les derniers clusters
        end = base + size + (1 if ci < (n % k) else 0)
        clusters.append(list(range(base, end)))
        base = end

    attacks = set()

    # --- 1) Intra-cluster : cycle + chords
    for cl in clusters:
        m = len(cl)
        # cycle principal
        for j in range(m):
            u = cl[j]
            v = cl[(j + 1) % m]
            attacks.add((u, v))

        # chords réguliers : u -> u+2, u+3, ...
        for step in range(2, 2 + intra_cycle_chords):
            for j in range(m):
                u = cl[j]
                v = cl[(j + step) % m]
                attacks.add((u, v))

        # bruit aléatoire intra-cluster
        # ~ intra_random_edges * m attaques
        for _ in range(intra_random_edges * m):
            u = random.choice(cl)
            v = random.choice(cl)
            if u != v:
                attacks.add((u, v))

    # --- 2) Inter-cluster : anneau entre clusters (avec plusieurs liens) pour cycles globaux
    for ci in range(k):
        c1 = clusters[ci]
        c2 = clusters[(ci + 1) % k]
        for _ in range(inter_ring_links):
            u = random.choice(c1)
            v = random.choice(c2)
            attacks.add((u, v))
        # ajout inverse (rend le graphe encore plus fortement connexe)
        for _ in range(max(1, inter_ring_links // 2)):
            u = random.choice(c2)
            v = random.choice(c1)
            attacks.add((u, v))

    # --- 3) Inter-cluster : attaques aléatoires globales (compliquent stable/preferred)
    all_indices = list(range(n))
    for _ in range(inter_random_edges):
        u = random.choice(all_indices)
        v = random.choice(all_indices)
        if u != v:
            attacks.add((u, v))

    # --- 4) Quelques self-attacks (souvent casse des arguments)
    for _ in range(self_attacks):
        u = random.randrange(n)
        attacks.add((u, u))

    return args, attacks


def write_apx(filename, args, attacks):
    with open(filename, "w") as f:
        for a in args:
            f.write(f"arg({a}).\n")
        for (u, v) in sorted(attacks):
            f.write(f"att(a{u},a{v}).\n")

import sys
if __name__ == "__main__":
    args, attacks = make_hard_af(
        n=int(sys.argv[1]),
        k=10,
        seed=42,
        intra_cycle_chords=4,
        intra_random_edges=6,
        inter_ring_links=8,
        inter_random_edges=int(sys.argv[1]),
        self_attacks=80
    )
    out = f"hard_{sys.argv[1]}.apx"
    write_apx(out, args, attacks)
    print("OK ->", out, "| args:", len(args), "| attacks:", len(attacks))

