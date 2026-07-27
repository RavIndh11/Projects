def generate_omission_permutations(domain: str) -> set[str]:
    """Generate permutations by omitting one character."""
    return {domain[:i] + domain[i+1:] for i in range(len(domain))}

def generate_repetition_permutations(domain: str) -> set[str]:
    """Generate permutations by repeating one character."""
    return {domain[:i] + domain[i] + domain[i:] for i in range(len(domain))}

def generate_transposition_permutations(domain: str) -> set[str]:
    """Generate permutations by swapping adjacent characters."""
    perms = set()
    for i in range(len(domain) - 1):
        perms.add(domain[:i] + domain[i+1] + domain[i] + domain[i+2:])
    return perms

def generate_substitution_permutations(domain: str) -> set[str]:
    """Generate permutations by substituting characters with visually similar or adjacent ones."""
    # A simple keyboard proximity map for QWERTY
    key_map = {
        'q': 'wa12', 'w': 'qesa23', 'e': 'wrsd34', 'r': 'etdf45', 't': 'ryfg56', 'y': 'tugh67',
        'u': 'yihj78', 'i': 'uojk89', 'o': 'ipkl90', 'p': 'ol0-',
        'a': 'qwsz', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb',
        'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
        'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
    }

    perms = set()
    for i, char in enumerate(domain):
        if char in key_map:
            for sub_char in key_map[char]:
                perms.add(domain[:i] + sub_char + domain[i+1:])
    return perms

def get_all_permutations(domain: str) -> set[str]:
    """
    Generate all possible permutations for a given base domain name.
    """
    perms = set()
    perms.update(generate_omission_permutations(domain))
    perms.update(generate_repetition_permutations(domain))
    perms.update(generate_transposition_permutations(domain))
    perms.update(generate_substitution_permutations(domain))

    # Remove the original domain if it was accidentally generated
    if domain in perms:
        perms.remove(domain)

    return perms
