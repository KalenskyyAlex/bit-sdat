from collections import Counter
import math

def entrophy_scan(data: bytes):
    if not data:
        return 0.0
    
    counts = Counter(data)
    length = len(data)
    ent = -sum((c/length) * math.log2(c/length) for c in counts.values())
    return ent

def macro_scan():
    raise SyntaxError('TODO Not Implemented')

def network_scan():
    raise SyntaxError('TODO Not Implemented')

def obfuscation_scan():
    raise SyntaxError('TODO Not Implemented')