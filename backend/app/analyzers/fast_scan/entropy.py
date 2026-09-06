"""Shannon entropy of a bounded sample, quick first-pass signal (M2).

IMPORTANT: this is *sample* entropy - it reflects only the first few KB that were
read, NOT the whole file. A file can have low-entropy headers and a compressed/
encrypted region further in. It is recorded as *evidence*, never as a verdict. The
analyzer emits it as `entropy_sample` and carries `entropy_sample_size` alongside.
"""

import math


def shannon_entropy(data: bytes) -> float:
    """Entropy in bits/byte (0..8). Empty input => 0."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h
