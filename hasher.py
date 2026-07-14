"""
hasher.py
Computes MD5, SHA1, and SHA256 hashes for a given file.
Reads in chunks so it doesn't choke on large files.
"""

import hashlib
import os


def hash_file(filepath: str) -> dict:
    """
    Given a path to a file, return a dict with md5, sha1, sha256, and size.
    Raises FileNotFoundError if the path doesn't exist.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"No such file: {filepath}")

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    size = 0
    chunk_size = 65536  # 64KB chunks - avoids loading huge files fully into memory

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)

    return {
        "filepath": filepath,
        "size_bytes": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def is_hash(value: str) -> bool:
    """
    Check if a string looks like a hash (hex-only, correct length for md5/sha1/sha256).
    Used by the main script to auto-detect whether input is a filepath or a raw hash.
    """
    value = value.strip()
    if not all(c in "0123456789abcdefABCDEF" for c in value):
        return False
    return len(value) in (32, 40, 64)  # md5=32, sha1=40, sha256=64


if __name__ == "__main__":
    # Quick manual test - run this file directly with a path argument
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 hasher.py <filepath>")
        sys.exit(1)

    result = hash_file(sys.argv[1])
    for k, v in result.items():
        print(f"{k}: {v}")
