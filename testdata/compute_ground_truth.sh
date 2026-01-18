#!/bin/bash
# Compute ground truth hash values for test reference files
# Uses standard Unix tools to verify our implementation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Reference file: Sintel trailer (Creative Commons licensed)
# Source: https://durian.blender.org/
REFERENCE_URL="https://download.blender.org/durian/trailer/sintel_trailer-480p.mp4"
REFERENCE_FILE="sintel_trailer-480p.mp4"
EXPECTED_SIZE=23014356  # bytes

echo "=== Ground Truth Hash Computation ==="
echo ""

# Download reference file if not present
if [ ! -f "$REFERENCE_FILE" ]; then
    echo "Downloading reference file: $REFERENCE_FILE"
    curl -L -o "$REFERENCE_FILE" "$REFERENCE_URL"
fi

# Verify file size
ACTUAL_SIZE=$(stat -f%z "$REFERENCE_FILE" 2>/dev/null || stat -c%s "$REFERENCE_FILE" 2>/dev/null)
if [ "$ACTUAL_SIZE" != "$EXPECTED_SIZE" ]; then
    echo "WARNING: File size mismatch! Expected $EXPECTED_SIZE, got $ACTUAL_SIZE"
    echo "The file may have changed. Please verify manually."
fi

echo "Reference file: $REFERENCE_FILE"
echo "File size: $ACTUAL_SIZE bytes"
echo ""

echo "=== Computing Standard Hashes ==="
echo ""

# SHA-256
echo -n "SHA-256: "
sha256sum "$REFERENCE_FILE" | cut -d' ' -f1

# SHA-1
echo -n "SHA-1: "
sha1sum "$REFERENCE_FILE" | cut -d' ' -f1

# MD5
echo -n "MD5: "
md5sum "$REFERENCE_FILE" | cut -d' ' -f1

# CRC32 (using Python as crc32 tool varies)
echo -n "CRC32: "
python3 -c "
import binascii
with open('$REFERENCE_FILE', 'rb') as f:
    crc = 0
    while chunk := f.read(65536):
        crc = binascii.crc32(chunk, crc)
    print(format(crc & 0xffffffff, '08x'))
"

# SHA3-256 (using openssl if available, otherwise Python)
echo -n "SHA3-256: "
if command -v openssl &> /dev/null && openssl dgst -sha3-256 /dev/null &> /dev/null 2>&1; then
    openssl dgst -sha3-256 "$REFERENCE_FILE" | awk '{print $2}'
else
    python3 -c "
import hashlib
with open('$REFERENCE_FILE', 'rb') as f:
    h = hashlib.sha3_256()
    while chunk := f.read(65536):
        h.update(chunk)
    print(h.hexdigest())
"
fi

# SHA3-384
echo -n "SHA3-384: "
if command -v openssl &> /dev/null && openssl dgst -sha3-384 /dev/null &> /dev/null 2>&1; then
    openssl dgst -sha3-384 "$REFERENCE_FILE" | awk '{print $2}'
else
    python3 -c "
import hashlib
with open('$REFERENCE_FILE', 'rb') as f:
    h = hashlib.sha3_384()
    while chunk := f.read(65536):
        h.update(chunk)
    print(h.hexdigest())
"
fi

echo ""
echo "=== Computing MidHash256 ==="
echo ""

# MidHash256: SHA-256(size_u64_be || middle_1MB)
python3 << 'PYTHON_EOF'
import hashlib
import struct
import os

filename = 'sintel_trailer-480p.mp4'
size = os.path.getsize(filename)
THRESHOLD = 1024 * 1024  # 1MB

with open(filename, 'rb') as f:
    hasher = hashlib.sha256()
    # Add size as 8-byte big-endian
    hasher.update(struct.pack('>Q', size))

    if size <= THRESHOLD:
        # Small file: hash entire content
        hasher.update(f.read())
    else:
        # Large file: hash middle 1MB
        middle_start = (size - THRESHOLD) // 2
        f.seek(middle_start)
        hasher.update(f.read(THRESHOLD))

    print(f"MidHash256: {hasher.hexdigest()}")
PYTHON_EOF

echo ""
echo "=== Computing BitTorrent v2 Hashes ==="
echo ""

# BitTorrent v2 pieces root and info hash
python3 << 'PYTHON_EOF'
import hashlib
import os

filename = 'sintel_trailer-480p.mp4'
BLOCK_SIZE = 16 * 1024  # 16 KiB

def compute_leaf_hashes(filepath):
    """Compute SHA-256 hash of each 16KB block"""
    leaves = []
    size = os.path.getsize(filepath)

    if size == 0:
        return [bytes(32)]

    with open(filepath, 'rb') as f:
        while True:
            block = f.read(BLOCK_SIZE)
            if not block:
                break
            # Pad last block with zeros
            if len(block) < BLOCK_SIZE:
                block = block + bytes(BLOCK_SIZE - len(block))
            leaves.append(hashlib.sha256(block).digest())

    return leaves

def compute_merkle_root(leaves):
    """Compute merkle root from leaf hashes"""
    if not leaves:
        return bytes(32)
    if len(leaves) == 1:
        return leaves[0]

    # Pad to power of 2
    target = 1
    while target < len(leaves):
        target *= 2

    current = list(leaves)
    while len(current) < target:
        current.append(bytes(32))

    # Build tree bottom-up
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            combined = current[i] + current[i+1]
            next_level.append(hashlib.sha256(combined).digest())
        current = next_level

    return current[0]

def bencode_int(i):
    return f'i{i}e'.encode()

def bencode_str(s):
    if isinstance(s, str):
        s = s.encode()
    return f'{len(s)}:'.encode() + s

def bencode_dict(d):
    result = b'd'
    for k in sorted(d.keys()):
        result += bencode_str(k)
        v = d[k]
        if isinstance(v, int):
            result += bencode_int(v)
        elif isinstance(v, (str, bytes)):
            result += bencode_str(v)
        elif isinstance(v, dict):
            result += bencode_dict(v)
    result += b'e'
    return result

# Compute pieces root
leaves = compute_leaf_hashes(filename)
pieces_root = compute_merkle_root(leaves)
print(f"BT Pieces Root: {pieces_root.hex()}")

# Compute info hash
size = os.path.getsize(filename)
basename = os.path.basename(filename)

# Build info dict as per BEP 52
info_dict = {
    'file tree': {
        basename: {
            '': {
                'length': size,
                'pieces root': pieces_root
            }
        }
    },
    'meta version': 2,
    'name': basename,
    'piece length': BLOCK_SIZE
}

encoded = bencode_dict(info_dict)
info_hash = hashlib.sha256(encoded).digest()
print(f"BT Info Hash: {info_hash.hex()}")

# Magnet link
print(f"Magnet: magnet:?xt=urn:btmh:1220{info_hash.hex()}&dn={basename}")
PYTHON_EOF

echo ""
echo "=== Summary ==="
echo "Copy these values to tests/ground_truth.rs"
