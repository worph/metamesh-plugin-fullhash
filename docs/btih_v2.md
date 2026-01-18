# BitTorrent v2 Hashes (BEP 52)

## Purpose

Generate BitTorrent v2 compatible hashes for magnet links and peer verification. Enables creating magnet links for files without a full .torrent file.

## Two Output Hashes

### 1. Pieces Root (`cid_bt_pieces_root`)

- **Multicodec**: `0xb702` (**official** `bittorrent-pieces-root`)
- **CID codec**: `0x55` (raw)
- **Description**: Merkle tree root of SHA-256 hashes of 16KB file blocks
- **Use case**: File verification, piece-level integrity checking

### 2. Info Hash (`cid_bt_info_hash`)

- **Multicodec**: `0x12` (standard SHA-256)
- **CID codec**: `0x55` (raw)
- **Description**: SHA-256 of bencoded info dictionary
- **Use case**: Magnet links, torrent identification

## Algorithm

```
1. Read file in 16KB blocks
2. SHA-256 hash each block (pad last block with zeros)
3. Build merkle tree from leaf hashes:
   - Pad to next power of 2 with zero hashes
   - Each parent = SHA-256(left_child || right_child)
   → Result: pieces_root (32 bytes)

4. Create info dictionary:
   {
     "file tree": { filename: { "": { "length": N, "pieces root": <pieces_root> } } },
     "meta version": 2,
     "name": filename,
     "piece length": 16384
   }

5. Bencode the dictionary
6. SHA-256(bencoded_info)
   → Result: info_hash (32 bytes)
```

### Merkle Tree Structure

```
                    [Root]
                   /      \
            [Node]          [Node]
           /      \        /      \
        [Leaf0] [Leaf1] [Leaf2] [Zero]

Leaf = SHA-256(16KB block)
Node = SHA-256(left || right)
```

## Magnet Link Generation

```
magnet:?xt=urn:btmh:1220<info_hash_hex>&dn=<filename>
```

Where:
- `btmh` = BitTorrent Multihash
- `1220` = `0x12` (SHA-256 code) + `0x20` (32 bytes = 0x20 in hex)
- `info_hash_hex` = 64 hex characters
- `dn` = display name (URL-encoded filename)

### Example

```
File: ubuntu-24.04-desktop-amd64.iso
Info Hash: a1b2c3d4...
Magnet: magnet:?xt=urn:btmh:1220a1b2c3d4...&dn=ubuntu-24.04-desktop-amd64.iso
```

## BEP 52 Compliance

This implementation follows [BEP 52](https://www.bittorrent.org/beps/bep_0052.html):

| Requirement | Implementation |
|-------------|----------------|
| Block size | 16 KiB (16,384 bytes) |
| Piece size | 16 KiB (minimum, power of 2) |
| Hash algorithm | SHA-256 |
| Merkle tree | Binary, power-of-2 padded |
| Info dict | v2 format with `file tree` |
| Meta version | 2 (v2-only torrent) |

## Properties

| Property | Pieces Root | Info Hash |
|----------|-------------|-----------|
| Hash size | 32 bytes | 32 bytes |
| Algorithm | Merkle SHA-256 | SHA-256 |
| Multicodec | 0xb702 (official) | 0x12 (SHA-256) |
| Time complexity | O(n) | O(n) |
| Space complexity | O(log n) | O(1) |

## Use Cases

1. **Magnet link creation** - Share files via magnet links without .torrent files
2. **Peer verification** - Verify file integrity in BitTorrent v2 swarms
3. **Deduplication** - Identify identical files across BitTorrent network
4. **Hybrid torrents** - Create v1+v2 hybrid torrents

## Limitations

- Pieces root depends on filename (included in info dict)
- Single-file torrents only (no multi-file directory support)
- Requires full file read for both hashes

## References

- [BEP 52: The BitTorrent Protocol Specification v2](https://www.bittorrent.org/beps/bep_0052.html)
- [Multicodec Table](https://github.com/multiformats/multicodec/blob/master/table.csv) - `bittorrent-pieces-root` = 0xb702
