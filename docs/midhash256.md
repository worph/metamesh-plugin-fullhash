# MidHash256

## Purpose

O(1) file identification hash - constant time regardless of file size. Designed for quick duplicate detection and large file identification before expensive full-hash operations.

## Multicodec

- **Code**: `0x1000` (custom, not in official multicodec registry)
- **CID codec**: `0x55` (raw)
- **Output key**: `cid_midhash256`

## Algorithm

```
1. Read file size (S)
2. If S <= 1MB:
     sample = entire file content
3. If S > 1MB:
     seek to (S - 1MB) / 2
     sample = read 1MB from middle
4. Hash = SHA-256(S as u64 big-endian || sample)
```

### Pseudocode

```rust
fn midhash256(path: &Path) -> [u8; 32] {
    let size = file_size(path);
    let mut hasher = SHA256::new();

    // Always include size as 8-byte big-endian prefix
    hasher.update(size.to_be_bytes());

    if size <= 1_048_576 {
        // Small file: hash entire content
        hasher.update(read_all(path));
    } else {
        // Large file: hash middle 1MB
        let middle_start = (size - 1_048_576) / 2;
        hasher.update(read_at(path, middle_start, 1_048_576));
    }

    hasher.finalize()
}
```

## Properties

| Property | Value |
|----------|-------|
| Time complexity | O(1) for files > 1MB |
| Space complexity | O(1) - fixed 1MB buffer |
| Hash size | 32 bytes (SHA-256) |
| Collision resistance | Same as SHA-256 for middle content |

## Use Cases

1. **Quick duplicate detection** - Identify potential duplicates before computing full hashes
2. **Large file identification** - Identify terabyte files in ~20ms regardless of size
3. **Pre-filtering** - Filter candidates before expensive operations (full hash, content analysis)
4. **Change detection** - Quick check if middle content changed (useful for video files)

## Limitations

- Files differing only at edges (first/last 512KB for 2MB+ files) will have same midhash
- Not suitable as a standalone deduplication hash - use as pre-filter only
- Custom multicodec code may conflict with future official allocations

## CID Example

```
File: movie.mkv (4.7 GB)
MidHash256: 3a7b...c2d1 (32 bytes)
CID: bafkreibh4xvl5... (base32lower encoded CIDv1)
```

## Integration

The hash is computed separately from the standard single-pass algorithms since it requires seeking to the middle of the file. For files <= 1MB, it reads the entire file like other algorithms.
