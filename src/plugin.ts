/**
 * Full Hash Plugin
 *
 * Computes multiple hashes of the entire file with CSV-based caching.
 * Uses the same CID format as the meta-hash library.
 *
 * Available hashes (all enabled by default):
 * - cid_sha2-256: SHA-256 hash
 * - cid_sha1: SHA-1 hash
 * - cid_md5: MD5 hash
 * - cid_crc32: CRC32 checksum
 * - cid_sha3-256: SHA3-256 hash
 * - cid_sha3-384: SHA3-384 hash
 *
 * Note: midhash256 is NOT computed here - it's computed in-process for fast file ID.
 * Note: btih_v2 requires special handling (BitTorrent v2 merkle tree) - not implemented yet.
 *
 * Cache:
 * - Stores computed hashes in CSV files: /cache/index-{hashType}.csv
 * - Cache key is: filename-size-mtime (recomputes if file changes)
 */

import { createReadStream, promises as fs } from 'fs';
import { createHash, Hash } from 'crypto';
import { stat } from 'fs/promises';
import path from 'path';
import { parse } from 'csv-parse';
import { stringify } from 'csv-stringify/sync';
import CRC32 from 'crc-32';
import type { PluginManifest, ProcessRequest, CallbackPayload } from './types.js';
import { MetaCoreClient } from './meta-core-client.js';

// Cache folder path (mounted as /cache in container)
const CACHE_FOLDER_PATH = globalThis.process.env.CACHE_PATH || '/cache';

// Hash algorithm definitions
const HASH_ALGORITHMS = {
    'cid_sha2-256': { crypto: 'sha256', prefix: 'baejbei' },
    'cid_sha1': { crypto: 'sha1', prefix: 'baeir' },
    'cid_md5': { crypto: 'md5', prefix: 'bahkq' },
    'cid_crc32': { crypto: null, prefix: 'bagzafmq' }, // Special handling
    'cid_sha3-256': { crypto: 'sha3-256', prefix: 'baelb' },
    'cid_sha3-384': { crypto: 'sha3-384', prefix: 'baekr' },
} as const;

type HashAlgorithm = keyof typeof HASH_ALGORITHMS;

// All available hash types (default: all enabled)
const ALL_HASH_TYPES: HashAlgorithm[] = Object.keys(HASH_ALGORITHMS) as HashAlgorithm[];

// Plugin configuration (set via /configure endpoint)
let enabledHashes: HashAlgorithm[] = [...ALL_HASH_TYPES];

// Per-hash-type caches
const hashCaches: Map<HashAlgorithm, Map<string, string>> = new Map();
const cacheLoaded: Set<HashAlgorithm> = new Set();
const cacheChanges: Set<HashAlgorithm> = new Set();

/**
 * Get index file path for a hash type
 */
function getIndexPath(hashType: HashAlgorithm): string {
    return path.join(CACHE_FOLDER_PATH, `index-${hashType}.csv`);
}

/**
 * Load cache for a specific hash type
 */
async function loadHashCache(hashType: HashAlgorithm): Promise<void> {
    if (cacheLoaded.has(hashType)) return;

    try {
        await fs.mkdir(CACHE_FOLDER_PATH, { recursive: true });

        const indexPath = getIndexPath(hashType);
        const exists = await fs.access(indexPath).then(() => true).catch(() => false);

        if (!exists) {
            hashCaches.set(hashType, new Map());
            cacheLoaded.add(hashType);
            return;
        }

        const cache = new Map<string, string>();
        const records: Array<{ path: string; size: string; mtime: string; hash: string }> = await new Promise((resolve, reject) => {
            const results: Array<{ path: string; size: string; mtime: string; hash: string }> = [];
            createReadStream(indexPath)
                .pipe(parse({ columns: true, skip_empty_lines: true }))
                .on('data', (record) => results.push(record))
                .on('end', () => resolve(results))
                .on('error', reject);
        });

        for (const record of records) {
            const cacheKey = `${record.path}-${record.size}-${record.mtime}`;
            cache.set(cacheKey, record.hash);
        }

        hashCaches.set(hashType, cache);
        cacheLoaded.add(hashType);
        console.log(`[full-hash] Loaded ${cache.size} entries for ${hashType}`);
    } catch (error) {
        console.error(`[full-hash] Error loading cache for ${hashType}:`, error);
        hashCaches.set(hashType, new Map());
        cacheLoaded.add(hashType);
    }
}

/**
 * Save cache for a specific hash type
 */
async function saveHashCache(hashType: HashAlgorithm): Promise<void> {
    if (!cacheChanges.has(hashType)) return;

    try {
        const cache = hashCaches.get(hashType);
        if (!cache || cache.size === 0) return;

        const entries: Array<{ path: string; size: string; mtime: string; hash: string }> = [];
        for (const [key, hash] of cache.entries()) {
            const [filename, size, mtime] = key.split('-');
            // Handle filenames that might contain dashes
            const parts = key.split('-');
            const mtimeIdx = parts.findIndex(p => p.includes('T') && p.includes('Z'));
            if (mtimeIdx >= 2) {
                const filename = parts.slice(0, mtimeIdx - 1).join('-');
                const size = parts[mtimeIdx - 1];
                const mtime = parts.slice(mtimeIdx).join('-');
                entries.push({ path: filename, size, mtime, hash });
            }
        }

        const csvString = stringify(entries, {
            header: true,
            columns: ['path', 'size', 'mtime', 'hash'],
        });

        await fs.writeFile(getIndexPath(hashType), csvString);
        cacheChanges.delete(hashType);
        console.log(`[full-hash] Saved ${entries.length} entries for ${hashType}`);
    } catch (error) {
        console.error(`[full-hash] Error saving cache for ${hashType}:`, error);
    }
}

/**
 * Get cached hash value
 */
function getCachedHash(hashType: HashAlgorithm, filename: string, size: number, mtime: string): string | null {
    const cache = hashCaches.get(hashType);
    if (!cache) return null;
    const cacheKey = `${filename}-${size}-${mtime}`;
    return cache.get(cacheKey) || null;
}

/**
 * Add hash to cache
 */
function addToCache(hashType: HashAlgorithm, filename: string, size: number, mtime: string, hash: string): void {
    let cache = hashCaches.get(hashType);
    if (!cache) {
        cache = new Map();
        hashCaches.set(hashType, cache);
    }
    const cacheKey = `${filename}-${size}-${mtime}`;
    cache.set(cacheKey, hash);
    cacheChanges.add(hashType);
}

/**
 * Encode bytes to base32 (RFC 4648, lowercase, no padding)
 */
function base32Encode(buffer: Buffer): string {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    let result = '';
    let bits = 0;
    let value = 0;

    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            result += alphabet[(value >> bits) & 0x1f];
        }
    }

    if (bits > 0) {
        result += alphabet[(value << (5 - bits)) & 0x1f];
    }

    return result;
}

/**
 * Format hash as CID with appropriate prefix
 */
function formatAsCid(hashType: HashAlgorithm, hashHex: string): string {
    const { prefix } = HASH_ALGORITHMS[hashType];
    const hashBuffer = Buffer.from(hashHex, 'hex');
    const base32Hash = base32Encode(hashBuffer);
    return `${prefix}${base32Hash}`;
}

/**
 * Compute all hashes for a file in a single pass
 */
async function computeHashes(filePath: string, hashTypes: HashAlgorithm[]): Promise<Map<HashAlgorithm, string>> {
    return new Promise((resolve, reject) => {
        const results = new Map<HashAlgorithm, string>();
        const hashers: Map<HashAlgorithm, Hash> = new Map();
        let crc32Value = 0;
        const needsCrc32 = hashTypes.includes('cid_crc32');

        // Initialize crypto hashers
        for (const hashType of hashTypes) {
            const algo = HASH_ALGORITHMS[hashType];
            if (algo.crypto) {
                try {
                    hashers.set(hashType, createHash(algo.crypto));
                } catch (e) {
                    console.warn(`[full-hash] Hash algorithm ${algo.crypto} not available, skipping ${hashType}`);
                }
            }
        }

        const stream = createReadStream(filePath);

        stream.on('data', (chunk: Buffer | string) => {
            const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            // Update all crypto hashers
            for (const [, hasher] of hashers) {
                hasher.update(data);
            }
            // Update CRC32
            if (needsCrc32) {
                crc32Value = CRC32.buf(data, crc32Value);
            }
        });

        stream.on('end', () => {
            // Finalize crypto hashes
            for (const [hashType, hasher] of hashers) {
                const hexHash = hasher.digest('hex');
                const cid = formatAsCid(hashType, hexHash);
                results.set(hashType, cid);
            }
            // Finalize CRC32
            if (needsCrc32) {
                // Convert to unsigned 32-bit and then to hex
                const unsigned = crc32Value >>> 0;
                const hexHash = unsigned.toString(16).padStart(8, '0');
                const cid = formatAsCid('cid_crc32', hexHash);
                results.set('cid_crc32', cid);
            }
            resolve(results);
        });

        stream.on('error', reject);
    });
}

export const manifest: PluginManifest = {
    id: 'full-hash',
    name: 'Full File Hash',
    version: '1.0.0',
    description: 'Computes multiple hashes (SHA-256, SHA-1, MD5, CRC32, SHA3) with CSV caching',
    author: 'MetaMesh',
    dependencies: [],
    priority: 100,
    color: '#9C27B0',
    defaultQueue: 'background',
    timeout: 300000, // 5 minutes for large files
    schema: {
        'cid_sha2-256': {
            label: 'SHA-256 Hash',
            type: 'cid',
            readonly: true,
            hint: 'SHA-256 hash in CID format',
        },
        'cid_sha1': {
            label: 'SHA-1 Hash',
            type: 'cid',
            readonly: true,
            hint: 'SHA-1 hash in CID format',
        },
        'cid_md5': {
            label: 'MD5 Hash',
            type: 'cid',
            readonly: true,
            hint: 'MD5 hash in CID format',
        },
        'cid_crc32': {
            label: 'CRC32 Checksum',
            type: 'cid',
            readonly: true,
            hint: 'CRC32 checksum in CID format',
        },
        'cid_sha3-256': {
            label: 'SHA3-256 Hash',
            type: 'cid',
            readonly: true,
            hint: 'SHA3-256 hash in CID format',
        },
        'cid_sha3-384': {
            label: 'SHA3-384 Hash',
            type: 'cid',
            readonly: true,
            hint: 'SHA3-384 hash in CID format',
        },
    },
    config: {
        enabledHashes: {
            type: 'string',
            label: 'Enabled hash algorithms (comma-separated)',
            default: 'cid_sha2-256,cid_sha1,cid_md5,cid_crc32,cid_sha3-256,cid_sha3-384',
            required: false,
        },
    },
};

/**
 * Configure which hashes to compute
 */
export function configure(config: Record<string, unknown>): void {
    if (config.enabledHashes && typeof config.enabledHashes === 'string') {
        const requested = config.enabledHashes.split(',').map(s => s.trim()) as HashAlgorithm[];
        enabledHashes = requested.filter(h => h in HASH_ALGORITHMS);
        console.log(`[full-hash] Enabled hashes: ${enabledHashes.join(', ')}`);
    }
}

export async function process(
    request: ProcessRequest,
    sendCallback: (payload: CallbackPayload) => Promise<void>
): Promise<void> {
    const startTime = Date.now();
    const metaCore = new MetaCoreClient(request.metaCoreUrl);

    try {
        const { cid, filePath, existingMeta } = request;

        // Determine which hashes need to be computed
        const hashesToCompute: HashAlgorithm[] = [];
        const hashesFromCache: Map<HashAlgorithm, string> = new Map();

        // Get file stats for cache lookup
        const stats = await stat(filePath);
        const filename = path.basename(filePath);
        const mtime = stats.mtime.toISOString();

        // Load caches and check what's needed
        for (const hashType of enabledHashes) {
            // Skip if already in metadata
            if (existingMeta?.[hashType]) {
                continue;
            }

            // Load cache for this hash type
            await loadHashCache(hashType);

            // Check cache
            const cachedHash = getCachedHash(hashType, filename, stats.size, mtime);
            if (cachedHash) {
                hashesFromCache.set(hashType, cachedHash);
            } else {
                hashesToCompute.push(hashType);
            }
        }

        // Skip if nothing to do
        if (hashesToCompute.length === 0 && hashesFromCache.size === 0) {
            console.log(`[full-hash] All hashes already computed for ${filePath}, skipping`);
            await sendCallback({
                taskId: request.taskId,
                status: 'skipped',
                duration: Date.now() - startTime,
                reason: 'All hashes already computed',
            });
            return;
        }

        // Compute missing hashes
        let computedHashes = new Map<HashAlgorithm, string>();
        if (hashesToCompute.length > 0) {
            console.log(`[full-hash] Computing ${hashesToCompute.length} hashes for ${filePath}`);
            computedHashes = await computeHashes(filePath, hashesToCompute);

            // Add computed hashes to cache
            for (const [hashType, hash] of computedHashes) {
                addToCache(hashType, filename, stats.size, mtime, hash);
            }

            // Save updated caches
            for (const hashType of hashesToCompute) {
                await saveHashCache(hashType);
            }
        }

        // Merge cached and computed hashes
        const allHashes = new Map([...hashesFromCache, ...computedHashes]);

        // Store all hashes to meta-core
        for (const [hashType, hash] of allHashes) {
            await metaCore.setProperty(cid, hashType, hash);
        }

        const cacheHits = hashesFromCache.size;
        const computed = computedHashes.size;
        console.log(`[full-hash] Stored ${allHashes.size} hashes (${cacheHits} cached, ${computed} computed)`);

        await sendCallback({
            taskId: request.taskId,
            status: 'completed',
            duration: Date.now() - startTime,
        });
    } catch (error) {
        const duration = Date.now() - startTime;
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`[full-hash] Error computing hashes for ${request.filePath}:`, errorMessage);

        await sendCallback({
            taskId: request.taskId,
            status: 'failed',
            duration,
            error: errorMessage,
        });
    }
}
