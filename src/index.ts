/**
 * MetaMesh Plugin: full-hash
 *
 * ============================================================================
 * PLUGIN MOUNT ARCHITECTURE - DO NOT MODIFY WITHOUT AUTHORIZATION
 * ============================================================================
 *
 * Each plugin container has exactly 3 mounts (2 for plugins without output):
 *
 *   1. /files              (READ-ONLY)  - Shared media files, read access only
 *   2. /cache              (READ-WRITE) - Plugin-specific cache folder
 *   3. /files/plugin/<id>  (READ-WRITE) - Plugin output folder (if needed)
 *
 * This plugin (full-hash) only requires mounts 1 and 2:
 *   - /files (RO) - to read entire files for hashing
 *   - /cache (RW) - to cache computed hashes in CSV files
 *
 * Cache Structure (one CSV per hash type):
 *   - /cache/index-cid_sha2-256.csv
 *   - /cache/index-cid_sha1.csv
 *   - /cache/index-cid_md5.csv
 *   - /cache/index-cid_crc32.csv
 *   - /cache/index-cid_sha3-256.csv
 *   - /cache/index-cid_sha3-384.csv
 *
 * Cache key format: filename-size-mtime (recomputes if file changes)
 *
 * Configuration:
 *   - enabledHashes: comma-separated list of hash types to compute
 *   - Default: all available hashes
 *
 * SECURITY: Plugins must NEVER write to /files directly.
 * All write operations go to /cache or /files/plugin/<id> only.
 *
 * ============================================================================
 */

import Fastify from 'fastify';
import type { HealthResponse, ProcessRequest, ProcessResponse, CallbackPayload, ConfigureRequest, ConfigureResponse } from './types.js';
import { manifest, process as processFile, configure } from './plugin.js';

const app = Fastify({ logger: true });
let ready = false;

app.get('/health', async (): Promise<HealthResponse> => ({ status: 'healthy', ready, version: manifest.version }));
app.get('/manifest', async () => manifest);
app.post<{ Body: ConfigureRequest }>('/configure', async (request): Promise<ConfigureResponse> => {
    try {
        configure(request.body.config);
        console.log(`[${manifest.id}] Configuration updated`);
        return { status: 'ok' };
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`[${manifest.id}] Configuration error:`, errorMessage);
        return { status: 'error', error: errorMessage };
    }
});
app.post<{ Body: ProcessRequest }>('/process', async (request, reply) => {
    const { taskId, cid, filePath, callbackUrl, metaCoreUrl } = request.body;
    if (!taskId || !cid || !filePath || !callbackUrl || !metaCoreUrl) {
        return reply.send({ status: 'rejected', error: 'Missing required fields' } as ProcessResponse);
    }
    processFile(request.body, async (payload: CallbackPayload) => {
        try { await fetch(callbackUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }); }
        catch (error) { console.error(`[${manifest.id}] Callback error:`, error); }
    }).catch(console.error);
    return reply.send({ status: 'accepted' } as ProcessResponse);
});

const port = parseInt(process.env.PORT || '8080', 10);
app.listen({ port, host: '0.0.0.0' }).then(() => { ready = true; console.log(`[${manifest.id}] Listening on port ${port}`); });
process.on('SIGTERM', async () => { ready = false; await app.close(); process.exit(0); });
