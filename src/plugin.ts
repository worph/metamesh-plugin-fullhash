/**
 * Full Hash Plugin
 *
 * Computes the SHA-256 hash of the entire file.
 * This is a background queue plugin - it's slow but provides
 * definitive content identification.
 *
 * Output:
 * - cid_sha2-256: SHA-256 hash formatted as CID
 */

import { createReadStream } from 'fs';
import { createHash } from 'crypto';
import type { PluginManifest, ProcessRequest, CallbackPayload } from './types.js';
import { MetaCoreClient } from './meta-core-client.js';

export const manifest: PluginManifest = {
    id: 'full-hash',
    name: 'Full File Hash',
    version: '1.0.0',
    description: 'Computes SHA-256 hash of the entire file for content identification',
    author: 'MetaMesh',
    dependencies: [],
    priority: 100,
    color: '#9C27B0',
    defaultQueue: 'background',
    timeout: 300000, // 5 minutes for large files
    schema: {
        'cid_sha2-256': {
            label: 'SHA-256 Hash (CID)',
            type: 'cid',
            readonly: true,
            hint: 'Content identifier using SHA-256 hash of the entire file',
        },
    },
    config: {},
};

/**
 * Compute SHA-256 hash of a file using streaming
 */
async function computeSHA256(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const hash = createHash('sha256');
        const stream = createReadStream(filePath);
        stream.on('data', (data) => hash.update(data));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
    });
}

export async function process(
    request: ProcessRequest,
    sendCallback: (payload: CallbackPayload) => Promise<void>
): Promise<void> {
    const startTime = Date.now();
    const metaCore = new MetaCoreClient(request.metaCoreUrl);

    try {
        const { cid, filePath, existingMeta } = request;

        // Skip if already computed
        if (existingMeta?.['cid_sha2-256']) {
            console.log(`[full-hash] SHA-256 already computed for ${filePath}, skipping`);
            await sendCallback({
                taskId: request.taskId,
                status: 'skipped',
                duration: Date.now() - startTime,
                reason: 'Already computed',
            });
            return;
        }

        console.log(`[full-hash] Computing SHA-256 hash for ${filePath}`);

        // Compute SHA-256 hash
        const sha256Hex = await computeSHA256(filePath);

        // Format as CID-like string (matching old format)
        const sha256Cid = `sha256-${sha256Hex}`;

        await metaCore.setProperty(cid, 'cid_sha2-256', sha256Cid);
        console.log(`[full-hash] SHA-256 computed: ${sha256Cid.substring(0, 20)}...`);

        const duration = Date.now() - startTime;

        await sendCallback({
            taskId: request.taskId,
            status: 'completed',
            duration,
        });
    } catch (error) {
        const duration = Date.now() - startTime;
        const errorMessage = error instanceof Error ? error.message : String(error);
        console.error(`[full-hash] Error computing SHA-256 hash for ${request.filePath}:`, errorMessage);

        await sendCallback({
            taskId: request.taskId,
            status: 'failed',
            duration,
            error: errorMessage,
        });
    }
}
