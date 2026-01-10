/**
 * Full Hash Plugin
 * Computes SHA-256 hash of the entire file
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
            await sendCallback({
                taskId: request.taskId,
                status: 'skipped',
                duration: Date.now() - startTime,
                reason: 'Already computed',
            });
            return;
        }

        console.log(`[full-hash] Computing SHA-256 for ${filePath}`);
        const sha256 = await computeSHA256(filePath);

        // Format as CID-like string
        const sha256Cid = `sha256-${sha256}`;

        await metaCore.setProperty(cid, 'cid_sha2-256', sha256Cid);

        const duration = Date.now() - startTime;
        console.log(`[full-hash] Computed in ${duration}ms: ${sha256Cid.substring(0, 20)}...`);

        await sendCallback({
            taskId: request.taskId,
            status: 'completed',
            duration,
        });
    } catch (error) {
        const duration = Date.now() - startTime;
        await sendCallback({
            taskId: request.taskId,
            status: 'failed',
            duration,
            error: error instanceof Error ? error.message : String(error),
        });
    }
}
