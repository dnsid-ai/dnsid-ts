// Deliberately named imports, loaded through the same Vite path as providers.
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';

export const namedGeneration = () => generateKeyPairSync('ed25519');
export const namedWrite = (file: string) => writeFileSync(file, 'custody canary');
export const namedAsyncWrite = (file: string) => writeFile(file, 'custody canary');
