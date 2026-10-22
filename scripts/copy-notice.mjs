import { copyFileSync } from 'node:fs';

// npm runs prepack in the workspace; keep the published notice in sync with the root.
copyFileSync(new URL('../NOTICE.txt', import.meta.url), 'NOTICE.txt');
