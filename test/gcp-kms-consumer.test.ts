import { it } from 'vitest';
import { gcpConsumer } from './helpers/gcp-consumer.ts';

it('Given deployment A and independent publication A, When composing actual GCP and SDK, Then public HTTP verifies, tampering and B binding reject, and local lifecycle preserves consumer A', () => gcpConsumer());

it('Given existing default deployment settings, When exercising unchanged composition and local lifecycle, Then real publication and consumer verification succeed', () => gcpConsumer('existing'));
