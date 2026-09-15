import type { AgentExecutor, ExecutionEventBus, RequestContext } from '@a2a-js/sdk/server';
import { AgentEvent } from '@a2a-js/sdk/server';
import { A2A_PROTOCOL_VERSION, Role } from '@a2a-js/sdk';
import type { AgentCard, Message, Part, SendMessageResult } from '@a2a-js/sdk';

export const DNSID_A2A_EXTENSION_URI =
  'https://example-provider.example/a2a/extensions/dnsid-http-message-signatures/v1';
export const DNSID_A2A_SIGNATURE_TAG = 'a2a-dnsid-http-sig-v1';
export const A2A_VERSION = A2A_PROTOCOL_VERSION;

export function buildAgentCard(id: string, url: string, providerUrl: string): AgentCard {
  return {
    name: 'Example DNSid Echo Agent',
    description: 'A minimal A2A agent that echoes text input and requires DNSid-bound HTTP Message Signatures.',
    version: '0.2.0',
    supportedInterfaces: [
      {
        url,
        protocolBinding: 'JSONRPC',
        protocolVersion: A2A_VERSION,
        tenant: '',
      },
    ],
    provider: {
      organization: 'Example Provider',
      url: providerUrl,
    },
    documentationUrl: `${providerUrl.replace(/\/$/, '')}/docs/echo-agent`,
    capabilities: {
      streaming: false,
      pushNotifications: false,
      extensions: [
        {
          uri: DNSID_A2A_EXTENSION_URI,
          description: 'Requires DNSid validation and RFC 9421 HTTP Message Signatures for inbound requests.',
          required: true,
          params: {
            dnsidSubject: 'selected-interface-host',
            runtimeProof: 'http-message-signature',
            signatureInputHeader: 'Signature-Input',
            signatureHeader: 'Signature',
            requiredSignatureTag: DNSID_A2A_SIGNATURE_TAG,
            keyidSyntax: '<caller-dnsid-subject>#<jwks-kid>',
            keyResolution: 'dnsid-ku-jwks',
            requiredCoveredComponents: [
              '@method',
              '@target-uri',
              'content-type',
              'content-digest',
              'a2a-version',
              'a2a-extensions',
            ],
            requiredSignatureParameters: ['keyid', 'alg', 'created', 'expires', 'nonce', 'tag'],
            contentDigest: 'sha-256-required',
            statusCheck: 'dnsid-su-active-required',
            providerPolicy: 'provider-url-host-must-equal-or-be-subdomain-of-gi',
            mtls: 'not-used-in-this-example-first-release-sdk-defers-fl-mtls',
          },
        },
      ],
    },
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [
      {
        id: 'echo',
        name: 'Echo',
        description: 'Returns the input text unchanged.',
        tags: ['echo', 'test', 'diagnostic'],
        examples: ['Echo: hello world', 'Return this exact text: ping'],
        inputModes: ['text/plain'],
        outputModes: ['text/plain'],
        securityRequirements: [{ schemes: { dnsidHttpSignatures: { list: [] } } }],
      },
    ],
    securitySchemes: {
      dnsidHttpSignatures: {
        scheme: {
          $case: 'apiKeySecurityScheme',
          value: {
            description: 'DNSid-bound RFC 9421 HTTP Message Signatures using Signature-Input and Signature headers.',
            location: 'header',
            name: 'Signature',
          },
        },
      },
    },
    securityRequirements: [{ schemes: { dnsidHttpSignatures: { list: [] } } }],
    signatures: [],
  };
}

export function echoExecutor(agentId: string): AgentExecutor {
  return {
    execute: async (ctx: RequestContext, eventBus: ExecutionEventBus): Promise<void> => {
      const text = textFromMessage(ctx.userMessage);
      const senderId = ctx.context?.user?.userName ?? 'unknown';
      console.log(`[${agentId}] handling message from verified sender ${senderId}: "${text}"`);

      const replyText = `[from: ${agentId}; verified sender: ${senderId}] ${text}`;
      console.log(`[${agentId}] sending response to ${senderId}: "${replyText}"`);

      eventBus.publish(AgentEvent.message(textAgentMessage(replyText, ctx.contextId)));
      eventBus.finished();
    },
    cancelTask: async (_taskId: string, eventBus: ExecutionEventBus): Promise<void> => {
      eventBus.finished();
    },
  };
}

export function textUserMessage(text: string): Message {
  return textMessage(text, Role.ROLE_USER, '');
}

export function textAgentMessage(text: string, contextId: string): Message {
  return textMessage(text, Role.ROLE_AGENT, contextId);
}

export function messageText(result: SendMessageResult): string {
  return textFromMessage(result as Message);
}

function textMessage(text: string, role: Role, contextId: string): Message {
  return {
    messageId: crypto.randomUUID(),
    contextId,
    taskId: '',
    role,
    parts: [textPart(text)],
    metadata: undefined,
    extensions: [],
    referenceTaskIds: [],
  };
}

function textFromMessage(message: Message): string {
  if (!Array.isArray(message.parts)) return '';
  return message.parts
    .filter((p): p is Part & { content: { $case: 'text'; value: string } } => p.content?.$case === 'text')
    .map(p => p.content.value)
    .join('');
}

function textPart(text: string): Part {
  return {
    content: { $case: 'text', value: text },
    metadata: undefined,
    filename: '',
    mediaType: 'text/plain',
  };
}
