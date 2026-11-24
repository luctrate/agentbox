// Trusted host adapter. No daemon endpoint, module path or permission behavior
// comes from the container. Kept separate from the general Paseo permission CLI.
import { readFile, realpath } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { homedir } from 'node:os';

function deny(message) { throw Object.assign(new Error(message), { denied: true }); }
function object(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function questionData(request) {
  if (request.kind !== 'question' || !['AskUserQuestion', 'request_user_input'].includes(request.name)) return null;
  const questions = request.input?.questions;
  if (!Array.isArray(questions) || !questions.length || questions.length > 20) deny('Unsupported question format');
  const keys = new Set();
  return questions.map(q => {
    const key = request.name === 'AskUserQuestion' ? q.question : q.header;
    if (typeof key !== 'string' || !key.trim() || keys.has(key) || ['__proto__', 'constructor', 'prototype'].includes(key)) deny('Unsupported question keys');
    keys.add(key);
    return { key, question: q.question, options: q.options ?? [], multiSelect: q.multiSelect === true };
  });
}

export async function perform(client, input) {
  const fetched = await client.fetchAgent({ agentId: input.id });
  const agent = fetched?.agent;
  // Revalidate on the same connection used to deliver the response.
  if (!agent || agent.id !== input.id || agent.archivedAt != null) deny('Worker is missing or archived');
  if (agent.labels?.['paseo.parent-agent-id'] !== input.owner || agent.provider !== input.provider ||
      typeof agent.cwd !== 'string' || await realpath(agent.cwd) !== input.cwd) deny('Worker identity changed');
  const pending = agent.pendingPermissions ?? [];
  if (!Array.isArray(pending)) deny('Invalid pending requests');
  if (input.operation === 'questions') {
    return { agentId: input.id, questions: pending.filter(p => p.kind === 'question' &&
      ['AskUserQuestion', 'request_user_input'].includes(p.name)).map(p => ({
        requestId: p.id, tool: p.name, questions: questionData(p),
      })), blockedPermissions: pending.filter(p => p.kind !== 'question' ||
        !['AskUserQuestion', 'request_user_input'].includes(p.name)).map(p => ({ id: p.id, tool: p.name })) };
  }
  if (input.operation === 'send') {
    if (pending.length) deny('Worker has pending requests; use questions/answer or request human review');
    const receipt = await client.sendAgentMessage(input.id, input.message, {
      sourceAgentId: input.owner, activeTurnBehavior: 'steer',
    });
    return { agentId: input.id, status: receipt.deliveryStatus ?? 'sent' };
  }
  if (input.operation !== 'answer') deny('Unsupported operation');
  // Exact IDs only. Never use the permit CLI's prefix matching or allow-all.
  const request = pending.find(p => p.id === input.questionId);
  if (!request) deny('Question is no longer pending');
  const questions = questionData(request);
  if (!questions) deny('Only clarification questions can be answered');
  if (!object(input.answers) || Object.keys(input.answers).length !== questions.length) deny('Answer every question using its exact key');
  const answers = Object.create(null);
  for (const q of questions) {
    const value = input.answers[q.key];
    if (typeof value !== 'string' || !value.trim() || value.length > 50000 || value.includes('\0')) deny('Invalid answer');
    answers[q.key] = value;
  }
  // Original question input is retained; caller can supply answer strings only.
  await client.respondToPermissionAndWait(input.id, request.id, {
    behavior: 'allow', updatedInput: { ...request.input, answers },
  });
  return { agentId: input.id, questionId: request.id, status: 'answered' };
}

async function main() {
  let body = '';
  for await (const chunk of process.stdin) body += chunk;
  const input = JSON.parse(body);
  // Resolve the trusted binary's own package; never import project node_modules.
  let directory = dirname(await realpath(process.argv[2]));
  while (true) {
    try {
      const pkg = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'));
      if (pkg.name === '@getpaseo/cli') break;
    } catch {}
    const parent = dirname(directory);
    if (parent === directory) throw new Error('Installed Paseo CLI package not found');
    directory = parent;
  }
  const { connectToDaemon } = await import(pathToFileURL(join(directory, 'dist/utils/client.js')).href);
  const client = await connectToDaemon({ target: { kind: 'instance', home: join(homedir(), '.paseo') }, timeout: 10000 });
  try { console.log(JSON.stringify(await perform(client, input))); }
  finally { await client.close().catch(() => {}); }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    // Do not echo upstream errors, prompts or credentials into HTTP responses.
    console.log(JSON.stringify({ error: error.denied ? 'denied' : 'unconfirmed' }));
    process.exitCode = 1;
  });
}
