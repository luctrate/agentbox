#!/usr/bin/env node
'use strict';

const { parseArgs } = require('node:util');
const { chromium } = require('playwright');

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      help: { type: 'boolean', short: 'h' },
      'wait-for': { type: 'string' },
      'wait-ms': { type: 'string', default: '500' },
      timeout: { type: 'string', default: '30000' },
      'max-chars': { type: 'string', default: '20000' },
      screenshot: { type: 'string' },
      evaluate: { type: 'string' },
      html: { type: 'boolean' },
    },
  });
  if (values.help) {
    console.log('research-browser URL [--wait-for CSS] [--wait-ms 500] [--timeout 30000] [--max-chars 20000] [--screenshot /tmp/page.png] [--evaluate "JS expression"] [--html]');
    return;
  }
  if (positionals.length !== 1) throw new Error('Supply one http:// or https:// URL; use --help for options');
  const url = new URL(positionals[0]);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only HTTP/HTTPS pages are supported');
  function integer(name, min, max) {
    const value = Number(values[name]);
    if (!Number.isInteger(value) || value < min || value > max) throw new Error(`Invalid --${name}`);
    return value;
  }
  const timeout = integer('timeout', 100, 120000);
  const waitMs = integer('wait-ms', 0, 30000);
  const maxChars = integer('max-chars', 1, 1000000);
  // Docker supplies the outer boundary: non-root, no privileges/host binds,
  // private IPC and restricted egress. Do not require SYS_ADMIN or host IPC.
  const browser = await chromium.launch({
    headless: true, chromiumSandbox: false,
    args: ['--disable-dev-shm-usage'],
  });
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    const page = await context.newPage();
    page.setDefaultTimeout(timeout);
    const response = await page.goto(url.href, { waitUntil: 'domcontentloaded', timeout });
    if (values['wait-for']) await page.locator(values['wait-for']).first().waitFor({ state: 'visible' });
    if (waitMs) await page.waitForTimeout(waitMs);
    const content = values.html ? await page.content() : await page.locator('body').innerText();
    const result = {
      url: page.url(), status: response?.status() ?? null, title: await page.title(),
      [values.html ? 'html' : 'text']: content.slice(0, maxChars), truncated: content.length > maxChars,
    };
    if (values.evaluate !== undefined) result.evaluation = await page.evaluate(values.evaluate);
    if (values.screenshot) {
      await page.screenshot({ path: values.screenshot, fullPage: true });
      result.screenshot = values.screenshot;
    }
    console.log(JSON.stringify(result, null, 2));
  } finally { await browser.close(); }
}

main().catch(error => {
  console.error(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
});
