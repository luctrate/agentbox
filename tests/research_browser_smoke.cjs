// Run inside the research browser image under its actual runtime constraints.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const { promisify } = require('node:util');
const execFile = promisify(require('node:child_process').execFile);
const { chromium } = require('playwright');

(async () => {
  const server = http.createServer((request, response) => {
    response.setHeader('Content-Type', 'text/html');
    response.end(`<title>Loading</title><main>Loading</main><button onclick="document.querySelector('main').textContent='Clicked'">Click me</button><script>setTimeout(()=>{document.title='JavaScript rendered';document.querySelector('main').textContent='Rendered by JavaScript';document.querySelector('main').id='ready';window.fixtureReady=true},50)</script>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  const screenshot = '/tmp/agentbox-browser-smoke.png';
  try {
    const { stdout } = await execFile('research-browser', [url, '--wait-for', '#ready', '--wait-ms', '0', '--screenshot', screenshot, '--evaluate', 'window.fixtureReady'], { timeout: 30000 });
    const result = JSON.parse(stdout);
    assert.equal(result.title, 'JavaScript rendered');
    assert.match(result.text, /Rendered by JavaScript/);
    assert.equal(result.evaluation, true);
    assert.equal(fs.readFileSync(screenshot).subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
    const browser = await chromium.launch({ headless: true, args: ['--disable-dev-shm-usage'] });
    try {
      const page = await browser.newPage();
      await page.goto(url);
      await page.locator('#ready').waitFor();
      await page.getByRole('button', { name: 'Click me' }).click();
      assert.equal(await page.locator('main').innerText(), 'Clicked');
    } finally { await browser.close(); }
    console.log(JSON.stringify({ javascriptRendering: true, evaluation: true, screenshotPNG: true, interactiveClick: true }));
  } finally { server.close(); fs.rmSync(screenshot, { force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
