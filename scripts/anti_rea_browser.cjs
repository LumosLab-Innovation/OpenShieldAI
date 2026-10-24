// Owned browser probe; ephemeral controller sessions never enter output or disk.
const { chromium } = require('playwright');

(async () => {
  const config = JSON.parse(process.env.LAB_PROBE_CONFIG);
  delete process.env.LAB_PROBE_CONFIG;
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const checks = {};
  let pageErrors = 0;
  try {
    const context = await browser.newContext();
    await context.route('**/*', route => config.some(item => new URL(route.request().url()).origin === item.url)
      ? route.continue() : route.abort());
    for (const item of config) {
      const page = await context.newPage();
      page.on('pageerror', () => pageErrors++);
      await page.goto(item.url);
      await page.getByLabel('Ephemeral lab session from the test controller').fill(item.session);
      await page.getByRole('button', { name: 'Quote one item' }).click();
      await page.waitForFunction(() => document.querySelector('#result').textContent === '166');
      checks[item.arm + '_legitimate_ui_works'] = true;
      if (item.arm === 'after') {
        await page.getByLabel('Ephemeral lab session from the test controller').fill('invalid-synthetic-session');
        await page.getByRole('button', { name: 'Quote one item' }).click();
        await page.waitForFunction(() => document.querySelector('#result').textContent === 'Access denied');
        checks.after_ui_rejects_invalid_session = true;
      }
      await page.close();
    }
    checks.no_page_script_errors = pageErrors === 0;
    console.log(JSON.stringify({schemaVersion: 'anti_rea_browser_v1', synthetic: true,
      status: Object.values(checks).every(Boolean) ? 'pass' : 'failed', checks, pageErrors}));
  } finally {
    await browser.close();
  }
})().catch(() => { console.log(JSON.stringify({status: 'failed', code: 'browser_probe_failed'})); process.exitCode = 1; });
