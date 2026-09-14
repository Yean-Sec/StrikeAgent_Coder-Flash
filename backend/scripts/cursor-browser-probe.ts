/**
 * Cursor 会话浏览器验证辅助：用 Playwright 真实打开页面、登录、截图取证。
 * 子智能体验证时优先调用本脚本（等同 Browser 实测，产出截图供 MD/JSON 引用）。
 *
 * 用法:
 *   npx tsx scripts/cursor-browser-probe.ts <workspaceDir> [path]
 * 例:
 *   npx tsx scripts/cursor-browser-probe.ts workspace/<projectId> /
 *   npx tsx scripts/cursor-browser-probe.ts workspace/<projectId> /login.php
 */
import fs from 'fs';
import path from 'path';
import { chromium } from 'playwright';

const workspaceArg = process.argv[2];
const pagePath = process.argv[3] || '/';
if (!workspaceArg) {
  console.error('Usage: npx tsx scripts/cursor-browser-probe.ts <workspaceDir> [path]');
  process.exit(1);
}

const workspace = path.resolve(workspaceArg);
const envPath = path.join(workspace, 'TARGET_ENV.json');
let baseUrl = 'http://localhost:18800';
let accounts: { username: string; password: string; role: string; login?: string }[] = [];
try {
  const env = JSON.parse(fs.readFileSync(envPath, 'utf8'));
  baseUrl = String(env.url || env.api_base || baseUrl).replace(/\/$/, '');
  accounts = Array.isArray(env.accounts) ? env.accounts : [];
} catch {
  /* default */
}

const shotDir = path.join(workspace, 'POC', 'browser_shots');
fs.mkdirSync(shotDir, { recursive: true });
const ts = new Date().toISOString().replace(/[:.]/g, '-');

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const target = baseUrl + (pagePath.startsWith('/') ? pagePath : `/${pagePath}`);
  const result: Record<string, unknown> = { baseUrl, target, ts, shots: [] as string[] };

  await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 30000 });
  const homeShot = path.join(shotDir, `${ts}_home.png`);
  await page.screenshot({ path: homeShot, fullPage: true });
  (result.shots as string[]).push(homeShot);

  const admin = accounts.find((a) => a.role === 'admin');
  if (admin?.login) {
    const loginUrl = baseUrl + admin.login;
    await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    const userSel = 'input[name="userid"], input[name="username"], input#userid, input#username';
    const passSel = 'input[name="pwd"], input[name="password"], input#pwd, input#password';
    if ((await page.locator(userSel).count()) > 0) {
      await page.locator(userSel).first().fill(admin.username);
      await page.locator(passSel).first().fill(admin.password);
      const submit = page.locator('input[type="submit"], button[type="submit"]').first();
      if ((await submit.count()) > 0) await submit.click();
      else await page.keyboard.press('Enter');
      await page.waitForTimeout(2000);
      const adminShot = path.join(shotDir, `${ts}_admin_after_login.png`);
      await page.screenshot({ path: adminShot, fullPage: true });
      (result.shots as string[]).push(adminShot);
      result.adminLogin = { ok: !page.url().includes('login'), url: page.url() };
    }
  }

  const title = await page.title();
  result.title = title;
  result.finalUrl = page.url();
  await browser.close();
  console.log(JSON.stringify(result, null, 2));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
