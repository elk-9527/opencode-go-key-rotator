/* 最终打包界面的浏览器层回归；使用本机已有 playwright-core。 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const {spawn} = require('child_process');

const playwrightPath = process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core';
const {chromium} = require(playwrightPath);

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  const executable = path.resolve(process.argv[2] || 'dist/Key-Router.exe');
  if (!fs.isFile?.(executable) && !fs.existsSync(executable)) throw new Error('没有找到待测 EXE');
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'key-router-ui-qa-'));
  const portFile = path.join(temp, 'server.port');
  const outputDir = path.resolve('output/playwright');
  fs.mkdirSync(outputDir, {recursive: true});
  const app = spawn(executable, ['--demo', '--no-open'], {
    env: {...process.env, RK_PORT_FILE: portFile},
    windowsHide: true,
    stdio: 'ignore',
  });
  let browser;
  try {
    const deadline = Date.now() + 30000;
    while (!fs.existsSync(portFile) && Date.now() < deadline) {
      if (app.exitCode !== null) throw new Error(`打包程序提前退出：${app.exitCode}`);
      await wait(100);
    }
    if (!fs.existsSync(portFile)) throw new Error('打包程序没有报告端口');
    const port = Number(fs.readFileSync(portFile, 'utf8'));
    const url = `http://127.0.0.1:${port}/`;

    browser = await chromium.launch({
      headless: true,
      ...(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE
        ? {executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE}
        : {}),
    });
    const page = await browser.newPage({viewport: {width: 1220, height: 840}, deviceScaleFactor: 1});
    const consoleProblems = [];
    page.on('console', (message) => {
      if (['error', 'warning'].includes(message.type())) consoleProblems.push(`${message.type()}: ${message.text()}`);
    });
    page.on('pageerror', (error) => consoleProblems.push(`pageerror: ${error.message}`));

    await page.goto(url, {waitUntil: 'networkidle'});
    await page.waitForFunction(() => document.querySelectorAll('.target-row').length === 9);
    if ((await page.locator('#versionText').textContent()).trim() !== 'v0.4.2 · DEMO') throw new Error('界面版本号不正确');
    if ((await page.locator('.target-row').count()) !== 9) throw new Error('目标数量不正确');
    const dshRow = page.locator('.target-row').filter({hasText: 'dsh'}).first();
    if (!(await dshRow.locator('.target-state').textContent()).includes('已配置')) throw new Error('dsh 配置状态显示错误');

    await page.locator('[data-theme-choice="light"]').click();
    if (await page.locator('html').getAttribute('data-resolved-theme') !== 'light') throw new Error('日间主题切换失败');
    await page.locator('[data-theme-choice="dark"]').click();
    if (await page.locator('html').getAttribute('data-resolved-theme') !== 'dark') throw new Error('夜间主题切换失败');
    await page.locator('[data-theme-choice="system"]').click();
    if (await page.locator('html').getAttribute('data-theme') !== 'system') throw new Error('跟随系统主题切换失败');

    await page.locator('#previewButton').click();
    await page.waitForFunction(() => document.querySelectorAll('.change-row').length === 9);
    if (!(await page.locator('#applyButton').isDisabled())) throw new Error('演示模式错误地允许真实应用');
    if ((await page.locator('.change-row').count()) !== 9) throw new Error('预览变更数量不正确');
    const visibleText = await page.locator('body').innerText();
    if (visibleText.includes('sk-demo-1234567890-example')) throw new Error('页面正文泄露了完整 API Key');
    const wideOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    if (wideOverflow) throw new Error('宽屏布局出现横向溢出');
    await page.screenshot({path: path.join(outputDir, 'key-router-v042.png'), fullPage: true});
    await page.screenshot({path: path.resolve('docs/key-router-ui.png'), fullPage: true});

    await page.setViewportSize({width: 760, height: 900});
    await wait(250);
    const narrowOverflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth);
    if (narrowOverflow) throw new Error('窄屏布局出现横向溢出');
    await page.screenshot({path: path.join(outputDir, 'key-router-v042-narrow.png'), fullPage: true});
    if (consoleProblems.length) throw new Error(`浏览器控制台异常：${consoleProblems.join(' | ')}`);

    await page.locator('#quitButton').click();
    await Promise.race([
      new Promise((resolve) => app.once('exit', resolve)),
      wait(10000).then(() => { throw new Error('退出按钮没有关闭本地服务'); }),
    ]);
    console.log('UI browser QA: OK (themes, preview, responsive, console, shutdown)');
  } finally {
    if (browser) await browser.close();
    if (app.exitCode === null) app.kill();
    fs.rmSync(temp, {recursive: true, force: true});
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
