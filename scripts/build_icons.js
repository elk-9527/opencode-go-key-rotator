'use strict';

const fs = require('fs');
const path = require('path');

const playwrightPath = process.env.PLAYWRIGHT_CORE_PATH || 'playwright-core';
const {chromium} = require(playwrightPath);

const root = path.resolve(__dirname, '..');
const source = path.join(root, 'assets', 'app-icon.svg');
const sourceData = `data:image/svg+xml;base64,${fs.readFileSync(source).toString('base64')}`;
const pngTarget = path.join(root, 'assets', 'app-icon.png');
const icoTarget = path.join(root, 'assets', 'app-icon.ico');
const iconSizes = [16, 20, 24, 32, 40, 48, 64, 128, 256];

function packIco(images) {
  const header = Buffer.alloc(6 + images.length * 16);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);

  let offset = header.length;
  images.forEach(({size, data}, index) => {
    const entry = 6 + index * 16;
    header.writeUInt8(size === 256 ? 0 : size, entry);
    header.writeUInt8(size === 256 ? 0 : size, entry + 1);
    header.writeUInt8(0, entry + 2);
    header.writeUInt8(0, entry + 3);
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(data.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += data.length;
  });

  return Buffer.concat([header, ...images.map(({data}) => data)]);
}

async function render(page, size) {
  await page.setViewportSize({width: size, height: size});
  await page.setContent(`<!doctype html><style>html,body{margin:0;width:100%;height:100%;overflow:hidden}img{display:block;width:100%;height:100%}</style><img src="${sourceData}">`);
  await page.locator('img').waitFor({state: 'visible'});
  await page.evaluate(() => Promise.all([document.fonts.ready, document.querySelector('img').decode()]));
  return page.screenshot({omitBackground: true});
}

async function main() {
  const launchOptions = {headless: true};
  if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE) {
    launchOptions.executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
  }
  const browser = await chromium.launch(launchOptions);
  try {
    const page = await browser.newPage({viewport: {width: 512, height: 512}, deviceScaleFactor: 1});
    fs.writeFileSync(pngTarget, await render(page, 512));
    const images = [];
    for (const size of iconSizes) images.push({size, data: await render(page, size)});
    fs.writeFileSync(icoTarget, packIco(images));
  } finally {
    await browser.close();
  }
  console.log(`已生成 ${path.relative(root, pngTarget)} 与 ${path.relative(root, icoTarget)}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
