/* Generate documentation screenshots from the real UI + mock IPC. */
const { chromium } = require("playwright");
const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");

const PORT = 4174;
const OUT = path.join(__dirname, "..", "docs", "screenshots");

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const server = spawn(process.execPath, [path.join(__dirname, "..", "tests", "ui", "server.js")], {
    env: { ...process.env, PORT: String(PORT) }, stdio: "ignore"
  });
  await new Promise(r => setTimeout(r, 600));
  const browser = await chromium.launch();
  try {
    const ctx = await browser.newContext({ viewport: { width: 620, height: 800 }, locale: "zh-CN" });
    await ctx.addInitScript({ path: path.join(__dirname, "..", "tests", "ui", "mock.js") });
    const page = await ctx.newPage();
    await page.goto(`http://127.0.0.1:${PORT}/`);
    await page.waitForSelector(".acct");
    await page.screenshot({ path: path.join(OUT, "main-620.png"), fullPage: true });

    await page.setViewportSize({ width: 1200, height: 900 });
    await page.screenshot({ path: path.join(OUT, "main-1200.png"), fullPage: true });

    await page.setViewportSize({ width: 760, height: 820 });
    await page.locator('[data-action="cfg"]').click();
    await page.waitForSelector("#cfgModal:not([hidden])");
    await page.waitForTimeout(400);
    await page.screenshot({ path: path.join(OUT, "settings.png") });
    await page.locator('[data-action="cfg-close"]').click();

    await page.locator('[data-action="bak"]').click();
    await page.locator("#impPath").fill("C:\\Users\\me\\zcode-hub-backup.zhb");
    await page.locator("#impPwd").fill("secret1");
    await page.locator('[data-action="bak-import"]').click();
    await page.waitForSelector("#bakPreview:not([hidden])");
    await page.waitForTimeout(400);
    await page.screenshot({ path: path.join(OUT, "backup-preview.png") });

    // English main window for README.en.md
    const pageEn = await ctx.newPage();
    await pageEn.goto(`http://127.0.0.1:${PORT}/`);
    await pageEn.evaluate(() => localStorage.setItem("hub-lang", "en"));
    await pageEn.reload();
    await pageEn.waitForSelector(".acct");
    await pageEn.setViewportSize({ width: 620, height: 800 });
    await pageEn.screenshot({ path: path.join(OUT, "main-620-en.png"), fullPage: true });

    console.log("screenshots written to", OUT);
  } finally {
    await browser.close();
    server.kill();
  }
})().catch(e => { console.error(e); process.exit(1); });
