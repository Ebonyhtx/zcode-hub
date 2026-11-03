const { test, expect } = require("@playwright/test");

test.beforeEach(async ({ page }) => {
  await page.addInitScript({ path: require("path").join(__dirname, "mock.js") });
  await page.goto("/");
  await expect(page.locator(".acct")).toHaveCount(3);
});

test("theme button toggles on the first click", async ({ page }) => {
  const before = await page.locator("body").getAttribute("data-theme");
  await page.locator("#themeBtn").click();
  await expect.poll(() => page.locator("body").getAttribute("data-theme")).not.toBe(before);
});

test("fold and expand keeps the card body in sync", async ({ page }) => {
  const head = page.locator('.acct[data-key="alpha"] .acct-head');
  const body = page.locator('.acct[data-key="alpha"] .acct-body');
  await head.click();
  await expect(body).toBeHidden();
  await head.click();
  await expect(body).toBeVisible();
});

test("search and filters narrow the account list", async ({ page }) => {
  await page.locator("#acctSearch").fill("beta");
  await expect(page.locator('.acct[data-key="beta"]')).toBeVisible();
  await expect(page.locator('.acct[data-key="alpha"]')).toHaveCount(0);

  await page.locator("#acctSearch").fill("");
  await page.locator('[data-action="filter"][data-filter="benefits"]').click();
  await expect(page.locator('.acct[data-key="alpha"]')).toBeVisible();
  await expect(page.locator('.acct[data-key="beta"]')).toHaveCount(0);

  await page.locator('[data-action="filter"][data-filter="all"]').click();
  await expect(page.locator(".acct")).toHaveCount(3);
});

test("pinning moves an account to the top", async ({ page }) => {
  await expect(page.locator(".acct").first()).toHaveAttribute("data-key", "alpha");
  await page.locator('[data-action="pin"][data-key="beta"]').click();
  await expect(page.locator(".acct").first()).toHaveAttribute("data-key", "beta");
  const calls = await page.evaluate(() => window.__calls.filter(c => c.cmd === "get_state").length);
  expect(calls).toBeGreaterThan(0);
});

test("tags can be edited from the card", async ({ page }) => {
  await page.locator('[data-action="tags"][data-key="beta"]').click();
  await expect(page.locator("#tagModal")).toBeVisible();
  await page.locator("#tagInput").fill("team, ops");
  await page.locator('[data-action="tags-ok"]').click();
  await expect(page.locator('.acct[data-key="beta"] .tag-user').first()).toHaveText("team");
  const call = await page.evaluate(() => window.__calls.filter(c => c.cmd === "set_profile_tags").pop());
  expect(call.args.key).toBe("beta");
  expect(call.args.tags).toEqual(["team", "ops"]);
});

test("settings toggles persist through set_settings", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await expect(page.locator("#cfgModal")).toBeVisible();
  await page.locator('#cfgModal label.tgl:has(#quotaNotifyTgl)').click();
  await expect(page.locator("#quotaNotifyTgl")).not.toBeChecked();
  await expect.poll(async () => page.evaluate(() => {
    const c = window.__calls.filter(x => x.cmd === "set_settings").pop();
    return c && c.args.quotaNotify;
  })).toBe(false);
});

test("backup import shows a preview before writing", async ({ page }) => {
  await page.locator('[data-action="bak"]').click();
  await page.locator("#impPath").fill("/tmp/backup.zhb");
  await page.locator("#impPwd").fill("secret1");
  await page.locator('[data-action="bak-import"]').click();
  await expect(page.locator("#bakPreview")).toBeVisible();
  await expect(page.locator("#bakPreview")).toContainText("Beta");
  await expect(page.locator("#bakPreview")).toContainText("Delta");
  await page.locator('[data-action="bak-import-confirm"]').click();
  await expect(page.locator("#bakStatus")).toContainText("导入完成");
});

test("claim history exports to JSON", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await page.locator('[data-action="cfg-history"]').click();
  await expect(page.locator("#historyList .history-row")).toHaveCount(1);
  await page.locator('[data-action="history-export"]').click();
  await expect(page.locator(".toasts")).toContainText("已导出 2 条记录");
});

test("settings can open the backup folder and shows backup count", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await expect(page.locator("#cfgModal")).toBeVisible();
  await expect(page.locator("#backupInfoTxt")).toContainText("共 2 份备份");
  await page.locator('[data-action="cfg-openbackup"]').click();
  await expect.poll(() => page.evaluate(() =>
    window.__calls.filter(c => c.cmd === "open_backup_dir").length)).toBeGreaterThan(0);
  await expect(page.locator(".toasts")).toContainText("已打开备份目录");
});

test("backup toast offers a shortcut to the backup folder", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await page.locator('[data-action="cfg-backup"]').click();
  await expect(page.locator(".toasts")).toContainText("备份完成");
  await page.locator('.toasts .linkbtn', { hasText: "打开备份目录" }).click();
  await expect.poll(() => page.evaluate(() =>
    window.__calls.filter(c => c.cmd === "open_backup_dir").length)).toBeGreaterThan(0);
});

test("latest local backup can be restored after confirmation", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await expect(page.locator("#backupInfoTxt")).toContainText("最近");
  await page.locator('[data-action="cfg-restorebackup"]').click();
  await expect(page.locator("#confirmModal")).toBeVisible();
  await page.locator('[data-action="confirm-ok"]').click();
  await expect(page.locator(".toasts")).toContainText("已恢复 2 个账号");
});

test("responsive grid switches between one and two columns", async ({ page }) => {
  await page.setViewportSize({ width: 700, height: 800 });
  const one = await page.evaluate(() => getComputedStyle(document.getElementById("acctList")).gridTemplateColumns);
  expect(one.trim().split(/\s+/).length).toBe(1);
  await page.setViewportSize({ width: 1200, height: 800 });
  const two = await page.evaluate(() => getComputedStyle(document.getElementById("acctList")).gridTemplateColumns);
  expect(two.trim().split(/\s+/).length).toBe(2);
});
