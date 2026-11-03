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
  await expect(page.locator("#backupInfoTxt")).toContainText("共 3 份备份");
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

test("backup picker lists every backup and restores the chosen one", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await page.locator('[data-action="cfg-restorebackup"]').click();
  await expect(page.locator("#restoreModal")).toBeVisible();
  const rows = page.locator("#restoreList .backup-row");
  await expect(rows).toHaveCount(3);
  // 不完整的备份置灰，不能被选中
  const broken = page.locator('#restoreList [data-name="20261101-120000"]');
  await expect(broken).toBeDisabled();
  await expect(page.locator('#restoreList [data-name="20261101-120000"]')).toHaveAttribute("data-ok", "0");

  await page.locator('#restoreList [data-name="20261102-120000"]').click();
  await expect(page.locator("#confirmModal")).toBeVisible();
  await page.locator('[data-action="confirm-ok"]').click();
  await expect(page.locator(".toasts")).toContainText("已恢复 2 个账号");
  const call = await page.evaluate(() => window.__calls.filter(c => c.cmd === "restore_backup").pop());
  expect(call.args.name).toBe("20261102-120000");
  // 恢复后前端清空额度快照并重新拉取状态
  await expect.poll(() => page.evaluate(() => window.__calls.filter(c => c.cmd === "get_state").length)).toBeGreaterThan(1);
});

/* ---------- claim state machine（preparing → waiting_captcha → claiming → success） ---------- */

// 让 claim_state 依次返回队列里的状态；mock 默认返回 idle
async function scriptClaimStates(page, states) {
  await page.evaluate((list) => {
    const state = window.__claimScript = { list, i: 0 };
    const orig = window.__TAURI_INTERNALS__.invoke;
    window.__TAURI_INTERNALS__.invoke = function (cmd, args) {
      if (cmd === "claim_state") {
        const next = state.list[Math.min(state.i, state.list.length - 1)];
        state.i += 1;
        return Promise.resolve(next);
      }
      return orig(cmd, args);
    };
  }, states);
}

test("claim walks through preparing, captcha and claiming to success", async ({ page }) => {
  await scriptClaimStates(page, [
    { status: "waiting_captcha", planId: "p1", planName: "Weekend bonus", captchaUrl: "http://127.0.0.1:9/c" },
    { status: "claiming", planId: "p1", planName: "Weekend bonus" },
    { status: "success", planId: "p1", planName: "Weekend bonus", effectiveAt: 1900000000 }
  ]);

  const btn = page.locator('[data-action="claim"][data-plan="p1"]').first();
  await expect(btn).toBeVisible();
  await btn.click();

  // 等待验证：按钮文案切到“验证中”，出现步骤条与重开入口
  await expect(page.locator('.acct[data-key="alpha"] .claim-step.on')).toHaveCount(2);
  await expect(page.locator('[data-action="claim-reopen"]')).toBeVisible();
  await expect(btn).toBeDisabled();

  // 领取中：第三步点亮
  await expect(page.locator('.acct[data-key="alpha"] .claim-step.on')).toHaveCount(3);
  await expect(btn).toHaveText("领取中");

  // 成功：toast、活动从卡片移除、按钮消失
  await expect(page.locator(".toasts")).toContainText("领取成功");
  await expect(page.locator('.acct[data-key="alpha"] .camp')).toHaveCount(0);
  await expect(page.locator('[data-action="claim"][data-plan="p1"]')).toHaveCount(0);
});

test("failed claim surfaces the error and re-enables the button", async ({ page }) => {
  await scriptClaimStates(page, [
    { status: "claiming", planId: "p1", planName: "Weekend bonus" },
    { status: "failed", planId: "p1", message: "服务端拒绝了领取" }
  ]);
  await page.locator('[data-action="claim"][data-plan="p1"]').first().click();
  await expect(page.locator(".toasts")).toContainText("领取失败");
  await expect(page.locator('[data-action="claim"][data-plan="p1"]')).toBeEnabled();
  await expect(page.locator('[data-action="claim"][data-plan="p1"]')).toHaveText("去领取");
});

test("claim history modal opens and renders rows", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await page.locator('[data-action="cfg-history"]').click();
  await expect(page.locator("#historyModal")).toBeVisible();
  await expect(page.locator("#historyList .history-row")).toHaveCount(1);
  await page.locator('[data-action="history-close"]').click();
  await expect(page.locator("#historyModal")).toBeHidden();
});

/* ---------- 无障碍 ---------- */
test("main view has no critical accessibility violations", async ({ page }) => {
  const { AxeBuilder } = require("@axe-core/playwright");
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa"])
    .disableRules(["color-contrast"]) // 主题色由设计规范控制，另行人工核验
    .analyze();
  const serious = results.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
  expect(serious.map((v) => `${v.id}: ${v.nodes.length} node(s) — ${v.help}`)).toEqual([]);
});

test("modals keep dialog semantics and accessible names", async ({ page }) => {
  const { AxeBuilder } = require("@axe-core/playwright");
  for (const [action, modal] of [["cfg", "#cfgModal"], ["bak", "#bakModal"]]) {
    await page.locator(`[data-action="${action}"]`).click();
    await expect(page.locator(modal)).toBeVisible();
    const results = await new AxeBuilder({ page })
      .include(modal)
      .withTags(["wcag2a", "wcag2aa"])
      .disableRules(["color-contrast"])
      .analyze();
    const serious = results.violations.filter((v) => v.impact === "critical" || v.impact === "serious");
    expect(serious.map((v) => `${modal} → ${v.id}: ${v.help}`)).toEqual([]);
    await page.keyboard.press("Escape");
  }
});

test("runtime errors are reported to the backend crash log", async ({ page }) => {
  await page.evaluate(() => {
    setTimeout(() => { throw new Error("boom-e2e"); }, 0);
  });
  await expect.poll(() => page.evaluate(() =>
    window.__calls.filter(c => c.cmd === "report_frontend_error")
      .some(c => String(c.args.message).indexOf("boom-e2e") >= 0)
  )).toBe(true);
});

/* ---------- 客户端演进 / 存档新鲜度 ---------- */

test("stale snapshot shows a tag and only the current account can refresh", async ({ page }) => {
  // beta 存档落后（旧版本 + 字段更少）
  await expect(page.locator('.acct[data-key="beta"] .tag.warn')).toContainText("旧 3.17.0");
  // 折叠态也能看到标签（标签在头部）
  await expect(page.locator('.acct[data-key="beta"]')).toHaveAttribute("data-key", "beta");

  // 非当前账号：只有说明，没有刷新按钮
  await page.locator('.acct[data-key="beta"] .acct-head').click();
  await expect(page.locator('.acct[data-key="beta"] .stale-note')).toBeVisible();
  await expect(page.locator('.acct[data-key="beta"] [data-action="refresh-profile"]')).toHaveCount(0);

  // 当前账号不落后时没有提示
  await expect(page.locator('.acct[data-key="alpha"] .stale-note')).toHaveCount(0);
});

test("refreshing the current account's stale snapshot clears the marker", async ({ page }) => {
  // 让 mock 把当前账号标成落后（字段更少），验证刷新按钮只在当前账号出现并生效
  await page.addInitScript(() => { window.__MOCK_OVERRIDES__ = { staleAlpha: true }; });
  await page.reload();
  await expect(page.locator('.acct[data-key="alpha"] .stale-note')).toBeVisible();
  const btn = page.locator('.acct[data-key="alpha"] [data-action="refresh-profile"]');
  await expect(btn).toBeVisible();
  await btn.click();
  await expect(page.locator(".toasts")).toContainText("存档已刷新");
  const call = await page.evaluate(() => window.__calls.filter(c => c.cmd === "refresh_profile").pop());
  expect(call.args.key).toBe("alpha");
});

test("settings show the client version and flag an unverified one", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  // 版本匹配：只显示版本号
  await expect(page.locator("#zcodeVer")).toHaveText("ZCode v3.17.2");
});

test("an unverified client version is flagged in settings only, not as a banner", async ({ page }) => {
  await page.addInitScript(() => {
    window.__MOCK_OVERRIDES__ = { compat: { zcode_version: "3.18.0", version_status: "newer" } };
  });
  await page.reload();
  await page.locator('[data-action="cfg"]').click();
  await expect(page.locator("#zcodeVer")).toContainText("未验证");
  await expect(page.locator("#zcodeVer")).toContainText("3.17.2");
  // 版本差异不是结构性错误 → 顶栏不出现
  await expect(page.locator("#compatBar")).toBeHidden();
});

// 非当前账号默认折叠，切换按钮在折叠体内——先展开
async function expandCard(page, key) {
  const card = page.locator(`.acct[data-key="${key}"]`);
  if (await card.evaluate((n) => n.classList.contains("folded"))) {
    await card.locator(".acct-head").click();
  }
  await expect(card.locator('[data-action="switch"]')).toBeVisible();
}

test("switch toast follows the explicit mode from the backend", async ({ page }) => {
  await expandCard(page, "beta");
  await page.locator('[data-action="switch"][data-key="beta"]').click();
  await page.locator('[data-action="confirm-ok"]').click();
  await expect(page.locator(".toasts")).toContainText("已切换并重启");
  const cold = await page.evaluate(() => window.__calls.filter(c => c.cmd === "switch_profile").pop());
  expect(cold.args.hot).toBe(false);
});

test("hot switch shows the restart hint instead of claiming a restart", async ({ page }) => {
  // 打开热切换开关
  await page.locator('[data-action="cfg"]').click();
  await page.locator('#cfgModal label.tgl:has(#hotTgl)').click();
  await page.locator('[data-action="cfg-close"]').click();
  await expandCard(page, "beta");
  await page.locator('[data-action="switch"][data-key="beta"]').click();
  await page.locator('[data-action="confirm-ok"]').click();
  await expect(page.locator(".toasts")).toContainText("已热切换");
  // 热切换后要求重启才能更新账号名
  await expect(page.locator("#noticeBar")).toBeVisible();
});

test("strict mode reports its own toast", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await page.locator('#cfgModal label.tgl:has(#safeModeTgl)').click();
  await page.locator('[data-action="cfg-close"]').click();
  await expandCard(page, "beta");
  await page.locator('[data-action="switch"][data-key="beta"]').click();
  await page.locator('[data-action="confirm-ok"]').click();
  await expect(page.locator(".toasts")).toContainText("严格模式");
});

test("strict mode disables the hot switch and says why", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await expect(page.locator("#hotTgl")).toBeEnabled();

  // 打开严格模式 → 热切换被禁用并换掉说明文案
  await page.locator('#cfgModal label.tgl:has(#safeModeTgl)').click();
  await expect(page.locator("#hotTgl")).toBeDisabled();
  await expect(page.locator("#hotHint")).toContainText("严格模式已开启");
  await expect(page.locator("#hotTglWrap")).toHaveClass(/tgl-disabled/);

  // 关掉严格模式 → 热切换恢复可用
  await page.locator('#cfgModal label.tgl:has(#safeModeTgl)').click();
  await expect(page.locator("#hotTgl")).toBeEnabled();
  await expect(page.locator("#hotHint")).toContainText("不重启客户端");
});

test("hot switch on warns that strict mode will override it", async ({ page }) => {
  await page.locator('[data-action="cfg"]').click();
  await page.locator('#cfgModal label.tgl:has(#hotTgl)').click();
  await expect(page.locator("#safeHint")).toContainText("会关闭热切换");
});

test("product version with four parts is shown as x.y.z", async ({ page }) => {
  await page.addInitScript(() => {
    window.__MOCK_OVERRIDES__ = { compat: { zcode_version: "3.17.2.9661" } };
  });
  await page.reload();
  await page.locator('[data-action="cfg"]').click();
  // PowerShell 的 ProductVersion 是四段，界面只显示到补丁号
  await expect(page.locator("#zcodeVer")).toHaveText("ZCode v3.17.2");
});

test("stale snapshot with unknown client version shows no placeholder", async ({ page }) => {
  // v1.11.0 前的旧存档：backfill 补了 field_count 但没有 client_version
  await page.addInitScript(() => { window.__MOCK_OVERRIDES__ = { staleUnknownVersion: true }; });
  await page.reload();
  const card = page.locator('.acct[data-key="gamma"]');
  await expect(card.locator(".tag.warn")).toHaveText("旧");
  // 关键：不能把 "?" 露给用户
  await expect(card.locator(".tag.warn")).not.toContainText("?");
  await card.locator(".acct-head").click();
  await expect(card.locator(".stale-note")).toContainText("7");
  await expect(card.locator(".stale-note")).not.toContainText("?");
});

test("expired snapshots are not marked stale", async ({ page }) => {
  // gamma 在 mock 里是 jwt_expired；过期存档没有有效 live 可刷新，不该标「旧」
  await expect(page.locator('.acct[data-key="gamma"] .tag.warn')).toHaveCount(0);
  await expect(page.locator('.acct[data-key="gamma"] .tag.expired')).toHaveCount(1);
});

test("responsive grid switches between one and two columns", async ({ page }) => {
  await page.setViewportSize({ width: 700, height: 800 });
  const one = await page.evaluate(() => getComputedStyle(document.getElementById("acctList")).gridTemplateColumns);
  expect(one.trim().split(/\s+/).length).toBe(1);
  await page.setViewportSize({ width: 1200, height: 800 });
  const two = await page.evaluate(() => getComputedStyle(document.getElementById("acctList")).gridTemplateColumns);
  expect(two.trim().split(/\s+/).length).toBe(2);
});
