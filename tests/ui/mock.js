/* Tauri IPC shim for UI tests. Runs before app.js. */
(function () {
  var state = {
    current_label: "Alpha",
    current_provider: "zai",
    current_logged_in: true,
    profiles: [
      { key: "alpha", label: "Alpha", captured_at: "2026-11-01T10:00:00Z", is_current: true, provider: "zai", jwt_expired: false, tags: ["work"] },
      { key: "beta", label: "Beta", captured_at: "2026-11-01T11:00:00Z", is_current: false, provider: "bigmodel", jwt_expired: false, tags: [] },
      { key: "gamma", label: "Gamma", captured_at: "2026-11-01T12:00:00Z", is_current: false, provider: "zai", jwt_expired: true, tags: [] }
    ],
    zcode_running: true,
    process_error: null,
    zcode_exe: "C:\\ZCode\\ZCode.exe",
    settings: {
      auto_check_minutes: 15, notify_enabled: true, hot_switch: false, safe_mode: false,
      lang: "zh", close_action: "tray", start_minimized: false,
      quota_notify: true, auto_backup: true, update_notify: true
    },
    benefits: {
      alpha: { ok: true, count: 1, checked_at: 1700000000,
               campaigns: [{ plan_id: "p1", title: "Weekend bonus", grant: "100", detail: "GLM +100" }] }
    },
    last_check: 1700000000,
    quota_cache: {},
    version: "1.9.1",
    autostart: false,
    compat: { ok: true, errors: [], notes: [], installed: true, zcode_version: "3.17.1" },
    update_available: null
  };
  var quota = {
    ok: true, fetched_at: 1700000000,
    data: { data: { balances: [{ plan_id: "p1", show_name: "GLM-5.3-Flash", available_units: 500,
                                 total_units: 1000, expires_at: 1900000000 }] } }
  };
  var history = {
    ok: true, samples: 3,
    points: [
      { ts: 1700000000, balances: [{ plan_id: "p1", model: "GLM", available: 900, total: 1000 }] },
      { ts: 1700003600, balances: [{ plan_id: "p1", model: "GLM", available: 700, total: 1000 }] },
      { ts: 1700007200, balances: [{ plan_id: "p1", model: "GLM", available: 500, total: 1000 }] }
    ],
    forecast: [{ plan_id: "p1", model: "GLM", days_left: 12 }]
  };
  function clone(v) { return JSON.parse(JSON.stringify(v)); }
  function toSnake(k) {
    var m = { minutes: "auto_check_minutes", notifyEnabled: "notify_enabled", hotSwitch: "hot_switch",
              safeMode: "safe_mode", lang: "lang", closeAction: "close_action", startMinimized: "start_minimized",
              quotaNotify: "quota_notify", autoBackup: "auto_backup", updateNotify: "update_notify",
              zcodePath: "zcode_path" };
    return m[k] || k;
  }
  window.__calls = [];
  window.__TAURI_INTERNALS__ = {
    invoke: function (cmd, args) {
      args = args || {};
      window.__calls.push({ cmd: cmd, args: args });
      switch (cmd) {
        case "get_state": return Promise.resolve(clone(state));
        case "fetch_quota":
          return Promise.resolve(args.key === "gamma"
            ? { ok: false, code: "auth", error: "登录已过期，请重新登录该账号" }
            : clone(quota));
        case "quota_history": return Promise.resolve(clone(history));
        case "set_settings":
          Object.keys(args).forEach(function (k) { state.settings[toSnake(k)] = args[k]; });
          return Promise.resolve({ ok: true, settings: clone(state.settings) });
        case "get_settings": return Promise.resolve(clone(state.settings));
        case "set_profile_tags":
          state.profiles.forEach(function (p) { if (p.key === args.key) p.tags = args.tags || []; });
          return Promise.resolve({ ok: true, tags: args.tags || [] });
        case "rename_profile": return Promise.resolve({ ok: true, label: args.label });
        case "inspect_bundle":
          return Promise.resolve({ ok: true, version: 2, count: 2, duplicates: 1, relogin: 0, invalid: 0,
            accounts: [
              { label: "Beta", provider: "bigmodel", tags: [], duplicate: true, needs_relogin: false, has_token: true },
              { label: "Delta", provider: "zai", tags: ["team"], duplicate: false, needs_relogin: false, has_token: true }
            ] });
        case "import_bundle": return Promise.resolve({ ok: true, added: 1, skipped: 1, relogin: 0 });
        case "backup_now": return Promise.resolve({ ok: true, profiles: 3 });
        case "get_backup_status": return Promise.resolve({ ok: true, count: 2, latest: "20261103-000001", latest_at: "2026-11-03T00:00:00Z", path: "C:/Users/demo/AppData/Roaming/zcode-hub/backups" });
        case "restore_latest_backup": return Promise.resolve({ ok: true, restored: 2, backup: "20261103-000001" });
        case "open_backup_dir": return Promise.resolve({ ok: true, path: "C:/Users/demo/AppData/Roaming/zcode-hub/backups" });
        case "export_diagnostics": return Promise.resolve({ ok: true, path: args.path });
        case "export_claim_history": return Promise.resolve({ ok: true, count: 2, path: args.path });
        case "claim_history":
          return Promise.resolve({ ok: true, items: [{ ts: 1700000000, plan: "Weekend bonus", effectiveAt: 1700001000 }] });
        case "claim_state": return Promise.resolve({ status: "idle" });
        case "oauth_status": return Promise.resolve({ status: "idle" });
        case "check_all_benefits":
          return Promise.resolve({ ok: true, accounts: 3, checked_ok: 3, failed: 0, transient: 0,
                                   accounts_with_benefits: 1, total_campaigns: 1 });
        case "check_benefits":
          return Promise.resolve({ ok: true, count: 1, campaigns: clone(state.benefits.alpha.campaigns),
                                   checked_at: 1700000000, key: args.key });
        case "plugin:dialog|save": return Promise.resolve("/tmp/zcode-hub-e2e.json");
        case "plugin:dialog|open": return Promise.resolve("/tmp/zcode-hub-e2e.zhb");
        default: return Promise.resolve({ ok: true });
      }
    }
  };
  try { localStorage.setItem("hub-lang", "zh"); localStorage.setItem("hub-theme", "light"); } catch (e) {}
})();
