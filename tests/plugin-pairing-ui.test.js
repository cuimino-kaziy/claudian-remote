import assert from "node:assert/strict";
import { build } from "esbuild";
import vm from "node:vm";
import test from "node:test";

async function mobileSettings({ nativeSettings = false, requestUrl } = {}) {
  const notices = [];
  const buttons = [];
  const inputs = [];
  const module = { exports: {} };
  const values = new Map();
  const localStorage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key)
  };
  let savedData = { vault_id: "vault-a" };
  class Control {
    setPlaceholder(value) { this.placeholder = value; return this; }
    setValue(value) { this.value = value; return this; }
    setButtonText(value) { this.label = value; return this; }
    setDisabled(value) { this.disabled = value; return this; }
    setCta() { return this; }
    addOptions() { return this; }
    onChange(callback) { this.change = callback; return this; }
    onClick(callback) { this.click = callback; return this; }
  }
  class Setting {
    setName() { return this; }
    setDesc() { return this; }
    setHeading() { return this; }
    addDropdown(callback) { callback(new Control()); return this; }
    addText(callback) { const control = new Control(); inputs.push(control); callback(control); return this; }
    addButton(callback) { const control = new Control(); buttons.push(control); callback(control); return this; }
  }
  class Plugin {
    app = {};
    addSettingTab(tab) { this.tab = tab; }
    registerObsidianProtocolHandler(name, callback) { this.protocol = callback; }
    registerView() {}
    addCommand() {}
    addRibbonIcon() {}
  }
  class Element {
    empty() { buttons.length = 0; inputs.length = 0; }
    createEl() { return new Element(); }
    createDiv() { return new Element(); }
    addEventListener() {}
    querySelectorAll() { return []; }
  }
  class PluginSettingTab {
    containerEl = new Element();
  }
  const { outputFiles } = await build({ entryPoints: [new URL("../src/plugin.js", import.meta.url).pathname], bundle: true, write: false, format: "cjs", platform: "browser", external: ["obsidian"], logLevel: "silent" });
  vm.runInNewContext(outputFiles[0].text, {
    module, exports: module.exports,
    require: () => ({
      Plugin, PluginSettingTab, Setting, ItemView: class {}, Modal: class {}, Component: class {},
      Platform: { isMobileApp: true },
      requestUrl,
      Notice: class { constructor(message) { notices.push(message); } hide() {} }
    }),
    URL, console, crypto: globalThis.crypto, TextEncoder, setTimeout, clearTimeout, localStorage
  });
  const createPlugin = () => {
    const plugin = new module.exports.default();
    plugin.manifest = { id: "claudian-remote", version: "0.2.0-beta.6.5" };
    plugin.loadData = async () => savedData;
    plugin.saveData = async (data) => { savedData = JSON.parse(JSON.stringify(data)); };
    if (!nativeSettings) {
      plugin.loadSettings = async () => { plugin.settings = {}; };
      plugin.initializePairing = () => {};
      plugin.deviceStore = { read: () => null };
    }
    return plugin;
  };
  return { plugin: createPlugin(), createPlugin, notices, buttons, inputs };
}

test("successful device pairing survives plugin reloads and version changes after legacy migration", async () => {
  let pairingRequests = 0;
  const { plugin, createPlugin } = await mobileSettings({
    nativeSettings: true,
    requestUrl: async ({ url }) => {
      pairingRequests += 1;
      return { status: 200, json: url.endsWith("/redeem")
        ? { claim_id: "claim-a", status: "approved", redemption_handle: "test-handle" }
        : { credential_id: "credential-a", credential: "new-device-token", generation: 1 } };
    }
  });
  await plugin.loadSettings();
  plugin.deviceStore.write("migration", { legacy_shared_token_v1: { completed: true, re_pair_required: true } });
  plugin.deviceStore.write("connection-profile", {
    endpoint: "https://relay.example.invalid", installation_id: "installation-a",
    vault_id: "vault-a", endpoint_audience: "audience-a"
  });
  plugin.initializePairing();
  await plugin.mobilePairing.acceptShortCode("TEST1234");
  assert.equal((await plugin.mobilePairing.complete()).paired, true);
  await plugin.saveTail;
  const paired = JSON.stringify(plugin.deviceStore.read("identity"));
  assert.equal(plugin.settings.re_pair_required, false);
  for (const version of ["0.2.0-beta.6.6", "0.2.0-beta.6.7"]) {
    const reloaded = createPlugin();
    reloaded.manifest.version = version;
    await reloaded.loadSettings();
    assert.equal(reloaded.settings.re_pair_required, false, version);
    assert.equal(reloaded.settings.mobile_token, "new-device-token", version);
    assert.equal(JSON.stringify(reloaded.deviceStore.read("identity")), paired, version);
  }
  assert.equal(pairingRequests, 2, "reloads must not redeem another pairing code");
});

test("completed legacy migration still rejects an old token or a device credential in the wrong scope", async (t) => {
  const profile = {
    endpoint: "https://relay.example.invalid", installation_id: "installation-a",
    vault_id: "vault-a", endpoint_audience: "audience-a"
  };
  const identity = {
    credential_id: "credential-a", mobile_token: "device-token", device_id: "iphone-a", client_instance_id: "view-a",
    installation_id: "installation-a", vault_id: "vault-a", endpoint_audience: "audience-a", generation: 1
  };
  const cases = [
    ["legacy token only", { mobile_token: "legacy-shared-token" }, profile],
    ["missing credential identity", { ...identity, credential_id: "" }, profile],
    ["wrong installation", { ...identity, installation_id: "installation-b" }, profile],
    ["wrong audience", { ...identity, endpoint_audience: "audience-b" }, profile],
    ["wrong profile vault", { ...identity, vault_id: "vault-b" }, profile],
    ["wrong synchronized vault", { ...identity, vault_id: "vault-b" }, { ...profile, vault_id: "vault-b" }]
  ];
  for (const [name, storedIdentity, storedProfile] of cases) {
    await t.test(name, async () => {
      const { plugin } = await mobileSettings({ nativeSettings: true });
      await plugin.loadSettings();
      plugin.deviceStore.write("migration", { legacy_shared_token_v1: { completed: true, re_pair_required: true } });
      plugin.deviceStore.write("identity", storedIdentity);
      plugin.deviceStore.write("connection-profile", storedProfile);
      await plugin.loadSettings();
      assert.equal(plugin.settings.re_pair_required, true);
      assert.equal(plugin.settings.mobile_token, "");
    });
  }
});

test("mobile Pair click shows progress and a safe failure instead of an unhandled rejection", async () => {
  const { plugin, notices, buttons, inputs } = await mobileSettings();
  let rejectRequest;
  let polls = 0, requests = 0;
  plugin.mobilePairing = { acceptShortCode: () => { requests += 1; return new Promise((_, reject) => { rejectRequest = reject; }); } };
  plugin.startMobilePairingPolling = () => { polls += 1; };
  await plugin.onload();
  plugin.tab.openSection("devices");
  inputs.find((item) => item.placeholder === "8 位配对码").change("TEST1234");
  const button = buttons.find((item) => item.label === "配对");
  const click = button.click();
  assert.equal(button.disabled, true);
  await button.click();
  assert.equal(requests, 1);
  assert.ok(notices.some((message) => message.includes("正在")));
  plugin.tab.openSection("connection");
  plugin.tab.openSection("devices");
  assert.equal(plugin.tab.pairingBusy, true);
  assert.equal(inputs.find((item) => item.placeholder === "8 位配对码").value, "TEST1234");
  rejectRequest(new Error("network failure with private-value"));
  await click;
  assert.equal(button.disabled, false);
  assert.equal(polls, 0);
  assert.equal(inputs.find((item) => item.placeholder === "8 位配对码").value, "TEST1234");
  const feedback = plugin.tab.feedback;
  plugin.tab.openSection("connection");
  plugin.tab.openSection("devices");
  assert.equal(plugin.tab.feedback, feedback);
  assert.ok(notices.some((message) => message.includes("失败") && message.includes("Tailscale")));
  assert.doesNotMatch(JSON.stringify(notices), /private-value/);
  const retry = button.click();
  rejectRequest(new Error("claim_invalid"));
  await retry;
  assert.ok(notices.some((message) => message.includes("配对码无效")));
});

test("entering the code completes pairing before opening the remote view", async () => {
  const { plugin, notices, buttons, inputs } = await mobileSettings();
  const calls = [];
  plugin.mobilePairing = {
    async acceptShortCode(code) { calls.push(["redeem", code]); this.pending = { status: "approved" }; },
    async pollUntilComplete() { calls.push(["complete"]); this.pending = null; return { paired: true }; }
  };
  plugin.openMobileView = async () => { calls.push(["open"]); };
  await plugin.onload();
  plugin.tab.openSection("devices");
  inputs.find((item) => item.placeholder === "8 位配对码").change("TEST1234");
  await buttons.find((item) => item.label === "配对").click();
  assert.deepEqual(calls, [["redeem", "TEST1234"], ["complete"], ["open"]]);
  assert.ok(notices.some((message) => message.includes("配对成功")));
  assert.doesNotMatch(notices.join(" "), /回到 Mac|等待.*批准/);
});

test("credential delivery failure stays in settings and never reports pairing success", async () => {
  const { plugin, notices, buttons, inputs } = await mobileSettings();
  let opened = false;
  plugin.mobilePairing = {
    async acceptShortCode() { this.pending = { status: "approved" }; },
    async pollUntilComplete() { throw new Error("credential_delivery_expired"); }
  };
  plugin.openMobileView = async () => { opened = true; };
  await plugin.onload();
  plugin.tab.openSection("devices");
  inputs.find((item) => item.placeholder === "8 位配对码").change("TEST1234");
  await buttons.find((item) => item.label === "配对").click();
  assert.equal(opened, false);
  assert.ok(notices.some((message) => message.includes("在 Mac 生成新码")));
  assert.doesNotMatch(notices.join(" "), /配对成功/);
});
