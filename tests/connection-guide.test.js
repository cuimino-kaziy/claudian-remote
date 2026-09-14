import assert from "node:assert/strict";
import test from "node:test";
import vm from "node:vm";
import { build } from "esbuild";
import { CONNECTION_GUIDES, connectionErrorMessage, normalizeConnectionAddress } from "../src/settings/connection-guide.js";

test("connection address accepts copied HTTPS endpoints and rejects secrets or insecure input", () => {
  assert.equal(normalizeConnectionAddress(" https://mac.example.ts.net/ "), "https://mac.example.ts.net");
  assert.equal(normalizeConnectionAddress("https://relay.example.invalid:8443/relay/"), "https://relay.example.invalid:8443/relay");
  for (const value of ["", "100.64.0.1", "http://relay.example.invalid", "wss://relay.example.invalid", "https://user:password@relay.example.invalid", "https://relay.example.invalid/?token=secret", "https://relay.example.invalid/#secret", "obsidian://claudian-remote"]) {
    assert.throws(() => normalizeConnectionAddress(value), /pairing_endpoint_(missing|invalid)/);
  }
  assert.match(connectionErrorMessage(new Error("claim_expired")), /Mac.*添加移动设备/);
  assert.match(connectionErrorMessage(new Error("pairing_wrong_vault")), /同一个|相同/);
  assert.doesNotMatch(connectionErrorMessage(new Error("request https://user:secret@private.example failed")), /secret|private\.example/);
  assert.match(CONNECTION_GUIDES.remote_vps.help, /尚未开放 VPS 自动部署/);
});

test("settings save only valid endpoints, preserve bound profiles, and pair through the existing controller", async () => {
  const elements = [];
  class Element {
    constructor(tag, options = {}) { this.tag = tag; Object.assign(this, options); this.events = {}; this.open = false; }
    empty() { elements.length = 0; rows.length = 0; }
    createEl(tag, options = {}) { const element = new Element(tag, options); elements.push(element); return element; }
    createDiv(options = {}) { return this.createEl("div", options); }
    addEventListener(type, callback) { this.events[type] = callback; }
    querySelector(selector) { return elements.find((element) => selector.includes(`"${element.attr?.["data-settings-tab"]}"`)); }
    querySelectorAll() { return []; }
    focus() { this.focused = true; }
  }
  class Control {
    setValue(value) { this.value = value; return this; }
    setPlaceholder() { return this; }
    setDisabled(value) { this.disabled = value; return this; }
    setButtonText(value) { this.label = value; return this; }
    setCta() { return this; }
    onClick(callback) { this.click = callback; return this; }
    onChange(callback) { this.change = callback; return this; }
    addOptions() { return this; }
  }
  const rows = [];
  class Setting {
    constructor() { rows.push(this); this.buttons = []; this.controlEl = new Element(); }
    setName(value) { this.name = value; return this; }
    setDesc() { return this; }
    addText(callback) { this.text = new Control(); callback(this.text); return this; }
    addButton(callback) { const button = new Control(); this.buttons.push(button); callback(button); return this; }
    addDropdown(callback) { this.dropdown = new Control(); callback(this.dropdown); return this; }
  }
  const { outputFiles } = await build({ entryPoints: [new URL("../src/plugin.js", import.meta.url).pathname], bundle: true, write: false, format: "cjs", platform: "browser", external: ["obsidian"], logLevel: "silent" });
  const module = { exports: {} };
  vm.runInNewContext(outputFiles[0].text, {
    module, exports: module.exports, URL, TextEncoder,
    require: () => ({ Plugin: class {}, ItemView: class {}, Modal: class {}, Component: class {},
      PluginSettingTab: class { constructor() { this.containerEl = new Element(); } },
      Notice: class { hide() {} }, Setting, Platform: { isMobileApp: true } })
  });
  let saves = 0, profile = null, accepted = "", polls = 0;
  const plugin = {
    settings: { relay_base_url: "", mobile_token: "", upload_directory: "Uploads" },
    deviceStore: { read: () => profile },
    saveSettings: async () => { saves += 1; }, currentPairingClaim: () => null,
    mobilePairing: { acceptShortCode: async (code) => { accepted = code; } },
    startMobilePairingPolling: () => { polls += 1; }
  };
  const tab = new module.exports.RemoteSettingsTab({}, plugin);
  const render = () => { tab.display(); return rows.find((row) => row.name === "服务器地址"); };
  let address = render();
  const selectTab = (section) => elements.find((element) => element.attr?.["data-settings-tab"] === section).events.click();
  assert.deepEqual(elements.filter((element) => element.attr?.role === "tab").map((element) => element.text), ["连接", "设备", "帮助"]);
  assert.equal(elements.find((element) => element.attr?.["aria-selected"] === "true").text, "连接");
  assert.ok(elements.filter((element) => element.tag === "details").every((element) => !element.open));
  address.text.change("https://draft.example.invalid");
  selectTab("devices");
  rows.find((row) => row.name === "移动设备配对").text.change("DRAFT123");
  selectTab("help");
  assert.ok(elements.filter((element) => element.tag === "details").every((element) => !element.open));
  assert.ok(elements.some((element) => element.tag === "code" && element.text.includes("https://")));
  selectTab("connection");
  address = rows.find((row) => row.name === "服务器地址");
  assert.equal(address.text.value, "https://draft.example.invalid");
  selectTab("devices");
  assert.equal(rows.find((row) => row.name === "移动设备配对").text.value, "DRAFT123");
  selectTab("connection");
  address = rows.find((row) => row.name === "服务器地址");
  address.text.change("http://invalid.example");
  assert.equal(saves, 0);
  await address.buttons[0].click();
  assert.equal(saves, 0);
  assert.equal(plugin.settings.relay_base_url, "");
  assert.match(tab.feedback, /https:\/\//);
  address = render();
  address.text.change("https://relay.example.invalid/");
  await address.buttons[0].click();
  assert.equal(saves, 1);
  assert.equal(plugin.settings.relay_base_url, "https://relay.example.invalid");
  const saveSettings = plugin.saveSettings;
  plugin.saveSettings = async () => { throw new Error("private persistence failure"); };
  address = render();
  address.text.change("https://failed-save.example.invalid");
  await address.buttons[0].click();
  assert.equal(plugin.settings.relay_base_url, "https://relay.example.invalid");
  assert.equal(rows.find((row) => row.name === "服务器地址").text.value, "https://failed-save.example.invalid");
  assert.doesNotMatch(tab.feedback, /private persistence failure/);
  let finishSave;
  plugin.saveSettings = () => new Promise((resolve) => { finishSave = resolve; });
  address = render();
  address.text.change("https://submitted.example.invalid");
  const pendingSave = address.buttons[0].click();
  selectTab("devices");
  selectTab("connection");
  rows.find((row) => row.name === "服务器地址").text.change("https://newer-draft.example.invalid");
  finishSave();
  await pendingSave;
  assert.equal(rows.find((row) => row.name === "服务器地址").text.value, "https://newer-draft.example.invalid");
  plugin.saveSettings = saveSettings;
  selectTab("devices");
  const pairing = rows.find((row) => row.name === "移动设备配对");
  pairing.text.change("ABCD2345");
  await pairing.buttons[0].click();
  assert.equal(accepted, "ABCD2345");
  assert.equal(polls, 1);
  let finishPairing;
  plugin.mobilePairing.acceptShortCode = () => new Promise((resolve) => { finishPairing = resolve; });
  const submittedPairing = rows.find((row) => row.name === "移动设备配对");
  submittedPairing.text.change("FIRST123");
  const pendingPairing = submittedPairing.buttons[0].click();
  selectTab("connection");
  selectTab("devices");
  rows.find((row) => row.name === "移动设备配对").text.change("NEWER123");
  finishPairing();
  await pendingPairing;
  assert.equal(rows.find((row) => row.name === "移动设备配对").text.value, "NEWER123");
  profile = { endpoint: "https://bound.example.invalid", mode: "remote_vps" };
  selectTab("connection");
  address = render();
  assert.equal(address.text.disabled, true);
  assert.equal(address.buttons[0].label, "复制地址");
  assert.equal(saves, 1);
  elements.length = 0;
  const helpTab = new module.exports.RemoteSettingsTab({}, plugin);
  helpTab.activeSection = "help";
  helpTab.display();
  assert.ok(elements.some((element) => element.tag === "a" && element.href?.endsWith("/docs/self-host-vps.md")));
  const navigation = [];
  const mobilePlugin = Object.create(module.exports.default.prototype);
  const leaf = { setViewState: async () => navigation.push("open-view") };
  mobilePlugin.app = {
    setting: { close: () => navigation.push("close-settings") },
    workspace: { getLeavesOfType: () => [], getLeaf: () => leaf, revealLeaf: () => navigation.push("reveal-view") }
  };
  await mobilePlugin.openMobileView();
  assert.deepEqual(navigation, ["open-view", "close-settings", "reveal-view"]);
});
