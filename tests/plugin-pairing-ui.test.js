import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import test from "node:test";

function mobileSettings() {
  const notices = [];
  const buttons = [];
  const inputs = [];
  const module = { exports: {} };
  class Control {
    setPlaceholder() { return this; }
    setValue() { return this; }
    setButtonText(value) { this.label = value; return this; }
    setDisabled(value) { this.disabled = value; return this; }
    onChange(callback) { this.change = callback; return this; }
    onClick(callback) { this.click = callback; return this; }
  }
  class Setting {
    setName() { return this; }
    setDesc() { return this; }
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
  class PluginSettingTab {
    containerEl = { empty() {}, createEl() {} };
  }
  vm.runInNewContext(fs.readFileSync(new URL("../main.js", import.meta.url), "utf8"), {
    module, exports: module.exports,
    require: () => ({
      Plugin, PluginSettingTab, Setting, ItemView: class {}, Modal: class {}, Component: class {},
      Platform: { isMobileApp: true },
      Notice: class { constructor(message) { notices.push(message); } hide() {} }
    }),
    URL, console, crypto: globalThis.crypto, TextEncoder, setTimeout, clearTimeout
  });
  const plugin = new module.exports();
  plugin.loadSettings = async () => { plugin.settings = {}; };
  plugin.initializePairing = () => {};
  return { plugin, notices, buttons, inputs };
}

test("mobile Pair click shows progress and a safe failure instead of an unhandled rejection", async () => {
  const { plugin, notices, buttons, inputs } = mobileSettings();
  let rejectRequest;
  let polls = 0;
  plugin.mobilePairing = { acceptShortCode: () => new Promise((_, reject) => { rejectRequest = reject; }) };
  plugin.startMobilePairingPolling = () => { polls += 1; };
  await plugin.onload();
  plugin.tab.display();
  inputs[1].change("TEST1234");
  const button = buttons.find((item) => item.label === "配对");
  const click = button.click();
  assert.equal(button.disabled, true);
  assert.ok(notices.some((message) => message.includes("正在")));
  rejectRequest(new Error("network failure with private-value"));
  await click;
  assert.equal(button.disabled, false);
  assert.equal(polls, 0);
  assert.ok(notices.some((message) => message.includes("失败") && message.includes("Tailscale")));
  assert.doesNotMatch(JSON.stringify(notices), /private-value/);
  const retry = button.click();
  rejectRequest(new Error("claim_invalid"));
  await retry;
  assert.ok(notices.some((message) => message.includes("配对码无效")));
});
