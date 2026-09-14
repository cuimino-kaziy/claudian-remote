import assert from "node:assert/strict";
import test from "node:test";
import { MobileComposer } from "../src/mobile/components/composer.js";

class FakeElement extends EventTarget {
  constructor(tag) {
    super();
    Object.assign(this, { tagName: tag.toUpperCase(), children: [], attributes: {}, style: {}, value: "", hidden: false, disabled: false, scrollHeight: 40 });
  }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  click() { if (!this.disabled) this.dispatchEvent(new Event("click")); }
  blur() { this.dispatchEvent(new Event("blur")); }
  remove() { this.removed = true; }
}

function setup(t) {
  const previous = globalThis.document;
  globalThis.document = { createElement: (tag) => new FakeElement(tag) };
  t.after(() => { globalThis.document = previous; });
  const calls = [];
  const composer = new MobileComposer(new FakeElement("div"), {
    onSend: (text) => calls.push(["send", text]), onSteer: (text) => calls.push(["steer", text]),
    onStop: () => calls.push(["stop"]), onAttach: (file) => calls.push(["attach", file]),
    onRemoveAttachment: () => calls.push(["remove"]), onRetryAttachment: () => calls.push(["retry"])
  });
  const online = { controls: { send: true, stop: true, steer: true }, isStreaming: false, offline: false, uploadEnabled: true };
  composer.render(online);
  return { composer, calls, online };
}

function key(input, options = {}) {
  const event = Object.assign(new Event("keydown", { cancelable: true }), { key: "Enter", ...options });
  input.dispatchEvent(event);
  return event;
}

function type(composer, text) {
  composer.input.value = text;
  composer.input.dispatchEvent(new Event("input"));
}

test("inline draft remains editable offline without sending or losing text on reconnect", (t) => {
  const { composer, calls, online } = setup(t);
  composer.render({ ...online, offline: true });
  assert.equal(composer.input.tagName, "TEXTAREA");
  assert.equal(composer.input.disabled, false);
  type(composer, "  离线草稿\n第二行  ");
  composer.send.click();
  key(composer.input, { ctrlKey: true });
  assert.equal(composer.value(), "离线草稿\n第二行");
  assert.equal(composer.attach.disabled, true);
  assert.deepEqual(calls, []);
  composer.render(online);
  assert.equal(composer.input.value, "  离线草稿\n第二行  ");
  composer.send.click();
  assert.deepEqual(calls, [["send", "离线草稿\n第二行"]]);
});

test("mobile Enter and IME keep newlines while Ctrl or Cmd Enter send", (t) => {
  const { composer, calls } = setup(t);
  type(composer, "你好");
  for (const options of [{}, { shiftKey: true }, { ctrlKey: true, isComposing: true }, { metaKey: true, keyCode: 229 }]) {
    assert.equal(key(composer.input, options).defaultPrevented, false);
  }
  assert.deepEqual(calls, []);
  assert.equal(key(composer.input, { ctrlKey: true }).defaultPrevented, true);
  assert.equal(key(composer.input, { metaKey: true }).defaultPrevented, true);
  assert.deepEqual(calls, [["send", "你好"], ["send", "你好"]]);
});

test("attachments gate sends until ready and reservations prevent duplicate delivery or removal", (t) => {
  const { composer, calls } = setup(t);
  const attachment = { name: "图.png", status: "uploading", progress: 0.4 };
  type(composer, "说明");
  composer.syncAttachments([attachment]);
  composer.send.click();
  assert.equal(composer.send.disabled, true);
  composer.clear();
  composer.syncAttachments([{ ...attachment, status: "ready" }]);
  assert.equal(composer.send.disabled, false);
  composer.send.click();
  assert.deepEqual(calls, [["send", ""]]);
  composer.syncAttachments([{ ...attachment, status: "ready", reserved: true }]);
  assert.equal(composer.send.disabled, true);
  const row = composer.attachmentTray.children[0];
  assert.equal(row.children.at(-1).disabled, true);
  assert.equal(row.children[1].children[0].textContent, "等待电脑回执");
  row.children.at(-1).click();
  assert.equal(calls.length, 1);
});

test("running turns expose separate stop and steer controls with capability and attachment gates", (t) => {
  const { composer, calls, online } = setup(t);
  type(composer, "调整方向");
  assert.equal(composer.stop.hidden, true);
  assert.equal(composer.steer.hidden, true);
  composer.render({ ...online, isStreaming: true });
  assert.equal(composer.send.textContent, "排队");
  composer.stop.click();
  composer.steer.click();
  composer.send.click();
  assert.deepEqual(calls, [["stop"], ["steer", "调整方向"], ["send", "调整方向"]]);
  composer.syncAttachments([{ name: "a", status: "ready" }]);
  assert.equal(composer.steer.hidden, true);
  composer.render({ ...online, isStreaming: true, controls: { send: true, stop: false, steer: false } });
  composer.stop.click();
  composer.steer.click();
  assert.equal(calls.length, 3);
  composer.render({ ...online, isStreaming: true, offline: true });
  composer.stop.click();
  composer.steer.click();
  assert.equal(calls.length, 3);
});

test("attachment activation uses the laid-out native file control without forwarding clicks or changing the draft", (t) => {
  const { composer } = setup(t);
  type(composer, "保留这段草稿");
  assert.equal(composer.fileInput.hidden, false);
  assert.equal(composer.fileInput.tabIndex, 0);
  assert.equal(composer.fileInput.attributes["aria-label"], "添加附件");
  assert.equal(composer.attach, composer.fileInput);
  assert.ok(composer.row.children[0].children.includes(composer.fileInput));
  let forwardedClicks = 0, focusChanges = 0;
  composer.fileInput.click = () => { forwardedClicks += 1; };
  composer.input.blur = composer.input.focus = () => { focusChanges += 1; };
  composer.attach.dispatchEvent(new Event("click"));
  assert.equal(forwardedClicks, 0);
  assert.equal(focusChanges, 0);
  assert.equal(composer.input.value, "保留这段草稿");
});

test("the native attachment picker is disabled by every live upload gate", (t) => {
  const { composer, calls, online } = setup(t);
  const file = { name: "file.txt" };
  for (const blocked of [
    { ...online, offline: true },
    { ...online, uploadEnabled: false },
    { ...online, controls: { ...online.controls, send: false } }
  ]) {
    composer.render(blocked);
    assert.equal(composer.fileInput.disabled, true);
    composer.fileInput.files = [file];
    composer.fileInput.dispatchEvent(new Event("change"));
    assert.deepEqual(calls, []);
  }
  composer.render(online);
  assert.equal(composer.fileInput.disabled, false);
  composer.fileInput.files = [file];
  composer.fileInput.dispatchEvent(new Event("change"));
  assert.deepEqual(calls, [["attach", file]]);
  assert.equal(composer.fileInput.value, "");
});

test("file selection and retry honor live upload availability while draft attachments can be removed", (t) => {
  const { composer, calls, online } = setup(t);
  const file = { name: "file.txt" };
  composer.fileInput.files = [file];
  composer.fileInput.dispatchEvent(new Event("change"));
  assert.deepEqual(calls, [["attach", file]]);
  composer.render({ ...online, uploadEnabled: false, attachments: [{ name: "a", status: "paused" }] });
  composer.fileInput.dispatchEvent(new Event("change"));
  const row = composer.attachmentTray.children[0];
  assert.equal(row.children[2].disabled, true);
  row.children.at(-1).click();
  assert.deepEqual(calls, [["attach", file], ["remove"]]);
});

test("draft growth is capped and clearing or disposing leaves no active transmission control", (t) => {
  const { composer, calls } = setup(t);
  composer.input.scrollHeight = 220;
  type(composer, "长草稿");
  assert.equal(composer.input.style.height, "128px");
  assert.equal(composer.input.style.overflowY, "auto");
  composer.input.scrollHeight = 40;
  composer.clear();
  assert.equal(composer.input.style.height, "40px");
  assert.equal(composer.input.style.overflowY, "auto");
  assert.equal(composer.send.disabled, true);
  composer.setDraft("关闭之后");
  composer.dispose();
  composer.send.click();
  composer.submit(false);
  assert.deepEqual(calls, []);
  assert.equal(composer.el.removed, true);
});
