import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import { activeConversationModel, MOBILE_HEADER_MAX_PX, shouldFollowBottom } from "../src/mobile/view-model.js";
import { createReplicaState } from "../src/mobile/reducer.js";

function state() {
  return createReplicaState({
    transport: { status: "connected" },
    presence: { mac: { status: "online", sessionId: "mac", connectionGeneration: 1 } },
    capabilities: { semantic_stream: true, stop: true, steer: true, approval: true, history_list: true, history_select: true },
    activeConversationId: "conv",
    conversations: {
      conv: {
        id: "conv", title: "A long mobile conversation", revision: 4, activeTurnId: "turn",
        turnOrder: ["turn"], turns: {
          turn: {
            id: "turn", status: "running", messageOrder: ["message"], activityOrder: [], approvalOrder: [], artifactOrder: [],
            activities: {}, approvals: {}, artifacts: {},
            messages: { message: { id: "message", role: "assistant", blockOrder: ["text"], blocks: { text: { id: "text", type: "text", text: "streaming" } } } }
          }
        }
      }
    }
  });
}

test("mobile model keeps compact header and exposes one streaming message", () => {
  const model = activeConversationModel(state());
  assert.equal(MOBILE_HEADER_MAX_PX, 56);
  assert.equal(model.title, "A long mobile conversation");
  assert.equal(model.messages[0].text, "streaming");
  assert.equal(model.controls.stop, true);
  assert.equal(model.controls.steer, true);
});

test("offline state remains readable but disables every desktop mutation", () => {
  const offline = state();
  offline.transport.status = "disconnected";
  const model = activeConversationModel(offline);
  assert.equal(model.messages[0].text, "streaming");
  assert.deepEqual(model.controls, { send: false, stop: false, steer: false, approval: false, history: false, historySelect: false });
});

test("scroll policy follows only when user stays near bottom", () => {
  assert.equal(shouldFollowBottom({ scrollHeight: 1000, clientHeight: 600, scrollTop: 340 }), true);
  assert.equal(shouldFollowBottom({ scrollHeight: 1000, clientHeight: 600, scrollTop: 100 }), false);
});

test("composer rollback restores separate stop and steer controls", async () => {
  const composer = await readFile(new URL("../src/mobile/components/composer.js", import.meta.url), "utf8");
  const inputModal = await readFile(new URL("../src/mobile/components/message-input-modal.js", import.meta.url), "utf8");
  assert.match(inputModal, /claudian-remote-modal-toolbar/);
  assert.match(inputModal, /claudian-remote-modal-stop/);
  assert.match(inputModal, /claudian-remote-modal-steer/);
  assert.doesNotMatch(composer, /claudian-remote-turn-menu|primaryActionMode/);
});

test("input modal keeps every action above the keyboard-owned textarea", async () => {
  const composer = await readFile(new URL("../src/mobile/components/composer.js", import.meta.url), "utf8");
  const inputModal = await readFile(new URL("../src/mobile/components/message-input-modal.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");

  assert.match(inputModal, /contentEl\.append\(this\.toolbar, this\.input, this\.attachmentTray, this\.fileInput\)/);
  assert.match(inputModal, /onPresentedChange\(true\)/);
  assert.match(inputModal, /onPresentedChange\(false\)/);
  assert.match(composer, /onPresentedChange:\s*\(presented\)\s*=>\s*\{\s*this\.el\.hidden\s*=\s*presented/);
  assert.doesNotMatch(inputModal, /this\.actions|claudian-remote-modal-cancel|"取消"/);
  for (const label of ["附件", "停止", "插队", "发送"]) assert.match(inputModal, new RegExp(`"${label}"`));
  assert.doesNotMatch(css, /claudian-remote-modal-actions/);
  assert.match(css, /claudian-remote-modal-toolbar[\s\S]*?min-height:\s*36px/);
  assert.match(css, /claudian-remote-modal-input[\s\S]*?min-height:\s*120px/);
});

test("input modal removes host title chrome and keeps actions on one row", async () => {
  const inputModal = await readFile(new URL("../src/mobile/components/message-input-modal.js", import.meta.url), "utf8");
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");

  assert.doesNotMatch(inputModal, /setTitle\("\u8f93\u5165\u6d88\u606f"\)/);
  assert.match(inputModal, /titleEl\.hidden\s*=\s*true/);
  assert.match(inputModal, /querySelector\("\.modal-close-button"\)/);
  assert.match(inputModal, /closeButton\.hidden\s*=\s*true/);
  assert.match(css, /claudian-remote-input-modal\s+\.modal-(?:header|title)[\s\S]*?display:\s*none\s*!important/);
  assert.match(css, /claudian-remote-modal-toolbar\s*\{[\s\S]*?flex-wrap:\s*nowrap/);
  assert.match(css, /claudian-remote-modal-toolbar button\s*\{[\s\S]*?flex:\s*1\s+1\s+0/);
});

test("mobile stylesheet reserves compact header and 44px touch targets", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  assert.match(css, /max-height:\s*56px/);
  assert.match(css, /--cr-touch:\s*44px/);
  assert.match(css, /env\(safe-area-inset-bottom\)/);
  assert.match(css, /border-radius:\s*22px/);
});

test("mobile composer retains safe-area footer padding", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const composerWrapRule = css.match(/\.claudian-remote-composer-wrap\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(composerWrapRule, /padding-bottom:[^;]*env\(safe-area-inset-bottom\)/);
  assert.match(composerWrapRule, /border-top:/);
  assert.match(composerWrapRule, /background:\s*var\(--background-primary\)/);
  assert.doesNotMatch(css, /--view-bottom-spacing|--cr-bottom-clearance|--cr-active-bottom-clearance/);
});

test("main chat view opens a native input modal and never owns a keyboard input", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const view = await readFile(new URL("../src/mobile/view.js", import.meta.url), "utf8");
  const composer = await readFile(new URL("../src/mobile/components/composer.js", import.meta.url), "utf8");
  const inputModal = await readFile(new URL("../src/mobile/components/message-input-modal.js", import.meta.url), "utf8");
  const composerWrapRule = css.match(/\.claudian-remote-composer-wrap\s*\{([^}]*)\}/)?.[1] || "";

  assert.match(composer, /MessageInputModal/);
  assert.match(composer, /claudian-remote-composer-launch/);
  assert.doesNotMatch(composer, /element\("textarea"|type\s*=\s*"file"/);
  assert.match(inputModal, /extends Modal/);
  assert.match(inputModal, /element\("textarea"/);
  assert.match(inputModal, /type\s*=\s*"file"/);
  assert.match(inputModal, /排队/);
  assert.match(inputModal, /插队/);
  assert.match(inputModal, /停止/);

  assert.doesNotMatch(css, /claudian-remote-mobile-active|--keyboard-height/);
  assert.doesNotMatch(view, /HOST_CHROME_CLASS|active-leaf-change/);
  assert.match(composerWrapRule, /--navbar-height/);
  assert.doesNotMatch(composerWrapRule, /position:\s*(?:fixed|absolute|sticky)/);
  assert.doesNotMatch(composerWrapRule, /(?:^|\n)\s*(?:top|bottom|transform|height)\s*:/);
  assert.doesNotMatch(css, /--view-bottom-spacing|--cr-host-navbar-clearance/);
});

test("mobile view delegates keyboard-era sizing to the Obsidian host", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const mobileViewRule = css.match(/\.claudian-remote-mobile-view\s*\{([^}]*)\}/)?.[1] || "";

  assert.match(mobileViewRule, /padding:\s*0\s*!important/);
  assert.match(mobileViewRule, /overflow:\s*hidden\s*!important/);
  assert.doesNotMatch(mobileViewRule, /position:\s*relative/);
  assert.doesNotMatch(mobileViewRule, /(?:^|\n)\s*height:\s*100%/);
  assert.doesNotMatch(mobileViewRule, /min-height:/);
  assert.doesNotMatch(mobileViewRule, /overscroll-behavior:/);
});

test("bottom sheets rollback to the iOS safe area", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  assert.match(css, /claudian-remote-sheet[\s\S]*box-sizing:\s*border-box/);
  assert.match(css, /claudian-remote-sheet[\s\S]*padding:[^;]*env\(safe-area-inset-bottom\)/);
});

test("composer rollback restores the stable footer and removes the floating menu", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const composerWrapRule = css.match(/\.claudian-remote-composer-wrap\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(css, /\.claudian-remote-modal-toolbar\s*\{/);
  assert.doesNotMatch(css, /\.claudian-remote-turn-menu\s*\{/);
  assert.match(composerWrapRule, /flex:\s*0\s+0\s+auto/);
  assert.doesNotMatch(composerWrapRule, /position:\s*(absolute|relative)/);
  assert.doesNotMatch(css, /\.claudian-remote-shell\.is-keyboard-open\s*\{/);
  assert.doesNotMatch(css, /--cr-visible-height/);
  assert.doesNotMatch(css, /\.claudian-remote-composer-wrap:focus-within\s*\{/);
  assert.match(css, /\.claudian-remote-composer-launch\s*\{[\s\S]*?border-radius:\s*22px/);
  assert.match(css, /\.claudian-remote-composer-launch\s*\{[\s\S]*?border-radius:\s*22px/);
  assert.match(css, /\.claudian-remote-modal-input\s*\{[\s\S]*?font-size:\s*16px/);
});

test("mobile rollback delegates keyboard resizing to Obsidian and keeps reduced-motion-safe sheets", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const history = await readFile(new URL("../src/mobile/components/history-drawer.js", import.meta.url), "utf8");
  const view = await readFile(new URL("../src/mobile/view.js", import.meta.url), "utf8");
  const composer = await readFile(new URL("../src/mobile/components/composer.js", import.meta.url), "utf8");

  assert.doesNotMatch(css, /claudian-remote-composer-wrap[\s\S]*transition:[^;]*padding-bottom/);
  assert.doesNotMatch(view, /MobileViewportController/);
  assert.doesNotMatch(view, /--cr-visible-height|is-keyboard-open/);
  assert.match(css, /claudian-remote-overlay\.is-open[\s\S]*claudian-remote-overlay\.is-open\s+\.claudian-remote-sheet/);
  assert.doesNotMatch(css, /claudian-remote-turn-menu\.is-open/);
  assert.match(css, /prefers-reduced-motion:\s*reduce[\s\S]*transition:\s*none/);
  assert.match(history, /classList\.toggle\("is-open"/);
  assert.match(view, /detailsOverlay\.classList\.toggle\("is-open"/);
  assert.doesNotMatch(composer, /turnMenu|onTurnMenuChange/);
});

test("running activity uses a reduced-motion-safe breathing animation", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  assert.match(css, /@keyframes\s+claudian-remote-breathe/);
  assert.match(css, /claudian-remote-activity\.is-running[\s\S]*animation:\s*claudian-remote-breathe/);
  assert.match(css, /prefers-reduced-motion:\s*reduce[\s\S]*claudian-remote-activity\.is-running[\s\S]*animation:\s*none/);
});

test("production mobile build does not globally suppress the running animation", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  assert.doesNotMatch(css, /claudian-remote-mobile-view \.claudian-remote-shell \*[\s\S]*animation:\s*none\s*!important/);
  assert.doesNotMatch(css, /claudian-remote-mobile-view \.claudian-remote-shell \*[\s\S]*transition:\s*none\s*!important/);
});

test("ready attachments are synchronously reserved before an async message submit", async () => {
  const view = await readFile(new URL("../src/mobile/view.js", import.meta.url), "utf8");
  const inputModal = await readFile(new URL("../src/mobile/components/message-input-modal.js", import.meta.url), "utf8");
  assert.match(view, /createDeliveryId\(\)[\s\S]*reserveReady\(deliveryId\)[\s\S]*composer\.syncAttachments/);
  assert.match(view, /consumeReservation\(deliveryId\)/);
  assert.match(view, /releaseReservation\(deliveryId\)/);
  assert.match(inputModal, /item\.status === "ready" && !item\.reserved/);
});
