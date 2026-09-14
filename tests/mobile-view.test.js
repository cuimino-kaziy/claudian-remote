import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import { activeConversationModel, MOBILE_HEADER_MAX_PX, shouldFollowBottom } from "../src/mobile/view-model.js";
import { createReplicaState } from "../src/mobile/reducer.js";

function state() {
  const value = createReplicaState({
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
  // This view-model fixture represents an already confirmed live handshake.
  value.compatibility = { writable: true, reason: "ready" };
  value.compatibilityMode = false;
  return value;
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
  assert.deepEqual(model.controls, {
    send: false, stop: false, steer: false, approval: false,
    history: false, historySelect: false, historyNew: false, historyRename: false, historyArchive: false
  });
});

test("scroll policy follows only when user stays near bottom", () => {
  assert.equal(shouldFollowBottom({ scrollHeight: 1000, clientHeight: 600, scrollTop: 340 }), true);
  assert.equal(shouldFollowBottom({ scrollHeight: 1000, clientHeight: 600, scrollTop: 100 }), false);
});

test("mobile stylesheet reserves compact header and 44px touch targets", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  assert.match(css, /max-height:\s*56px/);
  assert.match(css, /--cr-touch:\s*44px/);
  assert.match(css, /env\(safe-area-inset-bottom\)/);
  assert.match(css, /claudian-remote-history-search[\s\S]*?min-height:\s*var\(--cr-touch\)/);
  assert.match(css, /claudian-remote-history-action[\s\S]*?min-height:\s*var\(--cr-touch\)/);
});

test("mobile view seeds and refreshes readiness from device pairing settings", async () => {
  const view = await readFile(new URL("../src/mobile/view.js", import.meta.url), "utf8");
  const reducer = await readFile(new URL("../src/mobile/reducer.js", import.meta.url), "utf8");
  assert.match(view, /seed\.pairing\s*=\s*\{\s*status:\s*pairingStatusFromSettings\(this\.plugin\.settings\)/);
  assert.match(view, /setInterval\(\(\)\s*=>\s*this\.refreshPairingState\(\),\s*1000\)/);
  assert.match(view, /clearInterval\(this\.pairingWatcher\)/);
  assert.match(reducer, /setPairingStatus\(status\)/);
});

test("mobile composer retains safe-area footer padding", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const composerWrapRule = css.match(/\.claudian-remote-composer-wrap\s*\{([^}]*)\}/)?.[1] || "";
  assert.match(composerWrapRule, /padding-bottom:[^;]*env\(safe-area-inset-bottom\)/);
  assert.match(composerWrapRule, /border-top:/);
  assert.match(composerWrapRule, /background:\s*var\(--background-primary\)/);
  assert.doesNotMatch(css, /--view-bottom-spacing|--cr-bottom-clearance|--cr-active-bottom-clearance/);
});

test("mobile view delegates keyboard-era sizing to the Obsidian host", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const mobileViewRule = css.match(/\.claudian-remote-mobile-view\s*\{([^}]*)\}/)?.[1] || "";

  assert.match(mobileViewRule, /padding:\s*0\s*!important/);
  assert.match(mobileViewRule, /overflow:\s*hidden\s*!important/);
  assert.match(mobileViewRule, /position:\s*relative/);
  assert.doesNotMatch(mobileViewRule, /(?:^|\n)\s*height:\s*100%/);
  assert.doesNotMatch(mobileViewRule, /min-height:/);
  assert.doesNotMatch(mobileViewRule, /overscroll-behavior:/);
});

test("bottom sheets rollback to the iOS safe area", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  assert.match(css, /claudian-remote-sheet[\s\S]*box-sizing:\s*border-box/);
  assert.match(css, /claudian-remote-sheet[\s\S]*padding:[^;]*env\(safe-area-inset-bottom\)/);
});

test("mobile sheets preserve host chrome and reduced-motion behavior", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const history = await readFile(new URL("../src/mobile/components/history-drawer.js", import.meta.url), "utf8");
  const view = await readFile(new URL("../src/mobile/view.js", import.meta.url), "utf8");
  const composer = await readFile(new URL("../src/mobile/components/composer.js", import.meta.url), "utf8");

  assert.doesNotMatch(css, /claudian-remote-composer-wrap[\s\S]*transition:[^;]*padding-bottom/);
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
  const composer = await readFile(new URL("../src/mobile/components/composer.js", import.meta.url), "utf8");
  assert.match(view, /createDeliveryId\(\)[\s\S]*reserveReady\(deliveryId\)[\s\S]*composer\.syncAttachments/);
  assert.match(view, /consumeReservation\(deliveryId\)/);
  assert.match(view, /releaseReservation\(deliveryId\)/);
  assert.match(composer, /item\.status === "ready" && !item\.reserved/);
});

test("inline composer stays in the host layout and does not change native navigation", async () => {
  const css = await readFile(new URL("../styles.css", import.meta.url), "utf8");
  const view = await readFile(new URL("../src/mobile/view.js", import.meta.url), "utf8");
  const composer = await readFile(new URL("../src/mobile/components/composer.js", import.meta.url), "utf8");
  const rule = css.match(/\.claudian-remote-composer-wrap\s*\{([^}]*)\}/)?.[1] || "";
  assert.doesNotMatch(composer, /MessageInputModal|composer-launch/);
  assert.doesNotMatch(rule, /position:\s*(?:fixed|absolute|sticky)/);
  assert.doesNotMatch(view, /HOST_CHROME_CLASS|active-leaf-change/);
  assert.doesNotMatch(css, /claudian-remote-mobile-active|--keyboard-height|--view-bottom-spacing|--cr-host-navbar-clearance/);
});
