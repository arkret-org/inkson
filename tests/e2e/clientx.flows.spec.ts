import { expect, test } from "@playwright/test";
import { mockContrixApi } from "./mockContrixApi";

test.beforeEach(async ({ page }) => {
  await mockContrixApi(page);
  await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
});

test("bootstrap login and sync shows the connected workspace", async ({ page }) => {
  await expect(page.getByTestId("web-security-banner")).toContainText("non-production");
  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("status-label")).toContainText("Online");
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");
  await expect(page.getByTestId("space-list")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();

  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("timeline")).toContainText("Shared demo Space served by mocked serverx");
  await expect(page.getByTestId("sync-metrics")).toContainText("cx:commit:e2e");
  await expect(page.getByTestId("sync-metrics")).toContainText("cx:push:e2e");
  await expect(page.getByTestId("sync-metrics")).toContainText("1");
});

test("right panel shows space hierarchy without implicit cascade", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await expect(page.getByTestId("right-panel-space-info")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("hierarchy-no-cascade-note")).toContainText("membership");
  await expect(page.getByTestId("hierarchy-no-cascade-note")).toContainText("encryption");

  await expect(page.getByTestId("space-hierarchy-children")).toContainText("Design Child");
  await expect(page.getByTestId("space-hierarchy-children")).toContainText("cx:space:01js0childprivate000000000");
  await expect(page.getByTestId("space-hierarchy-children")).toContainText("lazy link");
  await expect(page.getByTestId("space-hierarchy-edges")).toContainText("unconfirmed_link");

  const hierarchyRequest = page.waitForRequest("**/api/v1/index/space-hierarchy?*");
  await page.getByTestId("right-panel-refresh-hierarchy").click();
  const requestUrl = new URL((await hierarchyRequest).url());
  expect(requestUrl.searchParams.get("depth")).toBe("2");
  expect(requestUrl.searchParams.get("include_unconfirmed")).toBe("true");
});

test("login page covers connection auth methods and token refresh", async ({ page }) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("login-panel")).toBeVisible();

  await page.getByTestId("test-connection-button").click();
  await expect(page.getByTestId("health-status")).toContainText("serverx");

  await page.getByTestId("passkey-login-button").click();
  await expect(page.getByTestId("passkey-status")).toContainText("Challenge received");

  await page.getByTestId("oidc-login-button").click();
  await expect(page.getByTestId("oidc-status")).toContainText("Redirect:");

  await page.getByTestId("dev-login-button").click();
  await expect(page.getByTestId("status-label")).toContainText("Online: dev-login");

  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await page.getByTestId("refresh-token-button").click();
  await expect(page.getByTestId("refresh-status")).toContainText("Refreshed");
});

test("registration wizard completes account bootstrap", async ({ page }) => {
  await page.goto("/register", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("register-panel")).toBeVisible();
  await expect(page.getByTestId("did-method-policy")).toContainText("did:plc");
  await expect(page.getByTestId("did-method-policy")).toContainText("did:uuid");

  await page.getByTestId("generate-did-button").click();
  await page.getByTestId("register-handle-input").fill("new-alice.example");
  await page.getByTestId("next-to-displayname").click();
  await page.getByTestId("register-display-name").fill("New Alice");
  await page.getByTestId("register-device-label").fill("alice-laptop");
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByTestId("generate-proof-button").click();
  await page.getByRole("button", { name: "Sign & Continue" }).click();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByTestId("complete-registration-button").click();

  await expect(page.getByTestId("registration-complete")).toContainText("Account registered successfully");
  await expect(page.getByTestId("register-summary-status")).toContainText("cx:didop:e2e");
});

test("registration can bind an existing protocol DID with scoped proof", async ({ page }) => {
  await page.goto("/register", { waitUntil: "domcontentloaded" });
  await page.getByTestId("register-path-bind").click();
  await page.getByTestId("bind-existing-did-input").fill("did:web:team.example");
  await page.getByTestId("bind-existing-did-button").click();
  await page.getByTestId("register-handle-input").fill("team.example");
  await page.getByTestId("next-to-displayname").click();
  await page.getByTestId("register-display-name").fill("Team Workspace");
  await page.getByTestId("register-device-label").fill("team-laptop");
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByTestId("generate-proof-button").click();
  await expect(page.getByTestId("proof-challenge")).toContainText("challenge-");
  await expect(page.getByTestId("proof-verification-method")).toHaveValue("authentication");
  await page.getByRole("button", { name: "Sign & Continue" }).click();
  await page.getByRole("button", { name: "Next" }).click();

  const didOperation = page.waitForRequest("**/api/v1/identity/submit-did-operation");
  await page.getByTestId("complete-registration-button").click();
  const didBody = await didOperation.then((request) => request.postDataJSON());
  expect(didBody.did).toBe("did:web:team.example");
  expect(didBody.operation.type).toBe("cx.did.bind");
  expect(didBody.operation.did_method).toBe("did:web");
  expect(didBody.operation.proof.audience).toContain("127.0.0.1");
  expect(didBody.operation.proof.verification_method).toBe("authentication");
  await expect(page.getByTestId("registration-complete")).toContainText("did:web:team.example");
});

test("settings can update account and device before session bootstrap", async ({ page }) => {
  await page.getByTestId("settings-nav-button").click();
  await expect(page.getByTestId("settings-panel")).toBeVisible();

  await page.getByTestId("settings-account-did-input").fill("did:web:bob.example");
  await page.getByTestId("settings-device-id-input").fill("dev_bob_1");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await page.getByTestId("settings-nav-button").click();
  await expect(page.getByTestId("settings-account-did-input")).toHaveValue("did:web:bob.example");
  await expect(page.getByTestId("settings-device-id-input")).toHaveValue("dev_bob_1");

  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("session-panel")).toContainText("session dev_bob_1");
  await expect(page.getByTestId("right-panel")).toContainText("did:web:bob.example");
  await expect(page.getByTestId("right-panel")).toContainText("dev_bob_1");
});

test("settings language selector mirrors shell direction for RTL locales", async ({ page }) => {
  await page.getByTestId("settings-nav-button").click();
  await page.getByTestId("section-theme").click();
  await expect(page.getByTestId("language-settings")).toBeVisible();
  await page.getByTestId("theme-night").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "night");
  await page.getByTestId("theme-system").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "system");

  await page.getByTestId("language-ar").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "rtl");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-direction", "rtl");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "ar");
  await expect(page.getByTestId("text-direction")).toContainText("rtl");

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "rtl");

  await page.getByTestId("settings-nav-button").click();
  await page.getByTestId("section-theme").click();
  await page.getByTestId("language-en").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "ltr");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "en");
});

test("kanban card detail exposes linked discussion and locked discussion boundaries", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await page.getByRole("link", { name: "Kanban" }).click();
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await page.getByTestId("kanban-card").first().click();
  await expect(page.getByTestId("card-detail-modal")).toContainText("Primary discussion");
  await expect(page.getByTestId("card-detail-modal")).toContainText("Locked discussion");
  await expect(page.getByTestId("card-detail-modal")).toContainText("card visibility != discussion visibility");
  await expect(page.getByTestId("locked-discussion-fail-closed")).toContainText("Opaque ref");
});

test("kanban queues card Event Envelopes and replays through events API", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await page.getByRole("link", { name: "Kanban" }).click();
  await page.getByTestId("add-card-button").first().click();
  await page.getByTestId("new-card-title-input").fill("Event envelope card");
  await page.getByTestId("save-card-button").click();
  await expect(page.getByTestId("board-event-record").last()).toContainText("cx.flow.create");
  await expect(page.getByTestId("board-event-record").last()).toContainText("actor_seq");
  await expect(page.getByTestId("board-event-record").last()).toContainText("schema cx.schema.core.v1");

  const eventSubmit = page.waitForRequest("**/api/v1/events/submit");
  await page.getByTestId("replay-board-queue").click();
  const eventBody = await eventSubmit.then((request) => request.postDataJSON());
  expect(eventBody.event.type).toBe("cx.flow.create");
  expect(eventBody.event.auth_refs).toContain("cx:capability:board.write");
  await expect(page.getByTestId("board-status")).toContainText("accepted");
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:event");
});

test("settings MIMI facade discovers drafts and runs interop actions", async ({ page }) => {
  await page.getByTestId("settings-nav-button").click();
  await page.getByTestId("section-mimi").click();
  await expect(page.getByTestId("mimi-interop-panel")).toBeVisible();
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("draft-ietf-mimi-protocol-06");
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("draft-ietf-mimi-content-08");
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("draft-ietf-mimi-room-policy-03");
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("draft-kohbrok-mimi-identifiers-01");

  await page.getByTestId("mimi-refresh-directory").click();
  await expect(page.getByTestId("mimi-directory-result")).toContainText("mimi://mimi.example.com");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("submit_message");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("identifier_query");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("proxy_download");

  await page.getByTestId("mimi-group-info").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("group-info 01JSMIMI participants 2");

  await page.getByTestId("mimi-identifier-query").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("identifier mimi://remote.example/alice reachable true");

  await page.getByTestId("mimi-proxy-download").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("proxy-download cx:blob:sha256:e2e");

  const submit = page.waitForRequest("**/api/v1/mimi/rooms/01JSMIMI/messages");
  await page.getByTestId("mimi-submit-message").click();
  expect((await submit).postDataJSON().source_format).toBe("text/markdown;variant=GFM-MIMI");
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("submit-message mimi-msg-e2e");
});

test("mobile viewport collapses shell chrome and keeps timeline usable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/timeline", { waitUntil: "domcontentloaded" });

  await expect(page.getByTestId("client-shell")).toBeVisible();
  await expect(page.getByTestId("sidebar")).toBeHidden();
  await expect(page.getByTestId("right-panel")).toBeHidden();
  await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
  await page.getByTestId("mobile-nav-toggle").click();
  await expect(page.getByTestId("mobile-nav-drawer")).toContainText("Board");
  await expect(page.getByTestId("main-view")).toBeVisible();
  await expect(page.getByTestId("composer-input")).toBeVisible();
});

test("accessibility smoke exposes landmarks and live timeline feed", async ({ page }) => {
  await expect(page.getByTestId("sidebar")).toHaveAttribute("role", "navigation");
  await expect(page.getByTestId("main-view")).toHaveAttribute("role", "main");
  await expect(page.getByTestId("right-panel")).toHaveAttribute("role", "complementary");

  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("timeline")).toHaveAttribute("role", "feed");
  await expect(page.getByTestId("timeline")).toHaveAttribute("aria-live", "polite");

  const sendRequest = page.waitForRequest("**/api/v1/messages/send");
  await page.getByTestId("composer-input").fill("a11y smoke message");
  await page.getByTestId("send-button").click();
  await sendRequest;

  await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("role", "article");
  await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("aria-label", /Timeline event from/);
});

test("directory search resolve and space selection flow works", async ({ page }) => {
  await page.getByTestId("directory-nav-button").click();
  await expect(page.getByTestId("directory-panel")).toBeVisible();

  await page.getByTestId("directory-search-input").fill("demo");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("directory-result")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("index-query-results")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("generic-entity-card")).toHaveAttribute("data-render-kind", "card");
  await expect(page.getByTestId("entity-type-label")).toContainText("space");
  await expect(page.getByTestId("entity-facets")).toContainText("renderable");
  await expect(page.getByTestId("projection-facets")).toContainText("item: stateful, rankable");
  await expect(page.getByTestId("unknown-facets-debug")).toContainText("com.example.preview");

  await page.getByTestId("directory-select-button").click();
  await page.getByTestId("resolve-selected-button").click();
  await expect(page.getByTestId("status-label")).toContainText("resolved public");
  await expect(page.getByTestId("selected-space-id")).toContainText("cx:space:01js0sp0000000000000000000");

  await page.getByTestId("tab-objects").click();
  await page.getByTestId("directory-search-input").fill("launch");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("protocol-object-results")).toContainText("Launch checklist card");
  await expect(page.getByTestId("protocol-object-results")).toContainText("Restricted discussion");
  await expect(page.getByTestId("protocol-object-results")).toContainText("locked");

  await page.getByTestId("tab-organizations").click();
  await page.getByTestId("directory-search-input").fill("contrix");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("org-result")).toContainText("Contrix Labs");
  await expect(page.getByTestId("org-result")).toContainText("listed");
  await page.getByTestId("org-search-members").click();
  await expect(page.getByTestId("tab-actors")).toHaveClass(/primary/);
  await expect(page.getByTestId("directory-search-input")).toHaveValue("contrix.example");
});

test("notifications are derived from index projections and respect per-space mute rules", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await page.getByTestId("notifications-nav-button").click();

  await expect(page.getByTestId("notifications-panel")).toBeVisible();
  await expect(page.getByTestId("notifications-panel")).toContainText("Alice sent a message in Demo Space");
  await expect(page.getByTestId("notifications-status")).toContainText("Loaded 2 notification projection");

  await page.getByTestId("mute-space-button").first().click();
  await expect(page.getByTestId("notifications-muted-empty")).toContainText("hidden by archive, type, or per-space mute rules");

  await page.getByTestId("settings-nav-button").click();
  await page.getByTestId("section-push").click();
  await expect(page.getByTestId("push-mute-summary")).toContainText("cx:space:01js0sp0000000000000000000");
  await page.getByTestId("settings-unmute-space").click();
  await expect(page.getByTestId("status-label")).toContainText("Unmuted");

  await page.getByTestId("notifications-nav-button").click();
  await expect(page.getByTestId("notifications-panel")).toContainText("You were invited to review Demo Space");
});

test("product account space lifecycle and canonical message flow works", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");

  await page.getByTestId("product-nav-button").click();
  await expect(page.getByTestId("product-panel")).toBeVisible();

  await page.getByTestId("register-account-button").click();
  await expect(page.getByTestId("account-flow")).toContainText("registered alice.example");

  await page.getByTestId("create-space-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("created cx:space:01js0productflow000000000000");
  await expect(page.getByTestId("selected-space-id")).toContainText("cx:space:01js0productflow000000000000");

  await page.getByTestId("add-member-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("members");
  await page.getByTestId("persist-message-button").click();
  await expect(page.getByTestId("message-persistence-flow")).toContainText("persisted cx:operation:e2e-product");
  const backfill = page.waitForRequest("**/api/v1/sync/backfill?space_id=*");
  await page.getByTestId("backfill-button").click();
  expect((await backfill).headers()["x-contrix-wait-for"]).toBe("sx:e2e:product");
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("timeline")).toContainText("persisted event cx:event:e2e-product");
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:product");
  await expect(page.getByTestId("sync-metrics")).toContainText("cx:commit:e2e-product");

  await page.getByTestId("product-nav-button").click();
  await page.getByTestId("remove-member-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("removed; members");
  await page.getByTestId("delete-space-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("deleted true");
});

test("chat creates discussion entities and sends structured mention payloads", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await page.getByRole("link", { name: "Chat" }).click();
  await expect(page.getByTestId("chat-panel")).toBeVisible();

  await page.getByTestId("new-channel-name").fill("Ops Announce");
  await page.getByTestId("new-channel-topic").fill("Broadcast deploy updates");
  await page.getByTestId("channel-kind-announce").click();
  const channelCommit = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("create-channel-button").click();
  const channelBody = await channelCommit.then((request) => request.postDataJSON());
  expect(channelBody.commit.operations[0].type).toBe("cx.flow.create");
  expect(channelBody.commit.operations[0].body.kind).toBe("announce");
  expect(channelBody.commit.operations[0].body.flow_id).toContain("cx:flow:");
  expect(channelBody.commit.operations[0].body.title).toBe("Ops Announce");
  expect(channelBody.commit.operations[0].body.rank).toBeTruthy();
  await expect(page.getByTestId("channel-item").last()).toContainText("Ops Announce");
  await expect(page.getByTestId("chat-status")).toContainText("flow committed");

  const chatSend = page.waitForRequest("**/api/v1/messages/send");
  await page.getByTestId("chat-input").fill("hello @did:web:bob.example about #cx:task:123");
  await page.getByTestId("send-chat-button").click();
  const chatBody = await chatSend.then((request) => request.postDataJSON());
  expect(chatBody.content.flow_id).toContain("cx:flow:");
  expect(chatBody.content.branch).toBe("discussion");
  expect(chatBody.content.mentions.some((mention: { target: string }) => mention.target === "did:web:bob.example")).toBeTruthy();
  expect(chatBody.content.mentions.some((mention: { target: string }) => mention.target === "cx:task:123")).toBeTruthy();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #cx:task:123");
  await expect(page.getByTestId("chat-mentions").last()).toContainText("did:web:bob.example");
  await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Revision chain");
  await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Tombstone");
  await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Linked discussion access");
});

test("forum anchors topics and stores comments separately from chat messages", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await page.getByRole("link", { name: "Forum" }).click();
  await expect(page.getByTestId("forum-panel")).toBeVisible();

  await page.getByTestId("new-topic-button").click();
  await page.getByTestId("topic-title-input").fill("Runbook Review");
  await page.getByTestId("topic-body-input").fill("Review this with @carol.example before #cx:task:follow-up");
  await page.getByTestId("topic-tags-input").fill("ops, review");
  await page.getByTestId("anchor-kind-run").click();
  await page.getByTestId("topic-anchor-target-input").fill("cx:run:incident-7");
  const topicCommit = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("submit-topic-button").click();
  const topicBody = await topicCommit.then((request) => request.postDataJSON());
  expect(topicBody.commit.operations[0].type).toBe("cx.topic.create");
  expect(topicBody.commit.operations[0].body.anchor_ref.kind).toBe("run");
  expect(topicBody.commit.operations[0].body.anchor_ref.target).toBe("cx:run:incident-7");
  expect(topicBody.commit.operations.some((operation: { type: string }) => operation.type === "cx.relation.create")).toBeTruthy();
  await expect(page.getByTestId("forum-topic").last()).toContainText("Runbook Review");
  await expect(page.getByTestId("forum-topic").last()).toContainText("cx:run:incident-7");

  await page.getByTestId("forum-topic").last().click();
  await expect(page.getByTestId("topic-anchor")).toContainText("cx:run:incident-7");
  const commentCommit = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("reply-input").fill("Looks good, track #cx:task:follow-up");
  await page.getByTestId("submit-reply-button").click();
  const commentBody = await commentCommit.then((request) => request.postDataJSON());
  expect(commentBody.commit.operations[0].type).toBe("cx.comment.create");
  expect(commentBody.commit.operations[0].target_ref).toContain("cx:topic:");
  await expect(page.getByTestId("forum-comment")).toContainText("Looks good, track #cx:task:follow-up");
  await expect(page.getByTestId("forum-status")).toContainText("comment committed");
});

test("agent runs and memory review submit lifecycle fact commits", async ({ page }) => {
  await page.getByTestId("connect-button").click();

  await page.getByTestId("agent-runs-nav-button").click();
  await expect(page.getByTestId("agent-runs-panel")).toBeVisible();
  await page.getByTestId("run-agent-input").fill("release-agent");
  await page.getByTestId("run-input").fill("Find blocker tasks");
  const createRun = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("start-run-button").click();
  const createRunBody = await createRun.then((request) => request.postDataJSON());
  expect(createRunBody.commit.operations[0].type).toBe("cx.run.create");
  expect(createRunBody.commit.operations[0].body.run_id).toContain("cx:run:");
  expect(createRunBody.commit.operations[0].body.status).toBe("running");
  await expect(page.getByTestId("agent-run-status")).toContainText("run created");
  await expect(page.getByTestId("agent-run").last()).toContainText("release-agent");

  const updateRun = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("update-run-button").last().click();
  const updateRunBody = await updateRun.then((request) => request.postDataJSON());
  expect(updateRunBody.commit.operations[0].type).toBe("cx.run.update");
  expect(updateRunBody.commit.operations[0].body.step.output).toBe("tool step recorded");
  await expect(page.getByTestId("agent-run-status")).toContainText("run updated");

  const completeRun = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("complete-run-button").last().click();
  const completeRunBody = await completeRun.then((request) => request.postDataJSON());
  expect(completeRunBody.commit.operations[0].type).toBe("cx.run.complete");
  expect(completeRunBody.commit.operations[0].body.status).toBe("completed");
  await expect(page.getByTestId("agent-run").last()).toContainText("completed");

  await page.getByTestId("memory-review-nav-button").click();
  await expect(page.getByTestId("memory-review-panel")).toBeVisible();
  await page.getByTestId("new-memory-input").fill("Agent should preserve provenance");
  const createMemory = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("capture-memory-button").click();
  const createMemoryBody = await createMemory.then((request) => request.postDataJSON());
  expect(createMemoryBody.commit.operations[0].type).toBe("cx.memory.create");
  expect(createMemoryBody.commit.operations[0].body.state).toBe("candidate");
  await expect(page.getByTestId("memory-status")).toContainText("memory captured");
  await expect(page.getByTestId("memory-entry").last()).toContainText("Agent should preserve provenance");

  await page.getByTestId("edit-memory-button").last().click();
  await page.getByTestId("memory-edit-input").fill("Agent should preserve provenance and source");
  const updateMemory = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("save-memory-edit").click();
  const updateMemoryBody = await updateMemory.then((request) => request.postDataJSON());
  expect(updateMemoryBody.commit.operations[0].type).toBe("cx.memory.update");
  expect(updateMemoryBody.commit.operations[0].body.content).toBe("Agent should preserve provenance and source");
  await expect(page.getByTestId("memory-status")).toContainText("memory updated");

  const confirmMemory = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("accept-memory-button").last().click();
  const confirmMemoryBody = await confirmMemory.then((request) => request.postDataJSON());
  expect(confirmMemoryBody.commit.operations[0].type).toBe("cx.memory.confirm");
  expect(confirmMemoryBody.commit.operations[0].target_ref).toContain("cx:memory:");
  await expect(page.getByTestId("memory-entry").last()).toContainText("confirmed");

  const supersedeMemory = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("supersede-memory-button").last().click();
  const supersedeMemoryBody = await supersedeMemory.then((request) => request.postDataJSON());
  expect(supersedeMemoryBody.commit.operations.some((operation: { type: string }) => operation.type === "cx.memory.create")).toBeTruthy();
  expect(supersedeMemoryBody.commit.operations.some((operation: { type: string }) => operation.type === "cx.memory.supersede")).toBeTruthy();
  await expect(page.getByTestId("memory-status")).toContainText("memory superseded");

  const invalidateMemory = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("reject-memory-button").last().click();
  const invalidateMemoryBody = await invalidateMemory.then((request) => request.postDataJSON());
  expect(invalidateMemoryBody.commit.operations[0].type).toBe("cx.memory.invalidate");
  await expect(page.getByTestId("memory-status")).toContainText("memory invalidated");
});

test("plaintext compose keeps request ids, revision chains, tombstones, and local MLS entries", async ({ page }) => {
  await page.getByRole("link", { name: "Timeline" }).click();
  await page.getByTestId("composer-input").fill("draft survives reload");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("composer-input")).toHaveValue("draft survives reload");

  const sendRequest = page.waitForRequest("**/api/v1/messages/send");
  await page.getByTestId("composer-input").fill("plain e2e message");
  await page.getByTestId("send-button").click();
  expect((await sendRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("timeline")).toContainText("plain e2e message");
  await expect(page.getByTestId("write-status")).toContainText("persisted cx:operation:e2e-message-1");

  const editRequest = page.waitForRequest(
    (request) => request.url().includes("/api/v1/messages/") && request.method() === "PATCH",
  );
  await page.getByTestId("edit-button").last().click();
  await page.getByTestId("edit-composer").locator("textarea").fill("plain e2e message edited");
  await page.getByTestId("save-edit-button").click();
  expect((await editRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("timeline")).toContainText("plain e2e message edited");
  await expect(page.getByTestId("revision-chain")).toContainText("plain e2e message");
  await expect(page.getByTestId("event-fact").last()).toContainText("cx:operation:e2e-edit");

  const redactRequest = page.waitForRequest(
    (request) => request.url().includes("/redact") && request.method() === "POST",
  );
  await page.getByTestId("redact-button").last().click();
  await page.getByTestId("confirm-redact-button").click();
  expect((await redactRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("redacted-tombstone")).toContainText("[Message redacted]");
  await expect(page.getByTestId("event-fact").last()).toContainText("tombstone cx:redaction:e2e:");

  await page.getByTestId("composer-input").fill("secret e2e message");
  await page.getByTestId("encrypt-local-button").click();
  await page.getByTestId("send-button").click();
  await expect(page.getByTestId("timeline")).toContainText("encrypted mls-rfc9420 epoch");
  await expect(page.getByTestId("right-panel")).toContainText("encrypted local payload");
});

test("timeline mark-read sends public receipt and stores private marker", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("timeline-event").first()).toBeVisible();

  const receiptRequest = page.waitForRequest("**/api/v1/receipts");
  await page.getByTestId("mark-read-button").first().click();
  const receiptBody = await receiptRequest.then((request) => request.postDataJSON());

  expect(receiptBody.space_id).toBe("cx:space:01js0sp0000000000000000000");
  expect(receiptBody.receipt_type).toBe("cx.receipt.read");
  expect(receiptBody.event_id).toContain("summary-cx:space");
  await expect(page.getByTestId("read-receipt-status")).toContainText("cx.receipt.read");
  await expect(page.getByTestId("read-marker-status")).toContainText("Read marker:");
  await expect(page.getByTestId("read-marker-badge")).toContainText("Read marker here");
});

test("timeline blob flow verifies hashes and authenticated downloads", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await page.getByRole("link", { name: "Timeline" }).click();

  const uploadRequest = page.waitForRequest("**/api/v1/blob/upload");
  await page.getByTestId("attach-blob-button").click();
  expect((await uploadRequest).headers()["authorization"]).toContain("Bearer");
  await expect(page.getByTestId("blob-status")).toContainText("upload hash ok");
  await expect(page.getByTestId("blob-status")).toContainText("no token in media URL");
  await expect(page.getByTestId("blob-policy-panel")).toContainText("unsafe or opaque type opens as attachment");
  await expect(page.getByTestId("blob-policy-panel")).toContainText("Thumbnail: cx:blob:sha256:e2e-thumb");

  const downloadRequest = page.waitForRequest("**/api/v1/blob/get?blob_ref=*");
  await page.getByTestId("verify-blob-download").click();
  const download = await downloadRequest;
  expect(download.headers()["authorization"]).toContain("Bearer");
  expect(download.url()).not.toContain("access_token");
  expect(download.url()).not.toContain("Bearer");
  await expect(page.getByTestId("blob-status")).toContainText("download verified sha256");
});

test("plaintext boundary blocks private drafts until exposure is acknowledged", async ({ page }) => {
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("plaintext-boundary-panel")).toBeVisible();
  await expect(page.getByTestId("plaintext-visible-services")).toContainText("configured server");
  await expect(page.getByTestId("plaintext-preview-disclosure")).toContainText("search");

  await page.getByTestId("private-plaintext-toggle").check();
  await page.getByTestId("composer-input").fill("private plaintext body");
  await page.getByTestId("send-button").click();
  await expect(page.getByTestId("write-status")).toContainText("plaintext blocked");
  await expect(page.getByTestId("plaintext-boundary-warning")).toContainText("not E2EE");

  const sendRequest = page.waitForRequest("**/api/v1/messages/send");
  await page.getByTestId("plaintext-boundary-ack").click();
  await page.getByTestId("send-button").click();
  expect((await sendRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("write-status")).toContainText("persisted cx:operation:e2e-message-1");
});

test("moderation report and to-device queue action hits protocol endpoints", async ({ page }) => {
  await page.getByRole("link", { name: "Timeline" }).click();
  const report = page.waitForRequest("**/api/v1/moderation/report");
  const deviceMessage = page.waitForRequest("**/api/v1/device_messages/yougen-txn-1");

  await page.getByTestId("report-queue-button").click();

  expect((await report).method()).toBe("POST");
  expect((await deviceMessage).method()).toBe("PUT");
});

test("space admin page handles metadata invites members and dangerous lifecycle", async ({ page }) => {
  await page.goto("/space/cx:space:01js0sp0000000000000000000/admin", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("space-admin-panel")).toBeVisible();
  await expect(page.getByTestId("admin-discussion-admission")).toContainText("Discussion-scoped external admission");
  await page.getByTestId("queue-discussion-admission").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("Discussion-scoped external admission");

  await page.getByTestId("space-name-input").fill("Updated Demo Space");
  await page.getByTestId("update-metadata-button").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("updated");

  await page.getByTestId("invite-target-input").fill("did:web:carol.example");
  const inviteCommit = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("send-invite-button").click();
  const inviteBody = await inviteCommit.then((request) => request.postDataJSON());
  expect(inviteBody.commit.operations[0].type).toBe("cx.invite.create");
  expect(inviteBody.commit.operations[0].body.invite_id).toBe("cx:invite:e2e");
  await expect(page.getByTestId("space-admin-status")).toContainText("invited did:web:carol.example");
  await expect(page.getByTestId("invite-row")).toContainText("pending");

  const acceptCommit = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("accept-invite-button").click();
  const acceptBody = await acceptCommit.then((request) => request.postDataJSON());
  expect(acceptBody.commit.operations[0].type).toBe("cx.invite.accept");
  await expect(page.getByTestId("invite-row")).toContainText("accepted");

  const cancelCommit = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("cancel-invite-button").click();
  const cancelBody = await cancelCommit.then((request) => request.postDataJSON());
  expect(cancelBody.commit.operations[0].type).toBe("cx.invite.cancel");
  await expect(page.getByTestId("invite-row")).toContainText("canceled");

  await page.getByTestId("rotate-space-epoch").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("rotated to epoch");

  await page.getByTestId("archive-space-button").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("archived");
});

test("audit page loads repo operations commits conflicts and snapshots", async ({ page }) => {
  await page.getByRole("link", { name: "Audit" }).click();
  await expect(page.getByTestId("audit-panel")).toBeVisible();
  await expect(page.getByTestId("event-envelope-audit")).toContainText("actor_seq");
  await expect(page.getByTestId("event-envelope-audit")).toContainText("auth_refs");

  await page.getByTestId("refresh-audit-button").click();
  await expect(page.getByTestId("audit-status")).toContainText("loaded");
  await expect(page.getByTestId("operation-row")).toContainText("cx:op:audit");
  await expect(page.getByTestId("commit-row")).toContainText("cx:commit:e2e");
});

test("audit capability explanation shows grants constraints and frontier reason", async ({ page }) => {
  await page.getByRole("link", { name: "Audit" }).click();
  await expect(page.getByTestId("capability-explanation")).toBeVisible();

  await page.getByTestId("load-capabilities-button").click();
  await expect(page.getByTestId("capability-decision")).toContainText("allowed");
  await expect(page.getByTestId("capability-frontier")).toContainText("cx:statehash:e2e");
  await expect(page.getByTestId("capability-reason")).toContainText("frontier_current");
  await expect(page.getByTestId("capability-grant-row")).toContainText("cx:grant:e2e");
  await expect(page.getByTestId("capability-resource-selectors")).toContainText("space:cx:space");
  await expect(page.getByTestId("capability-constraints")).toContainText("temporal");
  await expect(page.getByTestId("capability-allowed-facets")).toContainText("renderable, stateful");
  await expect(page.getByTestId("capability-delegation-chain")).toContainText("cx:grant:root");
});

test("devices panel reflects key queue push and crypto state after bootstrap", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");

  await page.getByTestId("devices-nav-button").click();
  await expect(page.getByTestId("devices-panel")).toBeVisible();
  await expect(page.getByTestId("device-verification-workbench")).toContainText("SAS");
  await expect(page.getByTestId("device-summary")).toContainText("Queue1");
  await expect(page.getByTestId("device-summary")).toContainText("Pushcx:push:e2e");
  await expect(page.getByTestId("device-summary")).toContainText("Cryptosession dev_yougen");
  await page.getByTestId("revoke-impact-button").click();
  await expect(page.getByTestId("device-summary")).toContainText("Revocation will require MLS remove proposal");
});

test("invalid server URL surfaces an error state", async ({ page }) => {
  await page.getByTestId("server-url-input").fill("not a url");
  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("status-label")).toContainText("Error: invalid URL");
});

test("insecure remote http endpoint is rejected before connect", async ({ page }) => {
  await page.getByTestId("server-url-input").fill("http://contrix.example");
  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("status-label")).toContainText("HTTPS is required for non-local servers");
});

test("call panel loads server ICE configuration", async ({ page }) => {
  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await page.getByTestId("refresh-ice-config").click();

  await expect(page.getByTestId("ice-config")).toContainText("stun:stun.serverx.local:3478");
  await expect(page.getByTestId("ice-config")).toContainText("turn:turn.serverx.local:3478?transport=udp");
  await expect(page.getByTestId("ice-ttl")).toContainText("600s");
});

test("visual smoke renders core product pages on desktop and mobile", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  for (const [route, testId] of [
    ["/", "dashboard-panel"],
    ["/register", "register-panel"],
    ["/kanban", "kanban-panel"],
    ["/chat", "chat-panel"],
    ["/settings", "settings-panel"],
  ] as const) {
    await page.goto(route, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId(testId)).toBeVisible();
    const shot = await page.screenshot();
    expect(shot.length).toBeGreaterThan(10_000);
  }

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/kanban", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
  const mobileShot = await page.screenshot();
  expect(mobileShot.length).toBeGreaterThan(10_000);
});

test("release readiness panel keeps production blockers visible", async ({ page }) => {
  await page.getByTestId("readiness-nav-button").click();

  await expect(page.getByTestId("readiness-panel")).toBeVisible();
  await expect(page.getByTestId("release-summary")).toContainText("Not production-ready");
  await expect(page.getByTestId("server-describe-readiness")).toContainText("did:web:serverx.local");
  await expect(page.getByTestId("local-profile-support")).toContainText("minimal_client");
  await expect(page.getByTestId("profile-readiness")).toContainText("chat_only_client");
  await expect(page.getByTestId("profile-readiness")).toContainText("ready");
  await expect(page.getByTestId("readiness-panel")).toContainText("Production registration");
  await expect(page.getByTestId("readiness-panel")).toContainText("Create space");
  await expect(page.getByTestId("readiness-panel")).toContainText("Invite, add, remove, and kick members");
  await expect(page.getByTestId("readiness-panel")).toContainText("Leave, archive, and delete space");

  await page.getByTestId("blocked-workflow-button").first().click();
  await expect(page.getByTestId("status-label")).toContainText("Blocked:");
});
