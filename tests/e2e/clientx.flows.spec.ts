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

test("directory search resolve and space selection flow works", async ({ page }) => {
  await page.getByTestId("directory-nav-button").click();
  await expect(page.getByTestId("directory-panel")).toBeVisible();

  await page.getByTestId("directory-search-input").fill("demo");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("directory-result")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("index-query-results")).toContainText("Contrix Demo Space");

  await page.getByTestId("directory-select-button").click();
  await page.getByTestId("resolve-selected-button").click();
  await expect(page.getByTestId("status-label")).toContainText("resolved public");
  await expect(page.getByTestId("selected-space-id")).toContainText("cx:space:01js0sp0000000000000000000");

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

test("product account contacts space lifecycle and canonical message flow works", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");

  await page.getByTestId("product-nav-button").click();
  await expect(page.getByTestId("product-panel")).toBeVisible();

  await page.getByTestId("register-account-button").click();
  await expect(page.getByTestId("account-flow")).toContainText("registered alice.example");

  await page.getByTestId("request-contact-button").click();
  await expect(page.getByTestId("contacts-flow")).toContainText("contact did:web:bob.example pending");
  await page.getByTestId("list-contacts-button").click();
  await expect(page.getByTestId("contacts-flow")).toContainText("1 contact(s)");
  await page.getByTestId("accept-contact-button").click();
  await expect(page.getByTestId("contacts-flow")).toContainText("contact did:web:bob.example accepted");

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

test("chat creates channel entities and sends structured mention payloads", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await page.getByRole("link", { name: "Chat" }).click();
  await expect(page.getByTestId("chat-panel")).toBeVisible();

  await page.getByTestId("new-channel-name").fill("Ops Announce");
  await page.getByTestId("new-channel-topic").fill("Broadcast deploy updates");
  await page.getByTestId("channel-kind-announce").click();
  const channelCommit = page.waitForRequest("**/api/v1/repo/submit-commit");
  await page.getByTestId("create-channel-button").click();
  const channelBody = await channelCommit.then((request) => request.postDataJSON());
  expect(channelBody.commit.operations[0].type).toBe("cx.channel.create");
  expect(channelBody.commit.operations[0].body.kind).toBe("announce");
  expect(channelBody.commit.operations[0].body.channel_id).toContain("cx:channel:");
  await expect(page.getByTestId("channel-item").last()).toContainText("Ops Announce");
  await expect(page.getByTestId("chat-status")).toContainText("channel committed");

  const chatSend = page.waitForRequest("**/api/v1/messages/send");
  await page.getByTestId("chat-input").fill("hello @did:web:bob.example about #cx:task:123");
  await page.getByTestId("send-chat-button").click();
  const chatBody = await chatSend.then((request) => request.postDataJSON());
  expect(chatBody.content.channel_id).toContain("cx:channel:");
  expect(chatBody.content.mentions.some((mention: { target: string }) => mention.target === "did:web:bob.example")).toBeTruthy();
  expect(chatBody.content.mentions.some((mention: { target: string }) => mention.target === "cx:task:123")).toBeTruthy();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #cx:task:123");
  await expect(page.getByTestId("chat-mentions").last()).toContainText("did:web:bob.example");
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

test("moderation report and to-device queue action hits protocol endpoints", async ({ page }) => {
  await page.getByRole("link", { name: "Timeline" }).click();
  const report = page.waitForRequest("**/api/v1/moderation/report");
  const deviceMessage = page.waitForRequest("**/api/v1/device_messages/chask-txn-1");

  await page.getByTestId("report-queue-button").click();

  expect((await report).method()).toBe("POST");
  expect((await deviceMessage).method()).toBe("PUT");
});

test("contacts page searches requests and accepts a contact", async ({ page }) => {
  await page.getByRole("link", { name: "Contacts" }).click();
  await expect(page.getByTestId("contacts-panel")).toBeVisible();

  await page.getByTestId("tab-search").click();
  await page.getByTestId("contact-search-input").fill("bob");
  await page.getByTestId("contact-search-button").click();
  await expect(page.getByTestId("search-result")).toContainText("bob.example");

  await page.getByTestId("send-contact-request").click();
  await expect(page.getByTestId("contacts-status")).toContainText("sent to did:web:bob.example");

  await page.getByTestId("tab-incoming").click();
  await page.getByTestId("refresh-incoming").click();
  await expect(page.getByTestId("incoming-request")).toContainText("did:web:alice.example");
  await page.getByTestId("accept-request-button").click();
  await expect(page.getByTestId("contacts-status")).toContainText("accepted did:web:alice.example");
});

test("space admin page handles metadata invites members and dangerous lifecycle", async ({ page }) => {
  await page.goto("/space/cx:space:01js0sp0000000000000000000/admin", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("space-admin-panel")).toBeVisible();

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

  await page.getByTestId("refresh-audit-button").click();
  await expect(page.getByTestId("audit-status")).toContainText("loaded");
  await expect(page.getByTestId("operation-row")).toContainText("cx:op:audit");
  await expect(page.getByTestId("commit-row")).toContainText("cx:commit:e2e");
});

test("devices panel reflects key queue push and crypto state after bootstrap", async ({ page }) => {
  await page.getByTestId("connect-button").click();
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");

  await page.getByTestId("devices-nav-button").click();
  await expect(page.getByTestId("devices-panel")).toBeVisible();
  await expect(page.getByTestId("device-summary")).toContainText("Queue1");
  await expect(page.getByTestId("device-summary")).toContainText("Pushcx:push:e2e");
  await expect(page.getByTestId("device-summary")).toContainText("Cryptosession dev_chask");
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

test("release readiness panel keeps production blockers visible", async ({ page }) => {
  await page.getByTestId("readiness-nav-button").click();

  await expect(page.getByTestId("readiness-panel")).toBeVisible();
  await expect(page.getByTestId("release-summary")).toContainText("Not production-ready");
  await expect(page.getByTestId("readiness-panel")).toContainText("Production registration");
  await expect(page.getByTestId("readiness-panel")).toContainText("Contacts and friends");
  await expect(page.getByTestId("readiness-panel")).toContainText("Create space");
  await expect(page.getByTestId("readiness-panel")).toContainText("Invite, add, remove, and kick members");
  await expect(page.getByTestId("readiness-panel")).toContainText("Leave, archive, and delete space");

  await page.getByTestId("blocked-workflow-button").first().click();
  await expect(page.getByTestId("status-label")).toContainText("Blocked:");
});
