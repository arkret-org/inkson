import { byClass } from "./strandsHarness";
import { expect, test } from "@playwright/test";
import { mockArkretApi } from "./mockArkretApi";

for (const viewport of [
  { width: 805, height: 515 },
  { width: 707, height: 397 },
  { width: 390, height: 600 },
]) {
  test(`changed Station details remain readable at ${viewport.width}x${viewport.height}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await mockArkretApi(page);
    await page.goto("/login", { waitUntil: "domcontentloaded" });
    await expect(page.locator(".auth-primary")).toBeVisible();
    const description = await page.evaluate(async () => {
      const response = await fetch("https://server.local/_arkret/describe");
      const value = await response.json();
      // This login fixture must confirm the exact selected Station base.
      value.transport_bindings[0].base_url = "https://server.local/";
      return value;
    });
    await page.route("https://server.local/_arkret/describe*", (route) => route.fulfill({ json: description }));
    await page.getByRole("textbox", { name: "Account server URL" }).fill("https://server.local/");
    await page.evaluate(async () => {
      const longPath = "previous-authentication-provider/".repeat(30);
      const binding = {
        base_url: "https://server.local/",
        service_id: "ak:did_core:web:previous-station.example",
        trust_domain: "ak:trust_domain:previous-station.example",
        authentication_metadata: {
          account_authority: {
            origin: "https://previous-auth.example",
            gate_account_base_url: `https://previous-auth.example/${longPath}_arkret/gate/account`,
          },
          methods: [{
            method: "oidc",
            issuer_uri: `https://previous-auth.example/${longPath}`,
            openid_configuration_url: `https://previous-auth.example/${longPath}.well-known/openid-configuration`,
            client_id: "previous-client-".repeat(25),
            scopes: ["openid", "profile"],
            grant_exchange: { kind: "account_handoff" },
          }],
          did_binding_methods: [],
        },
      };
      await new Promise<void>((resolve, reject) => {
        const opening = indexedDB.open("inkson.station-connections.v1", 1);
        opening.onupgradeneeded = () => opening.result.createObjectStore("bindings");
        opening.onerror = () => reject(opening.error);
        opening.onsuccess = () => {
          const db = opening.result;
          const tx = db.transaction("bindings", "readwrite");
          tx.objectStore("bindings").put(JSON.stringify(binding), binding.base_url);
          tx.oncomplete = () => { db.close(); resolve(); };
          tx.onerror = () => { db.close(); reject(tx.error); };
        };
      });
    });
    await page.locator(".auth-primary").click();
    const review = byClass(page, "station-connection-review");
    await expect(review).toBeVisible();
    await expect(review).toContainText("Server identity changed");
    await expect(review).toContainText("Trust domain changed");
    await expect(review).toContainText("Sign-in provider changed");
    await expect(page.locator(".auth-status:not(.auth-connection-review)")).toBeHidden();
    await expect(page.locator(".auth-primary")).toBeHidden();
    const details = review.locator(".auth-connection-details");
    await expect(details.getByRole("button", { name: "Connection details", exact: true })).toHaveAttribute("aria-expanded", "true");
    await expect(review.locator(".auth-connection-value").first()).toBeVisible();
    await expect(review).toContainText("previous-station.example");
    // Shared method type, grant exchange and permissions are omitted even when
    // the issuer and client change.
    for (const unchanged of ["Permissions", "Grant exchange", "Sign-in method · Type"]) {
      await expect(review.locator(".auth-connection-field .auth-connection-label").filter({ hasText: unchanged })).toHaveCount(0);
    }

    const metrics = await review.evaluate((element) => {
      const card = element.closest(".auth-card")!.getBoundingClientRect();
      return Array.from(element.querySelectorAll(".auth-connection-value, button")).map((child) => {
        const rect = child.getBoundingClientRect();
        return {
          left: rect.left, right: rect.right,
          cardLeft: card.left, cardRight: card.right,
          clientWidth: child.clientWidth, scrollWidth: child.scrollWidth,
        };
      });
    });
    for (const metric of metrics) {
      expect(metric.left).toBeGreaterThanOrEqual(metric.cardLeft);
      expect(metric.right).toBeLessThanOrEqual(metric.cardRight);
      expect(metric.scrollWidth).toBeLessThanOrEqual(metric.clientWidth + 1);
    }
    const accept = review.getByRole("button", { name: "Trust and continue" });
    await accept.scrollIntoViewIfNeeded();
    await expect(accept).toBeInViewport();
    await page.screenshot({ path: test.info().outputPath(`connection-review-${viewport.width}x${viewport.height}.png`) });
    await review.getByRole("button", { name: "Keep previous connection" }).click();
    await expect(review).toBeHidden();
  });
}

for (const changedField of ["identity", "trust domain", "client"] as const) {
  test(`review only shows the changed ${changedField}`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 600 });
    await mockArkretApi(page);
    const authorizations: string[] = [];
    page.on("request", request => {
      if (new URL(request.url()).pathname === "/authorize") authorizations.push(request.url());
    });
    await page.goto(changedField === "client" ? "/" : "/login", { waitUntil: "domcontentloaded" });
    await expect(page.locator(".auth-primary")).toBeVisible();
    const description = await page.evaluate(async () => {
      const value = await (await fetch("https://server.local/_arkret/describe")).json();
      value.transport_bindings[0].base_url = "https://server.local/";
      return value;
    });
    await page.route("https://server.local/_arkret/describe*", route => route.fulfill({ json: description }));
    await page.getByRole("textbox", { name: "Account server URL" }).fill("https://server.local/");
    const previous = await page.evaluate(async ({ description, changedField }) => {
      const binding = {
        base_url: "https://server.local/",
        service_id: description.service_id,
        trust_domain: description.trust_domain,
        authentication_metadata: structuredClone(description.authentication_metadata),
      };
      if (changedField === "identity") binding.service_id = "ak:did_core:web:previous-station.example";
      if (changedField === "trust domain") binding.trust_domain = "ak:trust_domain:previous-station.example";
      if (changedField === "client") binding.authentication_metadata.methods[0].client_id = "previous-client";
      const encoded = JSON.stringify(binding);
      await new Promise<void>((resolve, reject) => {
        const opening = indexedDB.open("inkson.station-connections.v1", 1);
        opening.onupgradeneeded = () => opening.result.createObjectStore("bindings");
        opening.onerror = () => reject(opening.error);
        opening.onsuccess = () => {
          const db = opening.result;
          const tx = db.transaction("bindings", "readwrite");
          tx.objectStore("bindings").put(encoded, binding.base_url);
          tx.oncomplete = () => { db.close(); resolve(); };
          tx.onerror = () => { db.close(); reject(tx.error); };
        };
      });
      return encoded;
    }, { description, changedField });
    await page.locator(".auth-primary").click();
    const review = byClass(page, "station-connection-review");
    const summary = changedField === "identity" ? "Server identity changed" : changedField === "trust domain" ? "Trust domain changed" : "Sign-in provider changed";
    await expect(review.locator(".auth-connection-summary-item")).toHaveText([summary]);
    if (changedField === "identity") {
      await review.scrollIntoViewIfNeeded();
      await page.screenshot({ path: test.info().outputPath("connection-review-identity-only.png") });
    }
    await expect(review.locator(".auth-connection-value").first()).toBeVisible();
    await expect(review.locator(".auth-connection-field")).toHaveCount(1);
    await expect(review.locator(".auth-connection-field .auth-connection-label")).toHaveText(changedField === "identity" ? "Server identity" : changedField === "trust domain" ? "Trust domain" : "Sign-in method · Client");
    await expect(review.locator(".auth-connection-value")).toHaveCount(2);
    // Reviewing and declining never changes the saved trust binding.
    const readBinding = () => page.evaluate(() => new Promise<string>((resolve, reject) => {
      const opening = indexedDB.open("inkson.station-connections.v1", 1);
      opening.onerror = () => reject(opening.error);
      opening.onsuccess = () => {
        const db = opening.result;
        const request = db.transaction("bindings").objectStore("bindings").get("https://server.local/");
        request.onsuccess = () => { db.close(); resolve(request.result); };
        request.onerror = () => { db.close(); reject(request.error); };
      };
    }));
    expect(await readBinding()).toBe(previous);
    expect(authorizations).toEqual([]);
    if (changedField === "client") {
      await review.getByRole("button", { name: "Trust and continue" }).click();
      await expect(page.getByTestId("coauth-login")).toBeVisible();
      expect(authorizations).toHaveLength(1);
      expect(new URL(authorizations[0]).searchParams.get("client_id")).toBe(description.authentication_metadata.methods[0].client_id);
      await page.goto("/login", { waitUntil: "domcontentloaded" });
      expect(JSON.parse(await readBinding()).authentication_metadata.methods[0].client_id).toBe(description.authentication_metadata.methods[0].client_id);
    } else if (changedField === "trust domain") {
      // The Station advertises another change before we resume this login.
      const newClient = "client-changed-again";
      description.authentication_metadata.methods[0].client_id = newClient;
      await review.getByRole("button", { name: "Trust and continue" }).click();
      await expect(review.locator(".auth-connection-summary-item")).toHaveText(["Sign-in provider changed"]);
      await expect(review.locator(".auth-connection-value").last()).toHaveText(newClient);
      await expect(page.locator(".auth-error")).toBeHidden();
      expect(authorizations).toEqual([]);
      expect(JSON.parse(await readBinding()).authentication_metadata.methods[0].client_id).not.toBe(newClient);
    } else {
      await review.getByRole("button", { name: "Keep previous connection" }).click();
      await expect(review).toBeHidden();
      expect(await readBinding()).toBe(previous);
      expect(authorizations).toEqual([]);
      await expect(page.locator(".auth-primary")).toBeEnabled();
    }
  });
}
