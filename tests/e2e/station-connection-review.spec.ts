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
    await expect(page.getByTestId("start-server-login-button")).toBeVisible();
    const description = await page.evaluate(async () => {
      const response = await fetch("https://server.local/_arkret/describe");
      const value = await response.json();
      // This login fixture must confirm the exact selected Station base.
      value.transport_bindings[0].base_url = "https://server.local/";
      return value;
    });
    await page.route("https://server.local/_arkret/describe*", (route) => route.fulfill({ json: description }));
    await page.getByRole("textbox", { name: "Sign-in server URL" }).fill("https://server.local/");
    await page.evaluate(async () => {
      const longPath = "previous-authentication-provider/".repeat(30);
      const binding = {
        base_url: "https://server.local/",
        service_id: "ak:did_core:web:previous-station.example",
        trust_domain: "ak:trust_domain:previous-station.example",
        auth_metadata: {
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
    await page.getByTestId("start-server-login-button").click();
    await expect(page.getByTestId("auth-status")).toContainText("Station identity or authentication changed");
    await page.getByRole("button", { name: "Review changed server" }).click();
    const review = page.getByTestId("station-connection-review");
    await expect(review).toBeVisible();
    await expect(review).toContainText("Server identity changed");
    await expect(review).toContainText("Trust domain changed");
    await expect(review).toContainText("Sign-in provider changed");
    await expect(page.getByTestId("auth-status")).toBeHidden();
    await expect(page.getByRole("button", { name: "Review changed server" })).toBeHidden();
    const details = review.locator("details");
    await expect(details).not.toHaveAttribute("open", "");
    await expect(review.locator("dd").first()).toBeHidden();
    await page.screenshot({ path: `target/connection-review-compact-${viewport.width}x${viewport.height}.png` });
    await details.getByText("View changed details").click();
    await expect(review).toContainText("previous-station.example");
    // Shared method type, grant exchange and permissions are omitted even when
    // the issuer and client change.
    for (const unchanged of ["Permissions", "Grant exchange", "Sign-in method · Type"]) {
      await expect(review.locator(".auth-connection-field strong").filter({ hasText: unchanged })).toHaveCount(0);
    }

    const metrics = await review.evaluate((element) => {
      const card = element.closest(".auth-card")!.getBoundingClientRect();
      return Array.from(element.querySelectorAll("dd, button")).map((child) => {
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
    const accept = review.getByRole("button", { name: "Trust new connection" });
    await accept.scrollIntoViewIfNeeded();
    await expect(accept).toBeInViewport();
    await page.screenshot({ path: `target/connection-review-${viewport.width}x${viewport.height}.png` });
    await review.getByRole("button", { name: "Keep previous connection" }).click();
    await expect(review).toBeHidden();
  });
}

for (const changedField of ["identity", "trust domain", "client"] as const) {
  test(`review only shows the changed ${changedField}`, async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 600 });
    await mockArkretApi(page);
    await page.goto("/login", { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId("start-server-login-button")).toBeVisible();
    const description = await page.evaluate(async () => {
      const value = await (await fetch("https://server.local/_arkret/describe")).json();
      value.transport_bindings[0].base_url = "https://server.local/";
      return value;
    });
    await page.route("https://server.local/_arkret/describe*", route => route.fulfill({ json: description }));
    await page.getByRole("textbox", { name: "Sign-in server URL" }).fill("https://server.local/");
    const previous = await page.evaluate(async ({ description, changedField }) => {
      const binding = {
        // The browser trust CAS stores the Rust serializer's exact JSON. Match
        // its field order when seeding a previously accepted connection.
        service_id: description.service_id,
        base_url: "https://server.local/",
        trust_domain: description.trust_domain,
        auth_metadata: structuredClone(description.auth_metadata),
      };
      if (changedField === "identity") binding.service_id = "ak:did_core:web:previous-station.example";
      if (changedField === "trust domain") binding.trust_domain = "ak:trust_domain:previous-station.example";
      if (changedField === "client") binding.auth_metadata.methods[0].client_id = "previous-client";
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
    await page.getByTestId("start-server-login-button").click();
    await expect(page.getByTestId("auth-status")).toHaveText("Station identity or authentication changed. Review the new connection before signing in.");
    await page.getByRole("button", { name: "Review changed server" }).click();
    const review = page.getByTestId("station-connection-review");
    const summary = changedField === "identity" ? "Server identity changed" : changedField === "trust domain" ? "Trust domain changed" : "Sign-in provider changed";
    await expect(review.locator("li")).toHaveText([summary]);
    const compactHeight = await review.evaluate(element => element.getBoundingClientRect().height);
    expect(compactHeight).toBeLessThan(300);
    if (changedField === "identity") {
      await review.scrollIntoViewIfNeeded();
      await page.screenshot({ path: "target/connection-review-identity-only.png" });
    }
    await review.getByText("View changed details").click();
    await expect(review.locator(".auth-connection-field")).toHaveCount(1);
    await expect(review.locator(".auth-connection-field strong")).toHaveText(changedField === "identity" ? "Server identity" : changedField === "trust domain" ? "Trust domain" : "Sign-in method · Client");
    await expect(review.locator("dd")).toHaveCount(2);
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
    if (changedField === "client") {
      await review.getByRole("button", { name: "Trust new connection" }).click();
      await expect(review).toBeHidden();
      await expect(page.getByTestId("auth-status")).toHaveText("New connection accepted. Start a new sign-in.");
      expect(JSON.parse(await readBinding()).auth_metadata.methods[0].client_id).toBe(description.auth_metadata.methods[0].client_id);
    } else {
      await review.getByRole("button", { name: "Keep previous connection" }).click();
      await expect(review).toBeHidden();
      expect(await readBinding()).toBe(previous);
    }
  });
}
