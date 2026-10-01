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
    await expect(review).toContainText("previous-station.example");
    await expect(review).toContainText("New sign-in provider");

    const metrics = await review.evaluate((element) => {
      const card = element.closest(".auth-card")!.getBoundingClientRect();
      return Array.from(element.querySelectorAll("pre, button")).map((child) => {
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
    const accept = review.getByRole("button", { name: "Trust this connection and sign in again" });
    await accept.scrollIntoViewIfNeeded();
    await expect(accept).toBeInViewport();
    await page.screenshot({ path: `target/connection-review-${viewport.width}x${viewport.height}.png` });
    await review.getByRole("button", { name: "Keep previous connection" }).click();
    await expect(review).toBeHidden();
  });
}
