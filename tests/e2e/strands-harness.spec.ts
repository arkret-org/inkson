import { expect, test, type Page } from "@playwright/test";
import { dismissBlockingRecoveryModal } from "./strandsHarness";

// These pages exercise the test helper against real browser dialogs. They
// are not application fixtures or evidence of a successful recovery flow.
const html = `<!doctype html><html><head><title>Recovery helper boundary</title></head>
<body><main class="shell app">
<button id="underlying">Underlying action</button>
<button id="late">Open late recovery</button>
<button id="owner">Replace owner</button>
<output role="status" id="result">dismissed:0; actions:0</output>
</main>
<dialog id="recovery" aria-label="Recovery missing"><button>Not now</button></dialog>
<dialog id="setup" class="recovery-key-setup-modal" aria-label="Recovery setup">
<button class="recovery-key-setup-dismiss">Do this later</button></dialog>
<script>
let dismissed=0, actions=0;
const recovery=document.getElementById('recovery'), setup=document.getElementById('setup');
const update=()=>document.getElementById('result').textContent='dismissed:'+dismissed+'; actions:'+actions;
document.addEventListener('click',event=>{
 const button=event.target.closest('button'); if(!button)return;
 if(button.id==='underlying'){actions++;update();}
 if(button.id==='late')setTimeout(()=>recovery.showModal(),100);
 if(button.id==='owner'){
  const owner=document.querySelector('.shell.app');owner.replaceWith(owner.cloneNode(true));
  setTimeout(()=>recovery.showModal(),200);
 }
 if(button.closest('#recovery')){
  recovery.close();dismissed++;update();
  if(location.pathname.endsWith('/chain'))setTimeout(()=>setup.showModal(),300);
 }
 if(button.closest('#setup')){setup.close();dismissed++;update();}
});
if(location.pathname.endsWith('/delayed')||location.pathname.endsWith('/chain'))
 setTimeout(()=>recovery.showModal(),200);
</script></body></html>`;

test.beforeEach(async ({ page }) => {
  await page.route("http://recovery-helper.test/**", route => route.fulfill({
    status: 200, contentType: "text/html", body: html,
  }));
});

async function open(page: Page, path = "empty") {
  await page.goto(`http://recovery-helper.test/${path}`, { waitUntil: "domcontentloaded" });
}

test("recovery helper keeps first discovery but skips repeated absent-dialog waits in one owner", async ({ page }) => {
  await open(page);
  const first = performance.now();
  await dismissBlockingRecoveryModal(page);
  expect(performance.now() - first).toBeGreaterThanOrEqual(7_800);
  for (let iteration = 0; iteration < 3; iteration += 1) {
    const repeated = performance.now();
    await dismissBlockingRecoveryModal(page);
    expect(performance.now() - repeated).toBeLessThan(4_000);
  }
  await expect(page.getByRole("status")).toHaveText("dismissed:0; actions:0");
});

test("recovery helper detects a late real blocking dialog after a negative observation", async ({ page }) => {
  await open(page);
  await dismissBlockingRecoveryModal(page);
  await page.getByRole("button", { name: "Open late recovery", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Recovery missing", exact: true });
  await expect(dialog).toBeVisible();
  await expect(page.getByRole("button", { name: "Underlying action", exact: true }).click({ timeout: 250 })).rejects.toThrow();
  await expect(page.getByRole("status")).toHaveText("dismissed:0; actions:0");
  await dismissBlockingRecoveryModal(page);
  await expect(dialog).toBeHidden();
  await page.getByRole("button", { name: "Underlying action", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("dismissed:1; actions:1");
});

test("recovery helper retains the real delayed follow-up recovery-setup chain", async ({ page }) => {
  await open(page, "chain");
  await dismissBlockingRecoveryModal(page);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("status")).toHaveText("dismissed:2; actions:0");
});

test("recovery helper repeats complete discovery after full document navigation", async ({ page }) => {
  await open(page);
  await dismissBlockingRecoveryModal(page);
  await open(page, "delayed");
  await dismissBlockingRecoveryModal(page);
  await expect(page.getByRole("status")).toHaveText("dismissed:1; actions:0");
});

test("recovery helper repeats complete discovery when the real shell owner is replaced", async ({ page }) => {
  await open(page);
  await dismissBlockingRecoveryModal(page);
  await page.getByRole("button", { name: "Replace owner", exact: true }).click();
  await dismissBlockingRecoveryModal(page);
  await expect(page.getByRole("status")).toHaveText("dismissed:1; actions:0");
});
