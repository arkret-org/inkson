import { expect, test } from '@playwright/test';
import { byClass, openKanban, gotoAndDismissRecovery, dismissBlockingRecoveryModal, dismissHistoryRecoveryModal, registerStrandsBeforeEach } from './strandsHarness';
registerStrandsBeforeEach({ personalAgentPairingExpiresAt: '2000-01-01T00:00:00.000Z' });

for (const width of [1280, 390]) {
  test(`card details separate reading, scheduling and technical scope at ${width}px`, async ({ page }, info) => {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 720 });
    await openKanban(page);
    await byClass(page, 'kanban-card').first().click();
    const detail = byClass(page, 'card-detail-modal');
    await expect(detail).toBeVisible();
    if (width === 390) {
      const title = detail.locator('.card-detail-title-row h2');
      await expect(title).toBeVisible();
      expect((await title.boundingBox())!.width).toBeGreaterThan(200);
      expect(await title.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    }
    for (const track of ['description', 'synthesis', 'discussion']) await expect(byClass(detail, `card-detail-tab-${track}`)).toBeVisible();
    const sidebar = detail.locator('.card-detail-sidebar');
    if (!await sidebar.isVisible()) await byClass(detail, 'card-detail-sidebar-toggle').click();
    await expect(sidebar).toContainText('People and time');
    await expect(sidebar).toContainText('Labels');
    const technical = sidebar.locator('.card-detail-access > .sapid-collapsible-trigger');
    await expect(technical).toHaveAttribute('aria-expanded', 'false');
    await technical.click();await expect(sidebar.locator('.card-detail-strand-identity')).toBeVisible();
    await technical.click();
    await expect(byClass(detail, 'card-detail-calendar-edit')).toHaveText(/Add schedule|Edit schedule/);
    await byClass(detail, 'card-detail-calendar-edit').click();
    await expect(byClass(page, 'card-detail-calendar-editor-dialog')).toBeVisible();
    await byClass(page, 'card-detail-cancel-edit-button').click();
    await byClass(detail, 'card-detail-tab-description').click();
    await expect(byClass(detail, 'card-detail-edit-description-button')).toHaveText(/Add description|Edit description/);
    await byClass(detail, 'card-detail-edit-description-button').click();
    const input = detail.getByRole('textbox', { name: 'Description', exact: true });
    await input.fill('Long draft that must remain independent of schedule and discussion\n'.repeat(60));
    await byClass(detail, 'card-detail-tab-synthesis').click();
    await byClass(detail, 'card-detail-tab-description').click();
    await expect(input).toContainText('Long draft that must remain independent of schedule and discussion');
    await byClass(detail, 'card-detail-cancel-edit-button').click();
    await page.screenshot({ path: info.outputPath(`card-detail-${width}.png`) });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

test('agent permission overview distinguishes configured ceiling, runtime readiness and disclosed source', async ({ page }, info) => {
  await gotoAndDismissRecovery(page, '/agents');
  await byClass(page, 'agent-admin-row').filter({ hasText: 'assistant' }).click();
  const overview = page.locator('.agent-permission-overview');
  await expect(overview).toContainText('configured ceilings, not current effective access');
  await expect(overview).toContainText('Read ceiling');
  await expect(overview).toContainText('Write and proposal ceiling');
  await expect(overview).toContainText('does not disclose physical location');
  await expect(page.locator('.agent-admin-pairing-card')).toHaveCount(0);
  const exact = page.locator('.agent-admin-exact-permissions > .sapid-collapsible-trigger');
  await expect(exact).toHaveAttribute('aria-expanded', 'false');await exact.click();
  await expect(page.locator('.agent-admin-content-capability-list')).toBeVisible();
  const source = overview.locator('.permission-source > .sapid-collapsible-trigger');await source.click();
  const json = JSON.parse(await overview.locator('.permission-source-json').textContent() || '{}');
  expect(json.requested_scope.actions.length).toBeGreaterThan(0);
  expect(json).not.toHaveProperty('pairing_code');expect(json).not.toHaveProperty('pairing_request_id');
  await page.screenshot({ path: info.outputPath('agent-permission-overview.png'), fullPage: true });
  await source.click();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await overview.screenshot({ path: info.outputPath('agent-permission-overview-mobile.png') });
  await page.setViewportSize({ width: 1280, height: 720 });
  await byClass(page, 'agent-admin-row').filter({ hasText: 'summary' }).click();
  await expect(page.locator('.agent-permission-state')).toContainText('Pairing expired');
  await expect(page.locator('.agent-permission-expiry')).toContainText('No runtime key authorization');
});

test('call entry keeps the discussion Realm and requires explicit group participants', async ({ page }, info) => {
  await openKanban(page);
  const realm = decodeURIComponent(new URL(page.url()).pathname.split('/')[2]);
  await page.goto(`/chat/${encodeURIComponent(realm)}`);await dismissHistoryRecoveryModal(page);await dismissBlockingRecoveryModal(page);
  let writes = 0;page.on('request', request => { if(request.method() === 'POST' && request.url().endsWith('/_arkret/self/events')) writes++; });
  await page.locator('.chat-call-voice-button').click();
  await expect(page).toHaveURL(url => url.pathname === '/call' && url.searchParams.get('realm_id') === realm);
  await expect(page.locator('.call-panel')).toBeVisible();
  await expect(page.locator('.call-target-name')).toContainText('Arkret Demo Realm');
  const manual = page.locator('.call-manual-targets > .sapid-collapsible-trigger');await expect(manual).toHaveAttribute('aria-expanded', 'false');
  await expect(page.locator('.call-group-input')).toBeHidden();
  await expect(page.locator('.call-start-group-button')).toBeDisabled();
  const choices = page.locator('.call-target-choice input');
  expect(await choices.count()).toBeGreaterThan(0);await choices.first().check();await expect(page.locator('.call-start-group-button')).toBeEnabled();
  await manual.click();await expect(page.locator('.call-realm-input')).toHaveValue(realm);
  await expect(page.locator('.call-group-input')).not.toHaveValue(/bob\.example|carol\.example/);
  await page.screenshot({ path: info.outputPath('call-context-and-manual.png'), fullPage: true });
  expect(writes).toBe(0);
  await page.goto('/call?peer=ak%3Adid_core%3Aweb%3Abob.example');await dismissBlockingRecoveryModal(page);
  await expect(page.locator('.call-realm-input')).toHaveValue('');
  await expect(page.locator('.call-start-voice-button')).toBeDisabled();
});

test('composer retains a concise visible audience and discloses its exact strand on demand', async ({ page }, info) => {
  await openKanban(page);const realm = decodeURIComponent(new URL(page.url()).pathname.split('/')[2]);
  await page.goto(`/chat/${encodeURIComponent(realm)}`);await dismissHistoryRecoveryModal(page);await dismissBlockingRecoveryModal(page);
  const shell=page.locator('.discussion-shell:not(.embedded)');await shell.locator('.channel-item').filter({ hasText:'Legal review for public beta' }).click();
  await expect(shell.locator('.composer-send-scope')).toContainText('authorized readers');
  await expect(shell.locator('.composer-send-scope')).not.toContainText('ak:strand:');
  const input=shell.locator('textarea');await input.fill('Scope details must not discard this unsent draft');
  const trigger=shell.locator('.composer-scope-details > .sapid-collapsible-trigger');await trigger.click();
  await expect(shell.locator('.composer-scope-details .mono')).toContainText('ak:strand:');await trigger.click();
  await expect(input).toHaveValue('Scope details must not discard this unsent draft');
  await page.screenshot({path:info.outputPath('composer-audience.png')});
});
