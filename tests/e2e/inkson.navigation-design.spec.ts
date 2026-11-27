import { expect, test } from '@playwright/test';
import { byClass, gotoAndDismissRecovery, registerStrandsBeforeEach, readLocalConfig } from './strandsHarness';

registerStrandsBeforeEach();

test('settings rows stay readable and the sidebar scrolls at the pane edge', async ({ page }) => {
  await page.setViewportSize({ width: 1100, height: 560 });
  await gotoAndDismissRecovery(page, '/settings/notifications');
  const list = page.locator('.settings-nav-list');
  const sidebar = page.locator('.settings-sidebar-column');
  const heading = sidebar.locator('.workspace-list-heading');
  const row = list.getByRole('link').first();
  const listBox = (await list.boundingBox())!;
  const sidebarBox = (await sidebar.boundingBox())!;
  expect(Math.abs(sidebarBox.x + sidebarBox.width - listBox.x - listBox.width)).toBeLessThanOrEqual(1);
  expect((await row.boundingBox())!.height).toBeGreaterThanOrEqual(40);
  const headingBox = await heading.boundingBox();
  const last = list.getByRole('link').last();
  await last.focus();
  await expect(last).toBeInViewport();
  expect(await list.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
  expect(await heading.boundingBox()).toEqual(headingBox);
});

test('one theme selector follows system appearance and translates in place on narrow screens', async ({ page }, info) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await page.emulateMedia({ colorScheme: 'dark' });
  await gotoAndDismissRecovery(page, '/settings/theme');
  await expect(page.locator('.theme-switcher.sapid-segmented-control').getByRole('radio')).toHaveCount(3);
  await expect(page.locator('.settings-theme-choice, .text-direction')).toHaveCount(0);
  await page.getByRole('radiogroup', { name: 'Theme' }).getByText('Follow system', { exact: true }).click();
  await expect(page.locator('.theme-effective-description')).toContainText('Dark');
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(page.locator('.theme-effective-description')).toContainText('Light');
  await byClass(page, 'settings-language-choice').filter({ hasText: '中文' }).click();
  await expect(page.getByRole('radio', { name: '跟随系统', exact: true })).toBeChecked();
  await expect(page.getByRole('radiogroup', { name: '主题' }).getByText('深色', { exact: true })).toBeVisible();
  await expect(page.locator('.theme-effective-description')).toContainText('浅色');
  await expect(page.locator('.rail-link:visible .rail-label')).toHaveCount(4);
  const shortcuts = page.locator('.topbar-shortcuts');
  const search = page.locator('.topbar .command-palette-trigger');
  const notifications = page.locator('.topbar-notifications-link');
  await expect(shortcuts).toBeHidden();
  await expect(search).toBeHidden();
  await expect(notifications).toBeInViewport();
  await expect(page.locator('.topbar .theme-switcher, .theme-toggle-button')).toHaveCount(0);
  await expect(page.locator('.topbar-context-title')).toBeVisible();
  await expect.poll(async () => (await page.locator('.topbar-context-title').boundingBox())?.width ?? 0).toBeGreaterThan(40);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('theme-navigation-320-zh.png') });
  await notifications.press('Control+/');
  await expect(page.locator('.shortcut-help-card')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.locator('.shortcut-help-card')).toBeHidden();
  await page.setViewportSize({ width: 861, height: 720 });
  await expect(search).toBeVisible();
  await expect(shortcuts).toBeVisible();
  await page.setViewportSize({ width: 860, height: 720 });
  await expect(search).toBeHidden();
  await expect(shortcuts).toBeHidden();
  await expect(notifications).toBeInViewport();
});

test('agent loading, failure and first-use states expose only the appropriate next action', async ({ page }, info) => {
  let release: () => void = () => {};
  const gate = new Promise<void>(resolve => { release = resolve; });
  let fails = true;
  await page.route('**/_arkret/self/agents', async route => {
    await gate;
    return fails ? route.fulfill({ status: 503, contentType: 'application/problem+json', body: JSON.stringify({ type: 'https://arkret.org/problems/service_unavailable', title: 'Service unavailable', status: 503, detail: 'Try again.' }) }) : route.fulfill({ json: { agents: [], has_more: false } });
  });
  await gotoAndDismissRecovery(page, '/agents');
  await expect(page.locator('.agent-list-state')).toContainText('Loading');
  await expect(byClass(page, 'agent-empty-create')).toHaveCount(0);
  release();
  await expect(byClass(page, 'agent-empty-retry')).toBeVisible();
  await expect(byClass(page, 'agent-empty-create')).toHaveCount(0);
  fails = false;
  await byClass(page, 'agent-empty-retry').click();
  await expect(byClass(page, 'agent-empty-create')).toBeVisible();
  await expect(byClass(page, 'agent-empty-retry')).toHaveCount(0);
  await expect(page.locator('.agent-list-state')).toHaveCount(1);
  await expect(page.locator('.agent-admin-detail-content .agent-list-state')).toBeVisible();
  await page.screenshot({ path: info.outputPath('agents-first-use.png') });
  await page.setViewportSize({ width: 320, height: 720 });
  await expect(page.locator('.agent-admin-list-pane .agent-list-state')).toBeVisible();
  await expect(page.locator('.agent-list-state')).toHaveCount(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath('agents-first-use-320.png') });
  await byClass(page, 'agent-empty-create').click();
  await expect(byClass(page, 'agent-admin-detail-pane')).toBeVisible();
  const slug = byClass(page, 'agent-admin-provision-agent-slug').getByRole('textbox');
  await slug.fill('invalid/name');
  await expect(byClass(page, 'agent-admin-provision-button')).toBeDisabled();
  await expect(page.locator('.agent-admin-field-hint')).toBeVisible();
  await slug.fill('draft-agent');
  await expect(page.locator('.agent-admin-field-hint')).toHaveCount(0);
  await page.getByRole('button', { name: 'Back to list', exact: true }).click();
  await byClass(page, 'agent-admin-create-open-button').click();
  await expect(slug).toHaveValue('draft-agent');
});

test('an empty agent filter can be cleared without creating or changing an agent', async ({ page }, info) => {
  let writes = 0;
  page.on('request', request => { if (new URL(request.url()).pathname.startsWith('/_arkret/self/agents') && request.method() !== 'GET') writes++; });
  await gotoAndDismissRecovery(page, '/agents');
  await expect(page.locator('.agent-admin-list-rows')).not.toBeEmpty();
  await page.getByRole('button', { name: /Search agents/ }).click();
  await page.locator('.agent-admin-list-pane input.workspace-navigation-search-input').fill('no-agent-can-have-this-name');
  await expect(byClass(page, 'agent-empty-clear')).toBeVisible();
  await expect(page.locator('.agent-admin-detail')).toHaveCount(0);
  await expect(page.locator('.agent-list-state')).toHaveCount(1);
  await page.screenshot({ path: info.outputPath('agents-filtered.png') });
  await byClass(page, 'agent-empty-clear').click();
  await expect(page.locator('.agent-admin-list-pane input.workspace-navigation-search-input')).toHaveValue('');
  await expect(page.locator('.agent-admin-list-rows')).not.toBeEmpty();
  await expect(page.locator('.agent-admin-detail')).toBeVisible();
  const filters = byClass(page, 'agent-admin-filter-bar');
  const all = filters.getByRole('radio', { name: 'All', exact: true });
  const paused = filters.getByRole('radio', { name: 'Paused', exact: true });
  await all.focus();
  await page.keyboard.press('ArrowRight');
  await expect(filters.getByRole('radio', { name: 'Active', exact: true })).toBeChecked();
  await page.keyboard.press('ArrowRight');
  await expect(paused).toBeChecked();
  await expect(paused).toBeFocused();
  await expect(page).toHaveURL(/\/agents\?filter=paused$/);
  expect(writes).toBe(0);
});

test('contacts distinguish loading, failure, first use and filtered results in the list pane', async ({ page }, info) => {
  let release: () => void = () => {};
  const gate = new Promise<void>(resolve => { release = resolve; });
  let fail = true;
  await page.route(/\/_arkret\/self\/contacts(?:\?.*)?$/, async route => {
    await gate;
    return fail ? route.fulfill({ status: 503, contentType: 'application/problem+json', body: JSON.stringify({ type: 'https://arkret.org/problems/service_unavailable', title: 'Service unavailable', status: 503, detail: 'Try again.' }) }) : route.fulfill({ json: { contacts: [], has_more: false } });
  });
  await page.route('**/_arkret/self/agents', route => route.fulfill({ json: { agents: [], has_more: false } }));
  await gotoAndDismissRecovery(page, '/contacts');
  const list = page.locator('.contacts-list-pane');
  await expect(list.locator('.contacts-loading')).toBeVisible();
  release();
  await expect(list.locator('.contacts-retry-button')).toBeVisible();
  fail = false;
  await list.locator('.contacts-retry-button').click();
  await expect(list.locator('.contacts-empty-add-button')).toBeVisible();
  await page.screenshot({ path: info.outputPath('contacts-first-use.png') });
  await list.locator('.contacts-empty-add-button').click();
  await expect(page.locator('.add-contact-modal')).toBeVisible();
});

test('global search focuses on its shortcut and leaves focus alone on reload', async ({ page }) => {
  await gotoAndDismissRecovery(page, '/settings/notifications');
  await page.keyboard.press('Control+/');
  const dismiss = page.locator('.shortcut-help-card button').last();
  await dismiss.focus();
  await dismiss.press('Control+f');
  await expect(page).toHaveURL(/settings\/notifications$/);
  await expect(dismiss).toBeFocused();
  await dismiss.press('Escape');
  await expect(dismiss).toBeHidden();
  await page.keyboard.press('Control+f');
  const input = page.locator('.global-search-input');
  await expect(input).toBeFocused();
  await page.reload();
  await expect(input).toBeVisible();
  await expect(input).not.toBeFocused();
  await page.keyboard.press('Control+f');
  await expect(input).toBeFocused();
});

test('navigation search keeps disclosure focus and paints the focused field inward', async ({ page }) => {
  for (const route of ['/realms/manage', '/settings']) {
    await gotoAndDismissRecovery(page, route);
    const disclosure = page.locator('.workspace-search-disclosure');
    const trigger = disclosure.getByRole('button');
    const input = disclosure.getByRole('textbox');
    await expect(trigger).toHaveAttribute('aria-expanded', 'false');
    await trigger.click();
    await expect(input).toBeVisible();
    await expect(trigger).toBeFocused();
    await expect(input).toHaveCSS('box-shadow', 'none');
    const bounds = await input.boundingBox();

    await input.click();
    await expect(input).toBeFocused();
    await expect(input).toHaveCSS('outline-style', 'none');
    await expect(input).toHaveCSS('box-shadow', /inset/);
    expect(await input.boundingBox()).toEqual(bounds);
    await input.fill('sample');
    await page.keyboard.press('Escape');
    await expect(input).toHaveCount(0);
    await expect(trigger).toBeFocused();
    await expect(trigger).toHaveCSS('outline-style', 'solid');

    await page.keyboard.press('Enter');
    await expect(input).toBeVisible();
    await expect(trigger).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(input).toBeFocused();
    await expect(input).toHaveValue('');
    await expect(input).toHaveCSS('outline-style', 'none');
    await expect(input).toHaveCSS('box-shadow', /inset/);
    await page.emulateMedia({ forcedColors: 'active' });
    await expect(input).toHaveCSS('outline-style', 'solid');
    await expect(input).toHaveCSS('outline-offset', '-2px');
    await page.emulateMedia({ forcedColors: 'none' });
  }
});

test('contact search has an actionable no-results state', async ({ page }, info) => {
  await gotoAndDismissRecovery(page, '/contacts');
  const search = page.locator('.contacts-list-pane input.workspace-navigation-search-input');
  await expect(page.locator('.contact-list-item').first()).toBeVisible();
  await page.getByRole('button', { name: /Search contacts/ }).click();
  await search.fill('no-contact-can-have-this-name');
  await expect(page.locator('.contacts-clear-filter')).toBeVisible();
  await page.screenshot({ path: info.outputPath('contacts-filtered.png') });
  await page.locator('.contacts-clear-filter').click();
  await expect(search).toHaveValue('');
  await expect(page.locator('.contact-list-item').first()).toBeVisible();
});

test('completed identity setup survives reload and explains the separate recovery materials', async ({ page }, info) => {
  await gotoAndDismissRecovery(page, '/onboarding');
  const panel = page.locator('.onboarding-panel');
  await expect(panel).toContainText("You're all set");
  const before = (await readLocalConfig(page)).active_account.authority;
  const guide = page.locator('.onboarding-material-guide');
  await expect(guide).toBeHidden();
  await page.getByRole('button', { name: 'What each recovery method restores', exact: true }).click();
  await expect(guide).toContainText('Password or Passkey');
  await expect(guide).toContainText('current policy and eligibility checks');
  await expect(guide).toContainText('does not automatically supply historical keys or new access');
  await page.screenshot({ path: info.outputPath('onboarding-recovery-materials.png') });
  await page.reload();
  await expect(panel).toContainText("You're all set");
  expect((await readLocalConfig(page)).active_account.authority).toEqual(before);
  await expect(guide).toBeHidden();
});
