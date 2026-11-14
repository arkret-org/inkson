import { expect, test } from '@playwright/test';
import { byClass, gotoAndDismissRecovery, registerStrandsBeforeEach, readLocalConfig } from './strandsHarness';

registerStrandsBeforeEach();

test('one theme selector follows system appearance and translates in place on narrow screens', async ({ page }, info) => {
  await page.setViewportSize({ width: 320, height: 720 });
  await page.emulateMedia({ colorScheme: 'dark' });
  await gotoAndDismissRecovery(page, '/settings/theme');
  await expect(page.locator('.theme-switcher').getByRole('radio')).toHaveCount(3);
  await expect(page.locator('.settings-theme-choice, .text-direction')).toHaveCount(0);
  await page.getByRole('radio', { name: 'Follow system', exact: true }).click();
  await expect(page.locator('.theme-effective-description')).toContainText('Dark');
  await page.emulateMedia({ colorScheme: 'light' });
  await expect(page.locator('.theme-effective-description')).toContainText('Light');
  await byClass(page, 'settings-language-choice').filter({ hasText: '中文' }).click();
  await expect(page.getByRole('radio', { name: '跟随系统', exact: true })).toBeChecked();
  await expect(page.getByRole('radio', { name: '深色', exact: true })).toBeVisible();
  await expect(page.locator('.theme-effective-description')).toContainText('浅色');
  await expect(page.locator('.rail-link:visible .rail-label')).toHaveCount(4);
  const more = page.locator('.topbar-more .sapid-popover-trigger');
  await expect(more).toBeVisible();
  const title = await page.locator('.topbar-context-title').boundingBox();
  const geometry = await page.locator('.topbar').evaluate(root => [root,...root.querySelectorAll('*')].filter(el => /topbar|actions|connection-status/.test(el.className)).map(el => ({tag:el.tagName, cls:el.className, style:el.getAttribute('style'), rect:el.getBoundingClientRect().toJSON(), display:getComputedStyle(el).display, flex:getComputedStyle(el).flex, width:getComputedStyle(el).width})));
  await (await import('node:fs/promises')).writeFile(info.outputPath('header-geometry.json'), JSON.stringify(geometry, null, 2));
  await page.screenshot({ path: info.outputPath('theme-navigation-320-zh.png') });
  expect(title!.width).toBeGreaterThan(40);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await more.click();
  await expect(page.locator('.theme-toggle-button:visible')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.screenshot({ path: info.outputPath('theme-navigation-320-zh.png') });
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
  await page.screenshot({ path: info.outputPath('agents-first-use.png') });
  await byClass(page, 'agent-empty-create').click();
  await expect(byClass(page, 'agent-admin-detail-pane')).toBeVisible();
});

test('an empty agent filter can be cleared without creating or changing an agent', async ({ page }, info) => {
  let writes = 0;
  page.on('request', request => { if (new URL(request.url()).pathname.startsWith('/_arkret/self/agents') && request.method() !== 'GET') writes++; });
  await gotoAndDismissRecovery(page, '/agents');
  await expect(page.locator('.agent-admin-list-rows')).not.toBeEmpty();
  await page.getByRole('button', { name: /Search agents/ }).click();
  await page.locator('.agent-admin-list-pane input.workspace-navigation-search-input').fill('no-agent-can-have-this-name');
  await expect(byClass(page, 'agent-empty-clear')).toBeVisible();
  await page.screenshot({ path: info.outputPath('agents-filtered.png') });
  await byClass(page, 'agent-empty-clear').click();
  await expect(page.locator('.agent-admin-list-pane input.workspace-navigation-search-input')).toHaveValue('');
  await expect(page.locator('.agent-admin-list-rows')).not.toBeEmpty();
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
