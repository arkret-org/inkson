# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: clientx.flows.spec.ts >> notifications are derived from index projections and respect per-space mute rules
- Location: tests\e2e\clientx.flows.spec.ts:352:1

# Error details

```
Error: locator.click: Error: strict mode violation: getByTestId('settings-nav-button') resolved to 2 elements:
    1) <a href="/settings" data-dioxus-id="142" class="sidebar-nav-item" data-testid="settings-nav-button">…</a> aka getByTestId('settings-nav-button').first()
    2) <a href="/settings" data-dioxus-id="142" class="sidebar-nav-item" data-testid="settings-nav-button">…</a> aka getByTestId('settings-nav-button').nth(1)

Call log:
  - waiting for getByTestId('settings-nav-button')

```

# Page snapshot

```yaml
- generic [active] [ref=e1]:
  - generic [ref=e5] [cursor=pointer]:
    - generic [ref=e6]:
      - img [ref=e7]
      - heading [level=3] [ref=e11]: Your app is being rebuilt.
    - paragraph [ref=e12]: A non-hot-reloadable change occurred and we must rebuild.
  - generic [ref=e13]:
    - generic [ref=e14]:
      - navigation "Main navigation" [ref=e15]:
        - link "Contrix Home" [ref=e18] [cursor=pointer]:
          - /url: /
          - generic [ref=e19]: ⌘
          - generic [ref=e20]:
            - generic [ref=e21]: Contrix
            - generic [ref=e22]: v1 client
        - generic "Current principal server context" [ref=e23]:
          - button "Switch Principal Server" [expanded] [ref=e24] [cursor=pointer]:
            - img [ref=e26]
            - generic [ref=e28]:
              - generic [ref=e29]: Principal Server
              - generic [ref=e30]: https://local.host
              - generic [ref=e31]: Describe not loaded
            - generic [ref=e32]:
              - generic [ref=e33]: session
              - img [ref=e34]
          - generic [ref=e36]:
            - generic "Server choices" [ref=e37]:
              - button "Switch to https://local.host" [ref=e38] [cursor=pointer]:
                - generic [ref=e39]:
                  - generic [ref=e40]: https://local.host
                  - generic [ref=e41]: Current data home
                - generic [ref=e42]: current
              - button "Switch to http://127.0.0.1:8787/" [ref=e43] [cursor=pointer]:
                - generic [ref=e44]:
                  - generic [ref=e45]: http://127.0.0.1:8787/
                  - generic [ref=e46]: Switch workspace scope
            - textbox "Custom Principal Server URL" [ref=e47]: https://local.host
            - generic [ref=e48]:
              - button "Refresh Principal Server metadata and sync state" [ref=e49] [cursor=pointer]:
                - img [ref=e50]
                - text: Refresh
              - link "Services" [ref=e52] [cursor=pointer]:
                - /url: /settings/server
                - img [ref=e53]
                - text: Services
        - link "Search / Directory ⌘K" [ref=e56] [cursor=pointer]:
          - /url: /directory
          - img [ref=e58]
          - generic [ref=e60]: Search / Directory
          - generic [ref=e61]: ⌘K
        - generic [ref=e62]:
          - heading "Personal" [level=4] [ref=e63]
          - link "Home" [ref=e64] [cursor=pointer]:
            - /url: /
            - img [ref=e66]
            - generic [ref=e68]: Home
          - link "Inbox 0" [ref=e69] [cursor=pointer]:
            - /url: /notifications
            - img [ref=e71]
            - generic [ref=e73]: Inbox
            - generic [ref=e74]: "0"
          - link "Directory" [ref=e75] [cursor=pointer]:
            - /url: /directory
            - img [ref=e77]
            - generic [ref=e79]: Directory
          - link "Settings" [ref=e80] [cursor=pointer]:
            - /url: /settings
            - img [ref=e82]
            - generic [ref=e84]: Settings
          - link "Timeline" [ref=e85] [cursor=pointer]:
            - /url: /timeline
            - img [ref=e87]
            - generic [ref=e89]: Timeline
          - link "Kanban" [ref=e90] [cursor=pointer]:
            - /url: /kanban
            - img [ref=e92]
            - generic [ref=e94]: Kanban
          - link "Chat" [ref=e95] [cursor=pointer]:
            - /url: /chat
            - img [ref=e97]
            - generic [ref=e99]: Chat
          - link "Audit" [ref=e100] [cursor=pointer]:
            - /url: /audit
            - img [ref=e102]
            - generic [ref=e104]: Audit
        - generic [ref=e105]:
          - heading "Spaces +" [level=4] [ref=e106]:
            - generic [ref=e107]: Spaces
            - link "+" [ref=e108] [cursor=pointer]:
              - /url: /product
          - generic [ref=e109]:
            - img [ref=e111]
            - generic [ref=e113]: No spaces loaded
        - generic [ref=e114]:
          - heading "Cross-organization" [level=4] [ref=e115]
          - generic [ref=e116]:
            - img [ref=e118]
            - generic [ref=e120]: No cross-org spaces loaded
        - generic [ref=e121]:
          - heading "Personal Spaces +" [level=4] [ref=e122]:
            - generic [ref=e123]: Personal Spaces
            - link "+" [ref=e124] [cursor=pointer]:
              - /url: /product
          - generic [ref=e125]:
            - img [ref=e127]
            - generic [ref=e129]: No personal spaces loaded
        - generic [ref=e130]:
          - heading "Protocol Tools" [level=4] [ref=e131]
          - link "Devices" [ref=e132] [cursor=pointer]:
            - /url: /devices
            - img [ref=e134]
            - generic [ref=e136]: Devices
          - link "Readiness" [ref=e137] [cursor=pointer]:
            - /url: /readiness
            - img [ref=e139]
            - generic [ref=e141]: Readiness
      - main "Main content" [ref=e142]:
        - generic [ref=e143]:
          - button "Hide navigation" [ref=e144] [cursor=pointer]:
            - img [ref=e145]
          - generic [ref=e147]:
            - link "https://local.host" [ref=e148] [cursor=pointer]:
              - /url: /settings/server
              - strong [ref=e149]: https://local.host
            - generic [ref=e150]: Session
            - generic [ref=e151]: /
            - generic [ref=e152]: Home
          - generic [ref=e153]:
            - button "Switch to night theme" [ref=e154] [cursor=pointer]:
              - img [ref=e155]
            - generic [ref=e157]:
              - generic [ref=e158]: ⌕
              - textbox "Search spaces, flows, people, applets..." [ref=e159]
              - generic [ref=e160]: ⌘K
            - status [ref=e161]:
              - generic [ref=e162]:
                - generic [ref=e163]: Offline
                - generic [ref=e164]: offline
              - generic [ref=e165]:
                - generic [ref=e166]: cursor -
                - button "Retry" [ref=e167] [cursor=pointer]
            - link "Inbox" [ref=e168] [cursor=pointer]:
              - /url: /notifications
            - link "Space" [ref=e169] [cursor=pointer]:
              - /url: /product
              - img [ref=e170]
              - text: Space
            - generic [ref=e172]: 0 spaces
            - button "Account menu" [ref=e174] [cursor=pointer]:
              - img [ref=e175]
              - generic "online" [ref=e177]
        - generic [ref=e179]:
          - generic [ref=e180]:
            - generic [ref=e181]:
              - heading "Workspace" [level=1] [ref=e182]
              - generic [ref=e183]: Server-backed workspace data is shown below.
            - generic [ref=e184]:
              - link "New Space" [ref=e185] [cursor=pointer]:
                - /url: /product
                - img [ref=e186]
                - text: New Space
              - link "Call" [ref=e188] [cursor=pointer]:
                - /url: /call
                - img [ref=e189]
                - text: Call
          - generic [ref=e191]:
            - link "Inbox 0 No loaded notifications" [ref=e192] [cursor=pointer]:
              - /url: /notifications
              - generic [ref=e193]: Inbox
              - generic [ref=e194]: "0"
              - generic [ref=e195]: No loaded notifications
            - link "Sync frontier - online · 0 pending" [ref=e196] [cursor=pointer]:
              - /url: /audit
              - generic [ref=e197]: Sync frontier
              - generic [ref=e198]: "-"
              - generic [ref=e199]: online · 0 pending
            - link "Devices 1 Current session device" [ref=e200] [cursor=pointer]:
              - /url: /devices
              - generic [ref=e201]: Devices
              - generic [ref=e202]: "1"
              - generic [ref=e203]: Current session device
            - generic [ref=e204]:
              - generic [ref=e205]: Local queue
              - generic [ref=e206]: "0"
              - generic [ref=e207]: writes waiting for replay
          - generic [ref=e208]:
            - generic [ref=e209]:
              - generic [ref=e210]:
                - generic [ref=e211]:
                  - strong [ref=e212]: Recent Spaces
                  - link "Browse spaces" [ref=e213] [cursor=pointer]:
                    - /url: /directory
                    - img [ref=e214]
                - generic [ref=e217]:
                  - generic [ref=e218]: "0"
                  - generic [ref=e219]:
                    - generic [ref=e220]: No spaces loaded
                    - generic [ref=e221]: The connected server did not return spaces yet.
              - generic [ref=e222]:
                - strong [ref=e224]: Recent Flows
                - table [ref=e225]:
                  - rowgroup [ref=e226]:
                    - row "Title Space State Updated" [ref=e227]:
                      - columnheader [ref=e228]
                      - columnheader "Title" [ref=e229]
                      - columnheader "Space" [ref=e230]
                      - columnheader "State" [ref=e231]
                      - columnheader "Updated" [ref=e232]
                  - rowgroup [ref=e233]:
                    - row "No recent flows loaded" [ref=e234]:
                      - cell "No recent flows loaded" [ref=e235]
              - generic [ref=e236]:
                - generic [ref=e237]: Recent Activity
                - generic [ref=e239]:
                  - generic [ref=e240]: empty
                  - generic [ref=e241]:
                    - generic [ref=e242]: No activity loaded
                    - generic [ref=e243]: Sync has not returned recent events.
            - generic [ref=e244]:
              - generic [ref=e245]:
                - generic [ref=e246]:
                  - strong [ref=e247]: Workspace State
                  - generic "Frontier values come from the current sync and event surfaces; no repo protocol is involved." [ref=e249]: "?"
                - generic [ref=e250]:
                  - generic [ref=e251]:
                    - generic [ref=e252]: Sync frontier
                    - generic [ref=e253]: "-"
                  - generic [ref=e254]: loaded
                - generic [ref=e255]:
                  - generic [ref=e256]:
                    - generic [ref=e257]: Event frontier
                    - generic [ref=e258]: Principal Server reported
                  - generic [ref=e259]: Not loaded
                - generic [ref=e260]:
                  - generic [ref=e261]:
                    - generic [ref=e262]: Queued writes
                    - generic [ref=e263]: local replay queue
                  - generic [ref=e264]: "0"
              - generic [ref=e265]:
                - generic [ref=e266]:
                  - strong [ref=e267]: Protocol Health
                  - button "Run health checks" [ref=e268] [cursor=pointer]:
                    - img [ref=e269]
                - generic [ref=e272]: Run checks after changing the Principal Server.
              - generic [ref=e273]:
                - generic [ref=e274]:
                  - strong [ref=e275]: Inbox
                  - link "Open inbox" [ref=e276] [cursor=pointer]:
                    - /url: /notifications
                    - img [ref=e277]
                - generic [ref=e280]:
                  - generic [ref=e281]: "0"
                  - generic [ref=e282]:
                    - generic [ref=e283]: No inbox items loaded
                    - generic [ref=e284]: Server-backed notifications only
    - generic [ref=e285]:
      - navigation "Main navigation" [ref=e286]:
        - link "Contrix Home" [ref=e289] [cursor=pointer]:
          - /url: /
          - generic [ref=e290]: ⌘
          - generic [ref=e291]:
            - generic [ref=e292]: Contrix
            - generic [ref=e293]: v1 client
        - generic "Current principal server context" [ref=e294]:
          - button "Switch Principal Server" [ref=e295] [cursor=pointer]:
            - img [ref=e297]
            - generic [ref=e299]:
              - generic [ref=e300]: Principal Server
              - generic [ref=e301]: https://local.host
              - generic [ref=e302]: Describe not loaded
            - generic [ref=e303]:
              - generic [ref=e304]: session
              - img [ref=e305]
        - link "Search / Directory ⌘K" [ref=e308] [cursor=pointer]:
          - /url: /directory
          - img [ref=e310]
          - generic [ref=e312]: Search / Directory
          - generic [ref=e313]: ⌘K
        - generic [ref=e314]:
          - heading "Personal" [level=4] [ref=e315]
          - link "Home" [ref=e316] [cursor=pointer]:
            - /url: /
            - img [ref=e318]
            - generic [ref=e320]: Home
          - link "Inbox 0" [ref=e321] [cursor=pointer]:
            - /url: /notifications
            - img [ref=e323]
            - generic [ref=e325]: Inbox
            - generic [ref=e326]: "0"
          - link "Directory" [ref=e327] [cursor=pointer]:
            - /url: /directory
            - img [ref=e329]
            - generic [ref=e331]: Directory
          - link "Settings" [ref=e332] [cursor=pointer]:
            - /url: /settings
            - img [ref=e334]
            - generic [ref=e336]: Settings
          - link "Timeline" [ref=e337] [cursor=pointer]:
            - /url: /timeline
            - img [ref=e339]
            - generic [ref=e341]: Timeline
          - link "Kanban" [ref=e342] [cursor=pointer]:
            - /url: /kanban
            - img [ref=e344]
            - generic [ref=e346]: Kanban
          - link "Chat" [ref=e347] [cursor=pointer]:
            - /url: /chat
            - img [ref=e349]
            - generic [ref=e351]: Chat
          - link "Audit" [ref=e352] [cursor=pointer]:
            - /url: /audit
            - img [ref=e354]
            - generic [ref=e356]: Audit
        - generic [ref=e357]:
          - heading "Spaces +" [level=4] [ref=e358]:
            - generic [ref=e359]: Spaces
            - link "+" [ref=e360] [cursor=pointer]:
              - /url: /product
          - generic [ref=e361]:
            - img [ref=e363]
            - generic [ref=e365]: No spaces loaded
        - generic [ref=e366]:
          - heading "Cross-organization" [level=4] [ref=e367]
          - generic [ref=e368]:
            - img [ref=e370]
            - generic [ref=e372]: No cross-org spaces loaded
        - generic [ref=e373]:
          - heading "Personal Spaces +" [level=4] [ref=e374]:
            - generic [ref=e375]: Personal Spaces
            - link "+" [ref=e376] [cursor=pointer]:
              - /url: /product
          - generic [ref=e377]:
            - img [ref=e379]
            - generic [ref=e381]: No personal spaces loaded
        - generic [ref=e382]:
          - heading "Protocol Tools" [level=4] [ref=e383]
          - link "Devices" [ref=e384] [cursor=pointer]:
            - /url: /devices
            - img [ref=e386]
            - generic [ref=e388]: Devices
          - link "Readiness" [ref=e389] [cursor=pointer]:
            - /url: /readiness
            - img [ref=e391]
            - generic [ref=e393]: Readiness
      - main "Main content" [ref=e394]:
        - generic [ref=e395]:
          - button "Hide navigation" [ref=e396] [cursor=pointer]:
            - img [ref=e397]
          - generic [ref=e399]:
            - link "https://local.host" [ref=e400] [cursor=pointer]:
              - /url: /settings/server
              - strong [ref=e401]: https://local.host
            - generic [ref=e402]: Session
            - generic [ref=e403]: /
            - generic [ref=e404]: Inbox
          - generic [ref=e405]:
            - button "Switch to night theme" [ref=e406] [cursor=pointer]:
              - img [ref=e407]
            - generic [ref=e409]:
              - generic [ref=e410]: ⌕
              - textbox "Search spaces, flows, people, applets..." [ref=e411]
              - generic [ref=e412]: ⌘K
            - status [ref=e413]:
              - generic [ref=e414]:
                - generic [ref=e415]: Offline
                - generic [ref=e416]: offline
              - generic [ref=e417]:
                - generic [ref=e418]: cursor -
                - button "Retry" [ref=e419] [cursor=pointer]
            - link "Inbox" [ref=e420] [cursor=pointer]:
              - /url: /notifications
            - link "Space" [ref=e421] [cursor=pointer]:
              - /url: /product
              - img [ref=e422]
              - text: Space
            - generic [ref=e424]: 0 spaces
            - button "Account menu" [ref=e426] [cursor=pointer]:
              - img [ref=e427]
              - generic "online" [ref=e429]
        - region "Notifications" [ref=e431]:
          - status [ref=e432]:
            - generic [ref=e433]:
              - generic [ref=e434]: Notifications
              - generic [ref=e435]:
                - generic "Inbox items are derived from sync account data and filtered by local mute rules. Push only wakes the client; notification bodies are resolved locally." [ref=e436]: "?"
                - generic [ref=e437]: 0 unread / 2 server
            - generic [ref=e438]:
              - tablist "Notification grouping" [ref=e439]:
                - button "All" [ref=e440] [cursor=pointer]
                - button "Space" [ref=e441] [cursor=pointer]
                - button "Type" [ref=e442] [cursor=pointer]
                - button "Time" [ref=e443] [cursor=pointer]
              - generic [ref=e444]:
                - button "Mark all read" [ref=e445] [cursor=pointer]:
                  - img [ref=e446]
                - button "Show archived" [ref=e448] [cursor=pointer]:
                  - img [ref=e449]
              - button "Refresh notifications" [ref=e452] [cursor=pointer]:
                - img [ref=e453]
            - generic [ref=e455]: Muted notifications for cx:space:0196419b-0000-7000-8000-000000000000.
          - generic [ref=e456]:
            - generic [ref=e457]:
              - generic [ref=e458]: Notifications
              - generic [ref=e459]: filtered
            - generic [ref=e460]: All loaded notifications are currently hidden by archive, type, or per-space mute rules.
          - generic [ref=e461]:
            - generic [ref=e462]:
              - generic [ref=e463]: Notification Rules
              - generic "These toggles only affect this client. Server-side moderation and retention policies remain separate." [ref=e464]: "?"
            - generic [ref=e465]:
              - generic [ref=e466]:
                - strong [ref=e467]: Mention notifications
                - generic [ref=e468]:
                  - checkbox "Enabled" [checked] [ref=e469]
                  - text: Enabled
              - generic [ref=e470]:
                - strong [ref=e471]: Reaction notifications
                - generic [ref=e472]:
                  - checkbox "Enabled" [checked] [ref=e473]
                  - text: Enabled
              - generic [ref=e474]:
                - strong [ref=e475]: Invite notifications
                - generic [ref=e476]:
                  - checkbox "Enabled" [checked] [ref=e477]
                  - text: Enabled
              - generic [ref=e478]:
                - strong [ref=e479]: Message notifications
                - generic [ref=e480]:
                  - checkbox "Enabled" [checked] [ref=e481]
                  - text: Enabled
            - generic [ref=e482]:
              - generic [ref=e483]:
                - generic [ref=e484]: Muted Spaces
                - generic [ref=e485]: "1"
              - generic [ref=e486]:
                - generic [ref=e487]: cx:space:0196419b-0000-7000-8000-000000000000
                - button "Unmute space" [ref=e488] [cursor=pointer]:
                  - img [ref=e489]
              - button "Clear All" [ref=e491] [cursor=pointer]
```

# Test source

```ts
  263 | 
  264 |   await page.getByTestId("mimi-refresh-directory").click();
  265 |   await expect(page.getByTestId("mimi-directory-result")).toContainText("mimi://mimi.example.com");
  266 |   await expect(page.getByTestId("mimi-directory-result")).toContainText("submit_message");
  267 |   await expect(page.getByTestId("mimi-directory-result")).toContainText("identifier_query");
  268 |   await expect(page.getByTestId("mimi-directory-result")).toContainText("proxy_download");
  269 | 
  270 |   await page.getByTestId("mimi-group-info").click();
  271 |   await expect(page.getByTestId("mimi-action-receipt")).toContainText("group-info 01JSMIMI participants 2");
  272 | 
  273 |   await page.getByTestId("mimi-identifier-query").click();
  274 |   await expect(page.getByTestId("mimi-action-receipt")).toContainText("identifier mimi://remote.example/alice reachable true");
  275 | 
  276 |   await page.getByTestId("mimi-proxy-download").click();
  277 |   await expect(page.getByTestId("mimi-action-receipt")).toContainText("proxy-download cx:blob:sha256:e2e");
  278 | 
  279 |   const submit = page.waitForRequest("**/api/v1/mimi/rooms/01JSMIMI/messages");
  280 |   await page.getByTestId("mimi-submit-message").click();
  281 |   expect((await submit).postDataJSON().source_format).toBe("text/markdown;variant=GFM-MIMI");
  282 |   await expect(page.getByTestId("mimi-action-receipt")).toContainText("submit-message mimi-msg-e2e");
  283 | });
  284 | 
  285 | test("mobile viewport collapses shell chrome and keeps timeline usable", async ({ page }) => {
  286 |   await page.setViewportSize({ width: 390, height: 844 });
  287 |   await page.goto("/timeline", { waitUntil: "domcontentloaded" });
  288 | 
  289 |   await expect(page.getByTestId("client-shell")).toBeVisible();
  290 |   await expect(page.getByTestId("sidebar")).toBeHidden();
  291 |   await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
  292 |   await page.getByTestId("mobile-nav-toggle").click();
  293 |   await expect(page.getByTestId("mobile-nav-drawer")).toContainText("Board");
  294 |   await expect(page.getByTestId("main-view")).toBeVisible();
  295 |   await expect(page.getByTestId("composer-input")).toBeVisible();
  296 | });
  297 | 
  298 | test("accessibility smoke exposes landmarks and live timeline feed", async ({ page }) => {
  299 |   await expect(page.getByTestId("sidebar")).toHaveAttribute("role", "navigation");
  300 |   await expect(page.getByTestId("main-view")).toHaveAttribute("role", "main");
  301 |   await expect(page.getByTestId("account-menu-button")).toHaveAttribute("aria-label", "Account menu");
  302 | 
  303 |   await page.getByRole("link", { name: "Timeline" }).click();
  304 |   await expect(page.getByTestId("timeline")).toHaveAttribute("role", "feed");
  305 |   await expect(page.getByTestId("timeline")).toHaveAttribute("aria-live", "polite");
  306 | 
  307 |   const sendRequest = page.waitForRequest("**/api/v1/events");
  308 |   await page.getByTestId("composer-input").fill("a11y smoke message");
  309 |   await page.getByTestId("send-button").click();
  310 |   await sendRequest;
  311 | 
  312 |   await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("role", "article");
  313 |   await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("aria-label", /Timeline event from/);
  314 | });
  315 | 
  316 | test("directory search resolve and space selection flow works", async ({ page }) => {
  317 |   await page.getByTestId("directory-nav-button").click();
  318 |   await expect(page.getByTestId("directory-panel")).toBeVisible();
  319 | 
  320 |   await page.getByTestId("directory-search-input").fill("demo");
  321 |   await page.getByTestId("directory-search-button").click();
  322 |   await expect(page.getByTestId("directory-result")).toContainText("Contrix Demo Space");
  323 |   await expect(page.getByTestId("index-query-results")).toContainText("Contrix Demo Space");
  324 |   await expect(page.getByTestId("generic-entity-card")).toHaveAttribute("data-render-kind", "card");
  325 |   await expect(page.getByTestId("entity-type-label")).toContainText("space");
  326 |   await expect(page.getByTestId("entity-facets")).toContainText("renderable");
  327 |   await expect(page.getByTestId("projection-facets")).toContainText("item: stateful, rankable");
  328 |   await expect(page.getByTestId("unknown-facets-debug")).toContainText("com.example.preview");
  329 | 
  330 |   await page.getByTestId("directory-select-button").click();
  331 |   await page.getByTestId("resolve-selected-button").click();
  332 |   await expect(page.getByTestId("status-label")).toContainText("resolved public");
  333 |   await expect(page.getByTestId("selected-space-id")).toContainText("cx:space:0196419b-0000-7000-8000-000000000000");
  334 | 
  335 |   await page.getByTestId("tab-objects").click();
  336 |   await page.getByTestId("directory-search-input").fill("launch");
  337 |   await page.getByTestId("directory-search-button").click();
  338 |   await expect(page.getByTestId("protocol-object-results")).toContainText("Launch checklist card");
  339 |   await expect(page.getByTestId("protocol-object-results")).toContainText("Restricted discussion");
  340 |   await expect(page.getByTestId("protocol-object-results")).toContainText("locked");
  341 | 
  342 |   await page.getByTestId("tab-organizations").click();
  343 |   await page.getByTestId("directory-search-input").fill("contrix");
  344 |   await page.getByTestId("directory-search-button").click();
  345 |   await expect(page.getByTestId("org-result")).toContainText("Contrix Labs");
  346 |   await expect(page.getByTestId("org-result")).toContainText("listed");
  347 |   await page.getByTestId("org-search-members").click();
  348 |   await expect(page.getByTestId("tab-actors")).toHaveClass(/primary/);
  349 |   await expect(page.getByTestId("directory-search-input")).toHaveValue("contrix.example");
  350 | });
  351 | 
  352 | test("notifications are derived from index projections and respect per-space mute rules", async ({ page }) => {
  353 |   await refreshServer(page);
  354 |   await page.getByTestId("notifications-nav-button").first().click();
  355 | 
  356 |   await expect(page.getByTestId("notifications-panel")).toBeVisible();
  357 |   await expect(page.getByTestId("notifications-panel")).toContainText("Alice sent a message in Demo Space");
  358 |   await expect(page.getByTestId("notifications-status")).toContainText("Loaded 2 notification projection");
  359 | 
  360 |   await page.getByTestId("mute-space-button").first().click();
  361 |   await expect(page.getByTestId("notifications-muted-empty")).toContainText("hidden by archive, type, or per-space mute rules");
  362 | 
> 363 |   await page.getByTestId("settings-nav-button").click();
      |                                                 ^ Error: locator.click: Error: strict mode violation: getByTestId('settings-nav-button') resolved to 2 elements:
  364 |   await page.getByTestId("settings-nav-item-push").click();
  365 |   await expect(page.getByTestId("push-mute-summary")).toContainText("cx:space:0196419b-0000-7000-8000-000000000000");
  366 |   await page.getByTestId("settings-unmute-space").click();
  367 |   await expect(page.getByTestId("status-label")).toContainText("Unmuted");
  368 | 
  369 |   await page.getByTestId("notifications-nav-button").first().click();
  370 |   await expect(page.getByTestId("notifications-panel")).toContainText("You were invited to review Demo Space");
  371 | });
  372 | 
  373 | test("product account space lifecycle and canonical message flow works", async ({ page }) => {
  374 |   await refreshServer(page);
  375 |   await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");
  376 | 
  377 |   await page.getByTestId("topbar-create-button").click();
  378 |   await expect(page.getByTestId("product-panel")).toBeVisible();
  379 | 
  380 |   await page.getByTestId("register-account-button").click();
  381 |   await expect(page.getByTestId("account-flow")).toContainText("registered alice.example");
  382 | 
  383 |   await page.getByTestId("create-space-button").click();
  384 |   await expect(page.getByTestId("space-lifecycle-flow")).toContainText("created cx:space:01js0productflow000000000000");
  385 |   await expect(page.getByTestId("selected-space-id")).toContainText("cx:space:01js0productflow000000000000");
  386 | 
  387 |   await page.getByTestId("add-member-button").click();
  388 |   await expect(page.getByTestId("space-lifecycle-flow")).toContainText("members");
  389 |   await page.getByTestId("persist-message-button").click();
  390 |   await expect(page.getByTestId("message-persistence-flow")).toContainText("persisted");
  391 |   await expect(page.getByTestId("message-persistence-flow")).toContainText("via cx:event:");
  392 |   // C17 (spec 2026-05-08): cx.events.query replaces cx.sync.backfill at /api/v1/events
  393 |   // with direction=backward.
  394 |   const backfill = page.waitForRequest("**/api/v1/events?**direction=backward*");
  395 |   await page.getByTestId("backfill-button").click();
  396 |   expect((await backfill).headers()["x-contrix-wait-for"]).toBe("sx:e2e:product");
  397 |   await page.getByRole("link", { name: "Timeline" }).click();
  398 |   await expect(page.getByTestId("timeline")).toContainText("persisted event cx:event:");
  399 |   await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:product");
  400 |   await page.getByTestId("account-menu-button").click();
  401 |   await expect(page.getByTestId("account-menu-frontier")).toContainText("cx:event:");
  402 | 
  403 |   await page.getByTestId("topbar-create-button").click();
  404 |   await page.getByTestId("remove-member-button").click();
  405 |   await expect(page.getByTestId("space-lifecycle-flow")).toContainText("removed; members");
  406 |   await page.getByTestId("delete-space-button").click();
  407 |   await expect(page.getByTestId("space-lifecycle-flow")).toContainText("deleted true");
  408 | });
  409 | 
  410 | test("chat creates discussion entities and sends structured mention payloads", async ({ page }) => {
  411 |   await refreshServer(page);
  412 |   await page.getByRole("link", { name: "Chat" }).click();
  413 |   await expect(page.getByTestId("chat-panel")).toBeVisible();
  414 | 
  415 |   await page.getByTestId("new-channel-name").fill("Ops Announce");
  416 |   await page.getByTestId("new-channel-topic").fill("Broadcast deploy updates");
  417 |   await page.getByTestId("channel-kind-announce").click();
  418 |   const channelEvent = page.waitForRequest("**/api/v1/events");
  419 |   await page.getByTestId("create-channel-button").click();
  420 |   const channelBody = await channelEvent.then((request) => request.postDataJSON());
  421 |   expect(channelBody.kind).toBe("cx.flow.create");
  422 |   expect(channelBody.payload.kind).toBe("announce");
  423 |   expect(channelBody.payload.flow_id).toContain("cx:flow:");
  424 |   expect(channelBody.payload.title).toBe("Ops Announce");
  425 |   expect(channelBody.payload.rank).toBeTruthy();
  426 |   await expect(page.getByTestId("channel-item").last()).toContainText("Ops Announce");
  427 |   await expect(page.getByTestId("chat-status")).toContainText("flow event accepted");
  428 | 
  429 |   const chatSend = page.waitForRequest("**/api/v1/events");
  430 |   await page.getByTestId("chat-input").fill("hello @did:web:bob.example about #cx:task:123");
  431 |   await page.getByTestId("send-chat-button").click();
  432 |   const chatBody = await chatSend.then((request) => request.postDataJSON());
  433 |   expect(chatBody.kind).toBe("cx.message.create");
  434 |   expect(chatBody.payload.flow_id).toContain("cx:flow:");
  435 |   expect(chatBody.payload.branch).toBe("discussion");
  436 |   expect(chatBody.payload.mentions.some((mention: { target: string }) => mention.target === "did:web:bob.example")).toBeTruthy();
  437 |   expect(chatBody.payload.mentions.some((mention: { target: string }) => mention.target === "cx:task:123")).toBeTruthy();
  438 |   await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #cx:task:123");
  439 |   await expect(page.getByTestId("chat-mentions").last()).toContainText("did:web:bob.example");
  440 |   await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Revision chain");
  441 |   await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Tombstone");
  442 |   await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Linked discussion access");
  443 | });
  444 | 
  445 | test("plaintext compose keeps request ids, revision chains, tombstones, and local MLS entries", async ({ page }) => {
  446 |   await page.getByRole("link", { name: "Timeline" }).click();
  447 |   await page.getByTestId("composer-input").fill("draft survives reload");
  448 |   await page.reload({ waitUntil: "domcontentloaded" });
  449 |   await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  450 |   await page.getByRole("link", { name: "Timeline" }).click();
  451 |   await expect(page.getByTestId("composer-input")).toHaveValue("draft survives reload");
  452 | 
  453 |   const sendRequest = page.waitForRequest("**/api/v1/events");
  454 |   await page.getByTestId("composer-input").fill("plain e2e message");
  455 |   await page.getByTestId("send-button").click();
  456 |   expect((await sendRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  457 |   await expect(page.getByTestId("timeline")).toContainText("plain e2e message");
  458 |   await expect(page.getByTestId("write-status")).toContainText("persisted cx:operation:");
  459 | 
  460 |   const editRequest = page.waitForRequest(
  461 |     (request) =>
  462 |       request.url().endsWith("/api/v1/events") &&
  463 |       request.method() === "POST" &&
```