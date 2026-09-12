// Exercises the production browser helpers without a live identity provider.
// Set NODE_PATH to a directory containing Playwright when it is not installed locally.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {chromium} = require('playwright');

function inlineSource(file) {
    const source = fs.readFileSync(file, 'utf8');
    return source.match(/inline_js = r#"([\s\S]*?)"#/)[1].replace(/export /g, '');
}

(async () => {
    let lastHeaders;
    const server = http.createServer((req, res) => {
        lastHeaders = req.headers;
        if (req.url === '/redirect') { res.writeHead(302, {Location: '/ok'}); res.end(); }
        else if (req.url === '/large') { res.end(Buffer.alloc(1048577)); }
        else if (req.url === '/encoding') { res.writeHead(200, {'Content-Encoding': 'identity'}); res.end('ok'); }
        else { res.end('ok'); }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const browser = await chromium.launch({headless: true});
    try {
        const context = await browser.newContext();
        const page = await context.newPage();
        const base = `http://127.0.0.1:${server.address().port}`;
        const source = inlineSource(path.join(__dirname, '../src/station_connection.rs'));
        await page.goto(base);
        await page.addScriptTag({content: source});
        assert.equal(await page.evaluate(() => station_connection_cas('station', 'old')), null);
        await page.reload();
        await page.addScriptTag({content: source});
        assert.equal(await page.evaluate(() => station_connection_cas('station', 'new')), 'old');
        assert.equal(await page.evaluate(() => station_connection_cas('station', 'new', 'old')), null);
        await assert.rejects(page.evaluate(() => station_connection_cas('station', 'bad', 'old')));
        const peer = await context.newPage();
        await peer.goto(base);
        await peer.addScriptTag({content: source});
        const race = await Promise.all([
            page.evaluate(() => station_connection_cas('race', 'first')),
            peer.evaluate(() => station_connection_cas('race', 'second')),
        ]);
        assert.equal(race.filter(value => value === null).length, 1);
        assert.equal(await page.evaluate(() => station_connection_cas('station', 'new')), null);
        const fetchSource = inlineSource(path.join(__dirname, '../../arkret-rust-sdk/crates/http-client/src/station_connection.rs'));
        await page.addScriptTag({content: fetchSource});
        await context.addCookies([{name: 'old_session', value: 'must-not-send', url: base}]);
        assert.deepEqual(await page.evaluate(url => station_description_bytes(url).then(Array.from), `${base}/ok`), [111, 107]);
        assert.equal(lastHeaders.cookie, undefined);
        assert.equal(lastHeaders.authorization, undefined);
        for (const route of ['redirect', 'large', 'encoding']) {
            await assert.rejects(page.evaluate(url => station_description_bytes(url), `${base}/${route}`));
        }
        await context.close();
        console.log('PASS: real Chromium IndexedDB reload, reviewed replacement, stale CAS, concurrent first contact; describe success, redirect, size and encoding rejection.');
    } finally {
        await browser.close();
        await new Promise(resolve => server.close(resolve));
    }
})().catch(error => { console.error(error); process.exitCode = 1; });
