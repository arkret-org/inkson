const base = process.env.INKSON_LAYOUT_BASE_URL ?? process.env.INKSON_E2E_BASE_URL ?? "http://127.0.0.1:4727";
// This loads the real WASM bundle, its production CSS, and the same typed
// Sapid menu builder used by every live Timeline message. No DOM menu replica.
export async function mountMessageMenuFixture(page, options={}) {
  await page.goto(new URL("/?__inkson_fixture=message-menu",base).href,{waitUntil:"domcontentloaded"});
  await page.evaluate(async options=>{
    const module=await import("/assets/pkg/inkson.js");
    await module.default();
    if(typeof module.mountMessageMenuFixture!=="function")throw new Error("Build the actual Inkson WASM bundle with spec-conformance for layout tests");
    const root=document.getElementById("app");
    if(!root)throw new Error("Inkson application root is missing");
    module.mountMessageMenuFixture(root,JSON.stringify(options));
  },options);
  await page.locator(".layout-message-fixture .msg-content").filter({hasText:"你好"}).waitFor({state:"visible"});
  await page.getByRole("button",{name:"消息操作",exact:true}).waitFor({state:"visible"});
}
