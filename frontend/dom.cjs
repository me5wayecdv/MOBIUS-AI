const { chromium } = require("@playwright/test");
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  await page.goto("http://127.0.0.1:8000/ui/graph?scan_id=" + process.argv[2]);
  await page.waitForSelector(".react-flow__node");
  await page.waitForTimeout(1500);
  const info = await page.evaluate(() => {
    const el = document.querySelector(".react-flow__node");
    const kids = [...el.children].map(c => ({cls: c.className, cw: c.clientWidth, ch: c.clientHeight, sw: c.scrollWidth, sh: c.scrollHeight}));
    return {outer: el.outerHTML.slice(0, 500), cw: el.clientWidth, ch: el.clientHeight, sw: el.scrollWidth, sh: el.scrollHeight, kids};
  });
  console.log(JSON.stringify(info, null, 2));
  await browser.close();
})();
