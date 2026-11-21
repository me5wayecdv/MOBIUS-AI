/* Zoom-100% label fit check + close-up screenshots of the dense graph. */
const { chromium } = require("@playwright/test");

const scanId = process.argv[2];
const base = "http://127.0.0.1:8000";

(async () => {
  const browser = await chromium.launch();
  const out = {};
  for (const vp of [
    { width: 1280, height: 900, label: "desktop" },
    { width: 390, height: 844, label: "mobile" },
  ]) {
    const page = await browser.newPage({ viewport: { width: vp.width, height: vp.height } });
    await page.goto(base + "/ui/graph?scan_id=" + scanId);
    await page.waitForSelector(".react-flow__node", { timeout: 20000 });
    await page.waitForTimeout(2000);
    // Force 100% zoom at origin to measure real layout sizes, not scaled ones.
    await page.evaluate(() => {
      document.querySelector(".react-flow__viewport").style.transform = "translate(0px, 0px) scale(1)";
    });
    await page.waitForTimeout(400);
    const metrics = await page.evaluate(() => {
      const els = [...document.querySelectorAll(".react-flow__node")];
      let clipV = 0, clipH = 0, samples = [];
      els.forEach((el, i) => {
        const inner = el.firstElementChild || el;
        const v = inner.scrollHeight > inner.clientHeight + 2;
        const h = inner.scrollWidth > inner.clientWidth + 2;
        if (v) clipV++;
        if (h) clipH++;
        if (i < 6) samples.push({ cw: inner.clientWidth, ch: inner.clientHeight, sw: inner.scrollWidth, sh: inner.scrollHeight });
      });
      return { nodes: els.length, clipV, clipH, samples };
    });
    await page.screenshot({ path: "artifacts/war-room/v4-dense-" + vp.label + "-zoom100.png" });
    out[vp.label] = metrics;
    await page.close();
  }
  await browser.close();
  console.log(JSON.stringify(out, null, 2));
})().catch((e) => { console.error(e); process.exit(1); });
