/* Measure node overlap + label clipping on the dense graph at desktop and narrow widths. */
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
    await page.waitForTimeout(2500);
    const metrics = await page.evaluate(() => {
      const els = [...document.querySelectorAll(".react-flow__node")];
      const rects = els.map((el) => {
        const r = el.getBoundingClientRect();
        return { l: r.left, t: r.top, r: r.right, b: r.bottom, w: r.width, h: r.height,
                 clipV: el.scrollHeight > el.clientHeight + 2, clipH: el.scrollWidth > el.clientWidth + 2,
                 label: (el.textContent || "").slice(0, 40) };
      });
      let overlaps = [];
      for (let i = 0; i < rects.length; i++)
        for (let j = i + 1; j < rects.length; j++) {
          const a = rects[i], b = rects[j];
          const ox = Math.min(a.r, b.r) - Math.max(a.l, b.l);
          const oy = Math.min(a.b, b.b) - Math.max(a.t, b.t);
          if (ox > 2 && oy > 2) overlaps.push([i, j, Math.round(ox), Math.round(oy)]);
        }
      return {
        nodes: rects.length,
        overlapCount: overlaps.length,
        overlaps: overlaps.slice(0, 10),
        clippedV: rects.filter((r) => r.clipV).length,
        clippedH: rects.filter((r) => r.clipH).length,
      };
    });
    await page.screenshot({ path: "artifacts/war-room/v4-dense-" + vp.label + ".png", fullPage: true });
    out[vp.label] = metrics;
    await page.close();
  }
  await browser.close();
  console.log(JSON.stringify(out, null, 2));
})().catch((e) => { console.error(e); process.exit(1); });
