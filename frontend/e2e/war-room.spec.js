import { test, expect } from "@playwright/test";
import fs from "node:fs";
import { spawnSync } from "node:child_process";

const api = "/api/v1";
const shots = "artifacts/war-room";

async function apiJson(request, path, options = {}) {
  const response = await request.fetch(api + path, options);
  const body = await response.text();
  if (!response.ok()) throw new Error(path + " failed " + response.status() + ": " + body);
  return body ? JSON.parse(body) : {};
}

test("D-056: upload → investigation → evidence → graph → PoC → report; replay survives refresh", async ({ page, request }) => {
  fs.mkdirSync(shots, { recursive: true });
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto("/ui");
  await expect(page.getByTestId("intake-panel")).toBeVisible();

  const apk = fs.readFileSync("e2e/fixtures/demo-lab.apk");
  await page.getByTestId("apk-file").setInputFiles({
    name: "mobius-ci-lab.apk",
    mimeType: "application/vnd.android.package-archive",
    buffer: apk,
  });
  await page.getByRole("button", { name: "Upload & create investigation" }).click();
  await expect(page.locator("#intake-status")).toContainText("INVESTIGATION CREATED");
  await expect(page.locator("#scan-select")).toHaveValue(/^scn_/);
  const scanId = await page.locator("#scan-select").inputValue();
  expect(scanId).toMatch(/^scn_/);
  await page.screenshot({ path: shots + "/d056-01-upload-and-investigation.png", fullPage: true });

  const evidence = await apiJson(request, "/scans/" + scanId + "/evidence?kind=tool-output&summary=CI%20fixture%20evidence&content=synthetic%20manifest%20observation%20evidence", { method: "POST" });
  expect(evidence.id).toMatch(/^ev_/);
  await page.reload();
  await expect(page.locator("#mission-state")).toContainText("RECON");
  await page.screenshot({ path: shots + "/d056-02-evidence.png", fullPage: true });

  const seeded = spawnSync("python", ["../scripts/seed_war_room_fixture.py", scanId], {
    encoding: "utf8",
    env: process.env,
  });
  if (seeded.status !== 0) throw new Error("fixture seeding failed: " + seeded.stderr);
  const fixture = JSON.parse(seeded.stdout.trim());
  const graph = await apiJson(request, "/scans/" + scanId + "/graph/rebuild", { method: "POST" });
  expect(graph.nodes).toBeGreaterThan(0);
  expect(graph.edges).toBeGreaterThan(0);
  await page.goto("/ui?scan_id=" + scanId);
  await expect(page.locator("#graph-summary")).toContainText("NODES");
  await expect(page.locator("#hypothesis-list")).toContainText("Fixture-only hypothesis");
  await expect(page.frameLocator("#graph-frame").locator(".flow-wrap")).toBeVisible();
  await expect(page.frameLocator("#graph-frame").locator(".react-flow__node")).toHaveCount(3);
  await expect(page.frameLocator("#graph-frame").locator(".react-flow__node").first()).toBeVisible();
  const embeddedNodeBox = await page.frameLocator("#graph-frame").locator(".react-flow__node").first().evaluate(el => { const r=el.getBoundingClientRect(); return {top:r.top,bottom:r.bottom,viewport:window.innerHeight,font:getComputedStyle(el).fontSize}; });
  expect(embeddedNodeBox.top).toBeGreaterThanOrEqual(0);
  expect(embeddedNodeBox.bottom).toBeLessThanOrEqual(embeddedNodeBox.viewport);
  expect(parseFloat(embeddedNodeBox.font)).toBeGreaterThanOrEqual(14);
  await page.screenshot({ path: shots + "/d056-03-graph.png", fullPage: true });

  const plan = {
    investigation_id: scanId,
    authorization_id: (await apiJson(request, "/scans/" + scanId)).authorization_id,
    target_sha256: (await apiJson(request, "/scans/" + scanId)).application.sha256,
    target_package: "com.example.lab",
    target_kind: "local_harness",
    hypothesis_ids: [fixture.hypothesis_id],
    prerequisites: ["Fixture hypothesis and evidence are persisted."],
    steps: [
      { action: "invoke_local_harness", target_ref: "unsafe_webview_forwarder_v1", input_values: { url: "javascript:alert(1)" }, timeout_seconds: 10 },
      { action: "assert_local_harness_result", target_ref: "sink_invoked", expected_value: true, timeout_seconds: 10 },
      { action: "invoke_local_harness", target_ref: "safe_webview_guard_v1", input_values: { url: "javascript:alert(1)" }, timeout_seconds: 10 },
      { action: "assert_local_harness_result", target_ref: "sink_invoked", expected_value: false, timeout_seconds: 10 }
    ],
    expected_outcome: "Synthetic positive and negative WebView harness controls; not APK runtime execution.",
    safety_class: "read_only",
    max_duration_seconds: 60,
    max_output_bytes: 16384,
    cleanup_steps: [],
    requires_approval: false
  };
  const poc = await apiJson(request, "/scans/" + scanId + "/poc/execute", { method: "POST", data: plan });
  expect(poc.status).toBe("passed");
  await page.reload();
  await expect(page.locator("#poc-runs")).toContainText("passed");
  await page.screenshot({ path: shots + "/d056-04-poc.png", fullPage: true });

  const report = await apiJson(request, "/scans/" + scanId + "/report", { method: "POST" });
  expect(report.markdown).toContain("Evidence");
  await page.reload();
  await expect(page.locator("#report-viewer")).toContainText("Outcome");
  await expect(page.locator("#report-viewer h2, #report-viewer h3")).toHaveCount(9,{timeout:15000});
  await expect(page.locator("#report-viewer table").first()).toBeVisible();
  await page.screenshot({ path: shots + "/d056-05-report.png", fullPage: true });

  const before = await apiJson(request, "/scans/" + scanId + "/events?after=0&limit=1000");
  const beforeSeq = before.current_seq;
  await page.reload();
  await expect(page.locator("#timeline")).toContainText("poc_completed");
  const after = await apiJson(request, "/scans/" + scanId + "/events?after=0&limit=1000");
  expect(after.current_seq).toBe(beforeSeq);
  expect((after.items || []).map(e => e.seq)).toEqual((before.items || []).map(e => e.seq));
  await page.screenshot({ path: shots + "/d056-06-refresh-replay.png", fullPage: true });

  for (const viewport of [{ width: 1280, height: 900, label: "desktop" }, { width: 390, height: 844, label: "mobile" }]) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.reload();
    await expect(page.locator("#mission-state")).toContainText("RECON");
    for (const [id, name] of [
      ["d050", "d050-mission-coverage"],
      ["d051", "d051-agent-network"],
      ["d052", "d052-timeline"],
      ["d053", "d053-code-studio"],
      ["d054", "d054-attack-graph"],
      ["d055", "d055-poc-report"],
    ]) {
      const panel = page.locator("#" + id);
      await panel.scrollIntoViewIfNeeded();
      await panel.screenshot({ path: shots + "/" + name + "-" + viewport.label + ".png" });
    }
    const graphFrame = page.locator("#graph-frame");
    await graphFrame.scrollIntoViewIfNeeded();
    await expect(graphFrame.contentFrame().locator(".react-flow__node")).toHaveCount(3);
    await graphFrame.screenshot({ path: shots + "/d033-react-flow-" + viewport.label + ".png" });
    await page.goto("/ui/graph?scan_id="+scanId);
    await expect(page.locator(".react-flow__node").first()).toBeVisible();
    await expect.poll(async()=>parseFloat(await page.locator(".react-flow__node").first().evaluate(el=>getComputedStyle(el).fontSize))).toBeGreaterThanOrEqual(14);
    await page.screenshot({ path: shots + "/d033-full-graph-" + viewport.label + ".png", fullPage:true });
    await page.goto("/ui?scan_id="+scanId);
  }
});
