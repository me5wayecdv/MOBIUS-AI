import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  outputDir: "../artifacts/playwright-test-results",
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  timeout: 120000,
  expect: { timeout: 15000 },
  use: {
    baseURL: "http://127.0.0.1:8000",
    browserName: "chromium",
    viewport: { width: 1280, height: 900 },
    trace: "retain-on-failure",
  },
  webServer: {
    command: "python -m uvicorn mobius.api.app:create_app --factory --host 127.0.0.1 --port 8000",
    url: "http://127.0.0.1:8000/api/v1/health",
    reuseExistingServer: !process.env.CI,
    timeout: 60000,
  },
});
