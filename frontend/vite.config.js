import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
const here = fileURLToPath(new URL(".", import.meta.url));
export default defineConfig({
  plugins:[react()], base:"/ui/graph/",
  build:{outDir:resolve(here,"../src/mobius/api/static/graph-ui"),emptyOutDir:true,assetsDir:"assets"},
});
