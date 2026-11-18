import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";
export default defineConfig({
  plugins:[react()], base:"/ui/graph/",
  build:{outDir:resolve(__dirname,"../src/mobius/api/static/graph-ui"),emptyOutDir:true,assetsDir:"assets"},
});
